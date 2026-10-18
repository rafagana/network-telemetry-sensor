#!/usr/bin/env python3
"""
pi_ebpf_streamer_1.2.py

Production-candidate full-fidelity eBPF packet streamer with proactive adaptation.

Key points
----------
- Protocol version remains 3: 62-byte packed chunk header with CRC32.
- PROACTIVE adaptation: Degrades capture BEFORE packet loss occurs.
- 3-tier mode ladder with packet-preserving degraded mode:
  * Mode 1 (normal): Full fidelity (snaplen=1522, sample=1:1)
  * Mode 2 (degraded): All packets preserved, truncated payload (snaplen=512, sample=1:1)
  * Mode 3 (critical): Emergency sampling on actual loss (snaplen=128, sample=1:10-1:100)
- Adaptation triggers:
  * HighRateIntervals >= 3 → degraded mode (PROACTIVE, before loss)
  * Any PerfLost > 0 → degraded mode (EARLY WARNING, research preservation)
  * PerfLost >= 200 → critical mode (REACTIVE, severe loss)
- Gradual recovery path prevents yo-yoing:
  * critical → degraded (12s stability)
  * degraded → normal (24s stability + traffic subsided)
  * Never: critical → normal directly
  * Never: degraded → normal while still under high-rate load
- Compressed queue pressure is treated as transport backpressure, not capture overload.
- The sender connects before capture is attached, so startup does not immediately fill queues.
- TCP send operations have timeouts and explicit send-start / send-complete diagnostics.

Requirements
------------
    sudo apt install -y bpfcc-tools python3-bcc python3-pyroute2 python3-zstandard

Run
---
    sudo python3 pi_ebpf_streamer_v1.2.py
"""

import ctypes
import multiprocessing
import os
import queue
import signal
import socket
import struct
import sys
import threading
import time
import zlib
from collections import deque
from datetime import datetime
from typing import Optional

import zstandard as zstd
from bcc import BPF
from pyroute2 import IPRoute

# =============================================================================
# USER CONFIGURATION
# =============================================================================

VAULT_IP = "192.168.10.137"
VAULT_PORT = 9999

CAPTURE_INTERFACE = "eth1"
PI_MGMT_IP = "192.168.10.31"

# Adaptive modes
FULL_FIDELITY_ONLY = False
ALLOW_EMERGENCY_DEGRADE = True

# Mode configurations
# Mode 1: Normal - full fidelity
MODE1_SNAPLEN = 1522
MODE1_SAMPLE_RATE = 1

# Mode 2: Degraded - proactive reduction on sustained high rate (before packet loss)
# Triggered by HighRateIntervals to prevent perf ring overflow.
# Keep sample=1:1 to preserve every packet that successfully drains from perf ring.
# Reducing snaplen alone (512 vs 1522) cuts per-packet overhead ~66%.
# Goal: Enter degraded mode BEFORE PerfLost occurs, not after.
MODE2_SNAPLEN = 512
MODE2_SAMPLE_RATE = 1

# Mode 3: Critical - reactive emergency mode on actual packet loss
# Aggressive sampling to stop the bleeding when snaplen reduction isn't enough.
MODE3_SNAPLEN = 128
MODE3_SAMPLE_RATE = 20

# Dynamic Mode 3 sampling. Once in Mode 3 the system is already losing packets,
# so 1:10 is the least aggressive emergency sampling rate.
MODE3_SAMPLE_RATE_MILD = 10
MODE3_SAMPLE_RATE_MODERATE = 20
MODE3_SAMPLE_RATE_SEVERE = 50
MODE3_SAMPLE_RATE_EXTREME = 100

# Buffer sizing
PERF_PAGE_CNT = 16384
CHUNK_QUEUE_MAXSIZE = 512
COMPRESS_QUEUE_MAXSIZE = 128

# Batching
BATCH_BYTES = 1024 * 1024
BATCH_MAX_PACKETS = 2048
BATCH_TIMEOUT_MS = 50

# Network
SOCKET_SNDBUF = 32 * 1024 * 1024
SOCKET_CONNECT_RETRY_SEC = 2
SOCKET_SEND_TIMEOUT_SEC = 10.0
VAULT_STARTUP_WAIT_SEC = 30
START_CAPTURE_AFTER_VAULT_CONNECTED = True
NUM_EGRESS_WORKERS = 1

# Monitoring
# IMPORTANT: Telemetry interval affects both adaptation speed AND processing throughput.
# monitor_stats() holds stats_lock and reads BPF maps (expensive!), blocking chunk builders
# during that time. Too frequent telemetry → GIL contention → perf ring starvation → PerfLost.
# At 1s interval, saw PerfLost spikes even at moderate traffic (53k pps, well within capacity).
# 3s interval reduces GIL contention by 67% while maintaining reasonable adaptation speed.
TELEMETRY_INTERVAL_SEC = 3  # Balance: fast adaptation vs. low GIL contention

# Recovery intervals - gradual restoration prevents yo-yoing
STABLE_INTERVALS_TO_RESTORE = 4      # critical → degraded: 4 * 3s = 12s
DEGRADED_INTERVALS_TO_RESTORE = 8    # degraded → normal: 8 * 3s = 24s

# Thresholds
QUEUE_PRESSURE_RATIO = 0.60
QUEUE_CRITICAL_RATIO = 0.85
QUEUE_RESTORE_RATIO = 0.20

# PerfLost thresholds
# ANY perf loss means kernel has dropped packets - treat it seriously for research preservation
PERF_LOST_CRITICAL_THRESHOLD = 200  # Severe loss → critical mode
# Note: Any perf_lost_delta > 0 triggers degraded mode (no minimum threshold)

BURST_RATE_THRESHOLD = 50000

# Proactive degradation on sustained high rate (PREVENTIVE, not reactive)
# HighRateIntervals counts consecutive intervals above BURST_RATE_THRESHOLD.
# Enter degraded mode BEFORE perf loss occurs to prevent ring buffer overflow.
HIGH_RATE_INTERVALS_TO_DEGRADE = 3  # 3 intervals * 3s = 9s of sustained high rate
HIGH_RATE_INTERVALS_TO_CRITICAL = 10  # Fallback if degraded mode doesn't help

TRANSPORT_BACKPRESSURE_RATIO = 0.85
TRANSPORT_SENT_RATE_FRACTION = 0.10

# Compression
COMPRESSION_LEVEL = 3
NUM_COMPRESSION_WORKERS = 1

# Shutdown
QUEUE_DRAIN_TIMEOUT_SEC = 60

# CPU affinity placeholder
ENABLE_CPU_AFFINITY = False

# =============================================================================
# CONSTANTS AND BINARY LAYOUT
# =============================================================================

DIR_INGRESS = 0
DIR_EGRESS = 1

FRAME_HEADER_STRUCT = struct.Struct(">QIIIQQ")
FRAME_HEADER_SIZE = FRAME_HEADER_STRUCT.size

PKT_META_STRUCT = struct.Struct("=III4xQ")
PKT_META_SIZE = PKT_META_STRUCT.size

# Packed v5.3 protocol header. Total: 62 bytes.
CHUNK_MAGIC = 0x43484E4B  # "CHNK"
CHUNK_VERSION = 3
CHUNK_HEADER_STRUCT = struct.Struct(">IHHQQQIBHHBQQI")
CHUNK_HEADER_SIZE = CHUNK_HEADER_STRUCT.size

# =============================================================================
# GLOBAL STATE
# =============================================================================

if os.geteuid() != 0:
    sys.exit("[-] Run as root: sudo python3 pi_ebpf_streamer_v1.2.py")

LOG_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILENAME = os.path.join(
    LOG_DIR,
    datetime.now().strftime("%Y%m%d_pi_ebpf_streamer_v1.2"),
)

capture_stop_event = threading.Event()
drain_stop_event = threading.Event()
egress_connected_event = threading.Event()
shutdown_phase = 0

raw_chunk_queue = queue.Queue(maxsize=CHUNK_QUEUE_MAXSIZE)
compressed_queue = queue.Queue(maxsize=COMPRESS_QUEUE_MAXSIZE)

num_cpus = multiprocessing.cpu_count()
cpu_chunks = {}
cpu_chunks_lock = threading.Lock()

BOOT_WALL_OFFSET_NS = time.time_ns() - time.monotonic_ns()

stats_lock = threading.Lock()
bpf_lock = threading.Lock()

stats = {
    "events_enqueued": 0,
    "events_sent": 0,
    "bytes_enqueued": 0,
    "bytes_sent": 0,
    "bytes_uncompressed": 0,
    "bytes_compressed": 0,
    "chunks_enqueued": 0,
    "chunks_compressed": 0,
    "chunks_sent": 0,
    "raw_queue_drops": 0,
    "compress_queue_drops": 0,
    "raw_packet_drops": 0,
    "compress_packet_drops": 0,
    "egress_chunk_drops": 0,
    "egress_packet_drops": 0,
    "perf_lost": 0,
    "sampled_out": 0,
    "socket_reconnects": 0,
    "send_errors": 0,
    "send_timeouts": 0,
    "mode_changes": 0,
}

enqueue_history = deque(maxlen=20)
runtime_state = {
    "mode": 1,
    "snaplen": MODE1_SNAPLEN,
    "sample_rate": MODE1_SAMPLE_RATE,
    "stable_intervals": 0,
    "burst_detected": False,
    "high_rate_intervals": 0,
}

bpf_obj = None
ipr = None
ifindex = None

global_sequence = 0
global_sequence_lock = threading.Lock()

global_chunk_id = 0
global_chunk_id_lock = threading.Lock()

# =============================================================================
# LOGGING
# =============================================================================

def log_message(msg: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    line = f"[{timestamp}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILENAME, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def ip_to_host_int(ip: str) -> int:
    octets = [int(x) for x in ip.split(".")]
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]


PI_MGMT_IP_HOST = ip_to_host_int(PI_MGMT_IP) if PI_MGMT_IP else 0

# =============================================================================
# EBPF C PROGRAM
# =============================================================================

ebpf_source = f"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <bcc/proto.h>

#define SNAPLEN_MAX 1522
#define DIR_INGRESS 0
#define DIR_EGRESS 1
#define PI_MGMT_IP_HOST 0x{PI_MGMT_IP_HOST:08x}U

struct vlan_hdr {{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
}};

struct pkt_meta {{
    u32 orig_len;
    u32 cap_len;
    u32 direction;
    u64 ts_ns;
}};

BPF_PERF_OUTPUT(skb_events);
BPF_ARRAY(cfg, u32, 2);
BPF_PERCPU_ARRAY(pkt_counter, u64, 1);
BPF_PERCPU_ARRAY(sampled_out_counter, u64, 1);

static __always_inline u32 read_cfg_or_default(u32 index, u32 fallback)
{{
    u32 *val = cfg.lookup(&index);
    if (!val || *val == 0)
        return fallback;
    return *val;
}}

static __always_inline int should_sample()
{{
    u32 sample_idx = 1;
    u32 sample_rate = read_cfg_or_default(sample_idx, 1);

    if (sample_rate <= 1)
        return 1;

    u32 zero = 0;
    u64 *counter = pkt_counter.lookup(&zero);
    if (!counter)
        return 1;

    *counter += 1;

    if ((*counter % sample_rate) == 0)
        return 1;

    u64 *sampled_out = sampled_out_counter.lookup(&zero);
    if (sampled_out)
        *sampled_out += 1;

    return 0;
}}

static __always_inline int is_pi_mgmt_ipv4(struct __sk_buff *skb)
{{
    if (PI_MGMT_IP_HOST == 0)
        return 0;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    u64 offset = sizeof(*eth);
    u16 proto = eth->h_proto;

    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {{
        struct vlan_hdr *vh = data + offset;
        if ((void *)(vh + 1) > data_end)
            return 0;
        proto = vh->h_vlan_encapsulated_proto;
        offset += sizeof(*vh);
    }}

    if (proto != bpf_htons(ETH_P_IP))
        return 0;

    struct iphdr *iph = data + offset;
    if ((void *)(iph + 1) > data_end)
        return 0;

    u32 saddr = bpf_ntohl(iph->saddr);
    u32 daddr = bpf_ntohl(iph->daddr);

    if (saddr == PI_MGMT_IP_HOST || daddr == PI_MGMT_IP_HOST)
        return 1;

    return 0;
}}

static __always_inline int submit_packet(struct __sk_buff *skb, u32 direction)
{{
    if (is_pi_mgmt_ipv4(skb))
        return TC_ACT_OK;

    if (!should_sample())
        return TC_ACT_OK;

    u32 snap_idx = 0;
    u32 snaplen = read_cfg_or_default(snap_idx, {MODE1_SNAPLEN});

    if (snaplen > SNAPLEN_MAX)
        snaplen = SNAPLEN_MAX;

    u32 pkt_len = skb->len;
    u32 cap_len = pkt_len;

    if (cap_len > snaplen)
        cap_len = snaplen;

    struct pkt_meta meta = {{}};
    meta.orig_len = pkt_len;
    meta.cap_len = cap_len;
    meta.direction = direction;
    meta.ts_ns = bpf_ktime_get_ns();

    skb_events.perf_submit_skb(skb, cap_len, &meta, sizeof(meta));

    return TC_ACT_OK;
}}

int physical_tc_ingress_tap(struct __sk_buff *skb)
{{
    return submit_packet(skb, DIR_INGRESS);
}}

int physical_tc_egress_tap(struct __sk_buff *skb)
{{
    return submit_packet(skb, DIR_EGRESS);
}}

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif
"""

# =============================================================================
# RUNTIME BPF CONFIGURATION
# =============================================================================

def set_runtime_config(snaplen: int, sample_rate: int, mode: int, force: bool = False) -> None:
    global bpf_obj

    snaplen = max(1, min(int(snaplen), 1522))
    sample_rate = max(1, min(int(sample_rate), 65535))

    with stats_lock:
        changed = (
            runtime_state["snaplen"] != snaplen
            or runtime_state["sample_rate"] != sample_rate
            or runtime_state["mode"] != mode
        )

    if not changed and not force:
        return

    with cpu_chunks_lock:
        for builder in cpu_chunks.values():
            builder.flush()

    with bpf_lock:
        if bpf_obj is None:
            return
        cfg = bpf_obj["cfg"]
        cfg[ctypes.c_int(0)] = ctypes.c_uint(snaplen)
        cfg[ctypes.c_int(1)] = ctypes.c_uint(sample_rate)

    with stats_lock:
        runtime_state["snaplen"] = snaplen
        runtime_state["sample_rate"] = sample_rate
        runtime_state["mode"] = mode
        stats["mode_changes"] += 1

    mode_names = {1: "normal", 2: "degraded", 3: "critical"}
    log_message(
        f"[ADAPT] mode={mode_names.get(mode, 'unknown')} "
        f"snaplen={snaplen} sample_rate=1:{sample_rate}"
    )

# =============================================================================
# SEQUENCE AND CHUNK IDS
# =============================================================================

def allocate_sequence() -> int:
    global global_sequence
    with global_sequence_lock:
        global_sequence += 1
        return global_sequence


def allocate_chunk_id() -> int:
    global global_chunk_id
    with global_chunk_id_lock:
        global_chunk_id += 1
        return global_chunk_id

# =============================================================================
# PER-CPU CHUNK MANAGEMENT
# =============================================================================

class CPUChunkBuilder:
    def __init__(self, cpu: int):
        self.cpu = cpu
        self.lock = threading.Lock()
        self.chunk = bytearray()
        self.packet_count = 0
        self.first_seq: Optional[int] = None
        self.last_seq: Optional[int] = None
        with stats_lock:
            self.capture_mode = runtime_state["mode"]
            self.capture_snaplen = runtime_state["snaplen"]
            self.capture_sample_rate = runtime_state["sample_rate"]
        self.last_flush_ns = time.monotonic_ns()

    def add_packet(self, frame_data: bytes, seq: int) -> None:
        with self.lock:
            if self.first_seq is None:
                self.first_seq = seq
            self.last_seq = seq
            self.chunk.extend(frame_data)
            self.packet_count += 1
            if len(self.chunk) >= BATCH_BYTES or self.packet_count >= BATCH_MAX_PACKETS:
                self._flush_locked()

    def _flush_locked(self) -> None:
        if self.packet_count == 0:
            return

        chunk_id = allocate_chunk_id()
        chunk = bytes(self.chunk)
        packet_count = self.packet_count
        byte_count = len(chunk)
        first_seq = self.first_seq or 0
        last_seq = self.last_seq or 0
        mode = self.capture_mode
        snaplen = self.capture_snaplen
        sample_rate = self.capture_sample_rate

        try:
            raw_chunk_queue.put_nowait((
                chunk_id, chunk, packet_count, byte_count,
                first_seq, last_seq, mode, snaplen, sample_rate
            ))
            with stats_lock:
                stats["chunks_enqueued"] += 1
                stats["events_enqueued"] += packet_count
                stats["bytes_enqueued"] += byte_count
        except queue.Full:
            with stats_lock:
                stats["raw_queue_drops"] += 1
                stats["raw_packet_drops"] += packet_count

        self.chunk = bytearray()
        self.packet_count = 0
        self.first_seq = None
        self.last_seq = None
        with stats_lock:
            self.capture_mode = runtime_state["mode"]
            self.capture_snaplen = runtime_state["snaplen"]
            self.capture_sample_rate = runtime_state["sample_rate"]
        self.last_flush_ns = time.monotonic_ns()

    def flush(self) -> None:
        with self.lock:
            self._flush_locked()

    def maybe_timeout_flush(self) -> None:
        with self.lock:
            if self.packet_count == 0:
                return
            now_ns = time.monotonic_ns()
            elapsed_ms = (now_ns - self.last_flush_ns) / 1_000_000
            if elapsed_ms >= BATCH_TIMEOUT_MS:
                self._flush_locked()


def get_cpu_chunk_builder(cpu: int) -> CPUChunkBuilder:
    with cpu_chunks_lock:
        if cpu not in cpu_chunks:
            cpu_chunks[cpu] = CPUChunkBuilder(cpu)
        return cpu_chunks[cpu]

# =============================================================================
# PERF CALLBACKS
# =============================================================================

def on_packet(cpu, data, size) -> None:
    if size < PKT_META_SIZE:
        return

    raw = ctypes.string_at(data, size)

    try:
        orig_len, cap_len, direction, kernel_ts_ns = PKT_META_STRUCT.unpack_from(raw, 0)
    except struct.error:
        return

    if cap_len <= 0 or size < PKT_META_SIZE + cap_len:
        return

    payload = raw[PKT_META_SIZE:PKT_META_SIZE + cap_len]
    seq = allocate_sequence()
    wall_ts_ns = BOOT_WALL_OFFSET_NS + kernel_ts_ns

    frame_header = FRAME_HEADER_STRUCT.pack(
        seq, cap_len, orig_len, direction, wall_ts_ns, kernel_ts_ns
    )
    frame_data = frame_header + payload

    chunk_builder = get_cpu_chunk_builder(cpu)
    chunk_builder.add_packet(frame_data, seq)


def on_lost(count=0, *args):
    actual_count = args[0] if args else count
    with stats_lock:
        stats["perf_lost"] += actual_count

# =============================================================================
# COMPRESSION WORKER
# =============================================================================

def compression_worker(worker_id: int) -> None:
    compressor = zstd.ZstdCompressor(level=COMPRESSION_LEVEL, threads=1)
    log_message(f"[COMPRESS-{worker_id}] Worker started")

    while shutdown_phase < 2:
        try:
            item = raw_chunk_queue.get(timeout=0.5)
        except queue.Empty:
            if shutdown_phase >= 1:
                break
            continue

        chunk_id, chunk, packet_count, byte_count, first_seq, last_seq, mode, snaplen, sample_rate = item

        try:
            compressed = compressor.compress(chunk)
            compressed_size = len(compressed)
            crc32 = zlib.crc32(compressed) & 0xffffffff
            header = CHUNK_HEADER_STRUCT.pack(
                CHUNK_MAGIC, CHUNK_VERSION, 0,
                chunk_id, first_seq, last_seq,
                packet_count, mode, snaplen, sample_rate, 0,
                byte_count, compressed_size, crc32,
            )
            full_chunk = header + compressed

            try:
                compressed_queue.put_nowait((full_chunk, packet_count, compressed_size, byte_count))
                with stats_lock:
                    stats["chunks_compressed"] += 1
                    stats["bytes_compressed"] += compressed_size
                    stats["bytes_uncompressed"] += byte_count
            except queue.Full:
                with stats_lock:
                    stats["compress_queue_drops"] += 1
                    stats["compress_packet_drops"] += packet_count
        except Exception as e:
            log_message(f"[COMPRESS-{worker_id}] Error: {type(e).__name__}: {e}")
        finally:
            raw_chunk_queue.task_done()

    log_message(f"[COMPRESS-{worker_id}] Shutdown complete")

# =============================================================================
# TCP SENDER
# =============================================================================

def configure_socket(s: socket.socket) -> None:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    s.settimeout(SOCKET_SEND_TIMEOUT_SEC)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_SNDBUF)
    except OSError as e:
        log_message(f"[WARN] Could not set SO_SNDBUF={SOCKET_SNDBUF}: {e}")
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    # Linux-specific: abort if transmitted data remains unacknowledged too long.
    tcp_user_timeout = getattr(socket, "TCP_USER_TIMEOUT", None)
    if tcp_user_timeout is not None:
        try:
            s.setsockopt(socket.IPPROTO_TCP, tcp_user_timeout, int(SOCKET_SEND_TIMEOUT_SEC * 1000))
        except OSError:
            pass


def connect_to_vault() -> socket.socket:
    while not drain_stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            configure_socket(s)
            s.connect((VAULT_IP, VAULT_PORT))
            actual_sndbuf = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            with stats_lock:
                stats["socket_reconnects"] += 1
            egress_connected_event.set()
            log_message(
                f"[TCP] Connected to {VAULT_IP}:{VAULT_PORT} "
                f"SO_SNDBUF={actual_sndbuf} timeout={SOCKET_SEND_TIMEOUT_SEC:.1f}s"
            )
            return s
        except Exception as e:
            egress_connected_event.clear()
            log_message(f"[TCP] Connect failed: {type(e).__name__}: {e}. Retrying in {SOCKET_CONNECT_RETRY_SEC}s.")
            time.sleep(SOCKET_CONNECT_RETRY_SEC)

    raise RuntimeError("Drain stop requested while connecting to Vault")


def network_sender(worker_id: int) -> None:
    client_socket = None
    log_message(f"[EGRESS-{worker_id}] Worker started")

    max_send_retries = 3
    chunks_sent_count = 0
    last_debug_ts = 0.0

    while shutdown_phase < 3:
        if client_socket is None:
            try:
                client_socket = connect_to_vault()
            except RuntimeError:
                log_message(f"[EGRESS-{worker_id}] Connection stopped, exiting")
                break

        try:
            chunk, packet_count, compressed_size, uncompressed_size = compressed_queue.get(timeout=0.5)
        except queue.Empty:
            if shutdown_phase >= 2:
                break
            continue

        send_success = False
        for attempt in range(max_send_retries):
            try:
                now = time.time()
                if now - last_debug_ts >= 5:
                    qsz = compressed_queue.qsize()
                    log_message(
                        f"[EGRESS-{worker_id}] Sending chunk bytes={len(chunk)} "
                        f"packets={packet_count} comp_q={qsz}/{COMPRESS_QUEUE_MAXSIZE}"
                    )
                    last_debug_ts = now

                client_socket.sendall(chunk)
                send_success = True
                chunks_sent_count += 1

                with stats_lock:
                    stats["chunks_sent"] += 1
                    stats["events_sent"] += packet_count
                    stats["bytes_sent"] += compressed_size

                if chunks_sent_count % 100 == 0:
                    log_message(f"[EGRESS-{worker_id}] Sent {chunks_sent_count} chunks successfully")
                break

            except socket.timeout as e:
                with stats_lock:
                    stats["send_errors"] += 1
                    stats["send_timeouts"] += 1
                log_message(
                    f"[EGRESS-{worker_id}] Send timeout attempt {attempt+1}/{max_send_retries} "
                    f"after {SOCKET_SEND_TIMEOUT_SEC:.1f}s: {e}"
                )
                try:
                    client_socket.close()
                except Exception:
                    pass
                client_socket = None
                egress_connected_event.clear()
            except Exception as e:
                with stats_lock:
                    stats["send_errors"] += 1
                log_message(
                    f"[EGRESS-{worker_id}] Send failed attempt {attempt+1}/{max_send_retries}: "
                    f"{type(e).__name__}: {e}"
                )
                try:
                    client_socket.close()
                except Exception:
                    pass
                client_socket = None
                egress_connected_event.clear()

            if attempt < max_send_retries - 1 and not drain_stop_event.is_set():
                try:
                    log_message(f"[EGRESS-{worker_id}] Reconnecting for retry {attempt+2}/{max_send_retries}")
                    client_socket = connect_to_vault()
                except RuntimeError:
                    break
            else:
                break

        if not send_success:
            with stats_lock:
                stats["egress_chunk_drops"] += 1
                stats["egress_packet_drops"] += packet_count
            log_message(
                f"[EGRESS-{worker_id}] Dropped chunk bytes={compressed_size} packets={packet_count} "
                f"after {max_send_retries} retries"
            )

        compressed_queue.task_done()

    egress_connected_event.clear()
    if client_socket is not None:
        try:
            client_socket.close()
        except Exception:
            pass
    log_message(f"[EGRESS-{worker_id}] Shutdown complete")

# =============================================================================
# TELEMETRY AND ADAPTIVE CONTROL
# =============================================================================

def read_sampled_out_count() -> int:
    global bpf_obj
    if bpf_obj is None:
        return 0
    try:
        sampled_out_array = bpf_obj["sampled_out_counter"]
        try:
            return sampled_out_array.sum(ctypes.c_int(0)).value
        except AttributeError:
            values = sampled_out_array[ctypes.c_int(0)]
            if isinstance(values, (list, tuple)):
                return sum(getattr(v, "value", v) for v in values)
            return getattr(values, "value", values)
    except Exception as e:
        log_message(f"[WARN] Failed to read sampled_out_counter: {type(e).__name__}: {e}")
        return 0


def snapshot_stats() -> dict:
    with stats_lock:
        s = dict(stats)
        s.update({
            "raw_queue_size": raw_chunk_queue.qsize(),
            "compress_queue_size": compressed_queue.qsize(),
            "mode": runtime_state["mode"],
            "snaplen": runtime_state["snaplen"],
            "sample_rate": runtime_state["sample_rate"],
            "stable_intervals": runtime_state["stable_intervals"],
            "burst_detected": runtime_state["burst_detected"],
            "high_rate_intervals": runtime_state.get("high_rate_intervals", 0),
            "egress_connected": egress_connected_event.is_set(),
        })
        if s["bytes_uncompressed"] > 0:
            s["compression_ratio"] = s["bytes_compressed"] / s["bytes_uncompressed"]
        else:
            s["compression_ratio"] = 0.0
        s["sampled_out"] = read_sampled_out_count()
        return s


def detect_burst(cur_stats: dict, prev_stats: dict, dt: float) -> bool:
    enq_delta = cur_stats["events_enqueued"] - prev_stats["events_enqueued"]
    enq_rate = enq_delta / dt if dt > 0 else 0
    enqueue_history.append((time.time(), enq_rate))
    if len(enqueue_history) < 2:
        return False
    prev_rate = prev_stats.get("last_enq_rate", 0)
    cur_stats["last_enq_rate"] = enq_rate
    return bool(prev_rate > 0 and enq_rate / prev_rate > 2.0)


def monitor_stats() -> None:
    prev = snapshot_stats()

    while not capture_stop_event.is_set():
        time.sleep(TELEMETRY_INTERVAL_SEC)

        cur = snapshot_stats()
        dt = TELEMETRY_INTERVAL_SEC

        enq_delta = cur["events_enqueued"] - prev["events_enqueued"]
        sent_delta = cur["events_sent"] - prev["events_sent"]
        bytes_sent_delta = cur["bytes_sent"] - prev["bytes_sent"]
        perf_lost_delta = cur["perf_lost"] - prev["perf_lost"]
        raw_pkt_drop_delta = cur["raw_packet_drops"] - prev["raw_packet_drops"]
        comp_pkt_drop_delta = cur["compress_packet_drops"] - prev["compress_packet_drops"]
        sampled_out_delta = cur["sampled_out"] - prev["sampled_out"]
        egress_pkt_drop_delta = cur["egress_packet_drops"] - prev.get("egress_packet_drops", 0)

        enq_rate = enq_delta / dt
        sent_rate = sent_delta / dt
        mbps_sent = (bytes_sent_delta * 8) / dt / 1_000_000
        raw_qratio = cur["raw_queue_size"] / CHUNK_QUEUE_MAXSIZE
        compress_qratio = cur["compress_queue_size"] / COMPRESS_QUEUE_MAXSIZE
        compression_pct = (1.0 - cur["compression_ratio"]) * 100 if cur["compression_ratio"] > 0 else 0.0

        burst_detected = detect_burst(cur, prev, dt)
        high_rate = enq_rate > BURST_RATE_THRESHOLD
        
        # HighRateIntervals tracks consecutive intervals above BURST_RATE_THRESHOLD
        # Resets when traffic rate drops, NOT when mode changes (traffic-based, not mode-based)
        with stats_lock:
            runtime_state["burst_detected"] = burst_detected
            if high_rate:
                runtime_state["high_rate_intervals"] = runtime_state.get("high_rate_intervals", 0) + 1
            else:
                runtime_state["high_rate_intervals"] = 0
            high_rate_intervals = runtime_state["high_rate_intervals"]

        mode_names = {1: "normal", 2: "degraded", 3: "critical"}
        log_message(
            "[TELEMETRY] "
            f"Mode: {mode_names.get(cur['mode'], 'unknown')} | "
            f"Snaplen: {cur['snaplen']} | "
            f"Sample: 1:{cur['sample_rate']} | "
            f"Egress: {'UP' if cur['egress_connected'] else 'DOWN'} | "
            f"RawQ: {cur['raw_queue_size']}/{CHUNK_QUEUE_MAXSIZE} ({raw_qratio:.0%}) | "
            f"CompQ: {cur['compress_queue_size']}/{COMPRESS_QUEUE_MAXSIZE} ({compress_qratio:.0%}) | "
            f"Enq/s: {enq_rate:.0f} | Sent/s: {sent_rate:.0f} | Mb/s: {mbps_sent:.1f} | "
            f"Compress: {compression_pct:.0f}% | RawPktDrops: +{raw_pkt_drop_delta} | "
            f"CompPktDrops: +{comp_pkt_drop_delta} | EgressPktDrops: +{egress_pkt_drop_delta} | "
            f"PerfLost: +{perf_lost_delta} | SampledOut: +{sampled_out_delta} | "
            f"Burst: {'YES' if burst_detected else 'NO'} | "
            f"HighRateIntervals: {high_rate_intervals}"
        )

        transport_backpressure = (
            compress_qratio >= TRANSPORT_BACKPRESSURE_RATIO
            and sent_rate < (enq_rate * TRANSPORT_SENT_RATE_FRACTION)
        )
        if transport_backpressure:
            log_message(
                "[WARN] Transport backpressure detected: "
                f"CompQ={compress_qratio:.0%}, Sent/s={sent_rate:.0f}, Enq/s={enq_rate:.0f}. "
                "This is a Vault/network issue, not capture overload. Mode NOT degraded."
            )

        if FULL_FIDELITY_ONLY:
            prev = cur
            continue

        # CRITICAL MODE (Mode 3): Reactive - severe packet loss detected
        # Enter critical mode immediately on severe perf ring loss or critical queue backup.
        # This is the "stop the bleeding" emergency response.
        if (
            ALLOW_EMERGENCY_DEGRADE
            and (
                perf_lost_delta >= PERF_LOST_CRITICAL_THRESHOLD
                or raw_qratio >= QUEUE_CRITICAL_RATIO
            )
        ):
            with stats_lock:
                runtime_state["stable_intervals"] = 0

            if perf_lost_delta > 100000:
                adaptive_sample_rate = MODE3_SAMPLE_RATE_EXTREME
            elif perf_lost_delta > 10000:
                adaptive_sample_rate = MODE3_SAMPLE_RATE_SEVERE
            elif perf_lost_delta > 1000:
                adaptive_sample_rate = MODE3_SAMPLE_RATE_MODERATE
            else:
                adaptive_sample_rate = MODE3_SAMPLE_RATE_MILD

            set_runtime_config(MODE3_SNAPLEN, adaptive_sample_rate, 3)

        # DEGRADED MODE (Mode 2): Proactive + Early Warning
        # Enter degraded mode on ANY of these conditions:
        # 1. Sustained high rate (PROACTIVE - prevent overflow before it happens)
        # 2. ANY perf loss detected (EARLY WARNING - even 1 packet lost matters for research)
        # 3. Queue pressure building (EARLY WARNING - before critical threshold)
        elif (
            high_rate_intervals >= HIGH_RATE_INTERVALS_TO_DEGRADE
            or perf_lost_delta > 0
            or raw_qratio >= QUEUE_PRESSURE_RATIO
        ):
            # Any of these signals indicates the pipeline is under stress.
            # Reduce snaplen to preserve packet continuity before severe loss occurs.
            with stats_lock:
                runtime_state["stable_intervals"] = 0
            set_runtime_config(MODE2_SNAPLEN, MODE2_SAMPLE_RATE, 2)

        # RECOVERY: Gradual restoration to prevent yo-yoing
        # critical → degraded → normal (not critical → normal)
        else:
            both_queues_healthy = raw_qratio < QUEUE_RESTORE_RATIO and compress_qratio < QUEUE_RESTORE_RATIO
            no_drops = perf_lost_delta == 0 and raw_pkt_drop_delta == 0 and comp_pkt_drop_delta == 0
            traffic_subsided = high_rate_intervals == 0  # Ensure traffic actually dropped
            
            if both_queues_healthy and no_drops:
                with stats_lock:
                    runtime_state["stable_intervals"] += 1
                    stable = runtime_state["stable_intervals"]
                    current_mode = runtime_state["mode"]
                
                # Critical → Degraded first (avoid jumping straight to normal)
                if current_mode == 3 and stable >= STABLE_INTERVALS_TO_RESTORE:
                    set_runtime_config(MODE2_SNAPLEN, MODE2_SAMPLE_RATE, 2)
                
                # Degraded → Normal only after longer stability AND traffic has subsided
                # This prevents mode churn when degraded mode is successfully handling high rate
                elif current_mode == 2 and stable >= DEGRADED_INTERVALS_TO_RESTORE and traffic_subsided:
                    set_runtime_config(MODE1_SNAPLEN, MODE1_SAMPLE_RATE, 1)
            else:
                with stats_lock:
                    runtime_state["stable_intervals"] = 0

        prev = cur

# =============================================================================
# SUPPORT THREADS AND SHUTDOWN HELPERS
# =============================================================================

def timeout_flush_worker() -> None:
    while not capture_stop_event.is_set():
        time.sleep(BATCH_TIMEOUT_MS / 1000.0)
        with cpu_chunks_lock:
            for builder in cpu_chunks.values():
                builder.maybe_timeout_flush()


def bounded_queue_join(q: queue.Queue, name: str, timeout_sec: int) -> bool:
    start = time.time()
    while time.time() - start < timeout_sec:
        if q.unfinished_tasks == 0:
            return True
        time.sleep(0.1)
    log_message(f"[WARN] {name} drain timeout ({timeout_sec}s) with {q.unfinished_tasks} tasks remaining")
    return False


def drain_abandoned_raw_queue() -> int:
    dropped_packets = 0
    dropped_chunks = 0
    while True:
        try:
            item = raw_chunk_queue.get_nowait()
        except queue.Empty:
            break
        _, _, packet_count, _, _, _, _, _, _ = item
        dropped_packets += packet_count
        dropped_chunks += 1
        raw_chunk_queue.task_done()
    if dropped_chunks > 0:
        with stats_lock:
            stats["raw_queue_drops"] += dropped_chunks
            stats["raw_packet_drops"] += dropped_packets
        log_message(f"[SHUTDOWN] Abandoned {dropped_chunks} raw chunks ({dropped_packets} packets)")
    return dropped_packets


def drain_abandoned_compressed_queue() -> int:
    dropped_packets = 0
    dropped_chunks = 0
    while True:
        try:
            item = compressed_queue.get_nowait()
        except queue.Empty:
            break
        _, packet_count, _, _ = item
        dropped_packets += packet_count
        dropped_chunks += 1
        compressed_queue.task_done()
    if dropped_chunks > 0:
        with stats_lock:
            stats["egress_chunk_drops"] += dropped_chunks
            stats["egress_packet_drops"] += dropped_packets
        log_message(f"[SHUTDOWN] Abandoned {dropped_chunks} compressed chunks ({dropped_packets} packets)")
    return dropped_packets

# =============================================================================
# TC ATTACHMENT AND CLEANUP
# =============================================================================

def attach_tc_hooks(bpf: BPF) -> None:
    global ipr, ifindex
    ipr = IPRoute()
    matches = ipr.link_lookup(ifname=CAPTURE_INTERFACE)
    if not matches:
        raise RuntimeError(f"Interface not found: {CAPTURE_INTERFACE}")
    ifindex = matches[0]

    fn_ingress = bpf.load_func("physical_tc_ingress_tap", BPF.SCHED_CLS)
    fn_egress = bpf.load_func("physical_tc_egress_tap", BPF.SCHED_CLS)

    try:
        ipr.tc("del", "clsact", ifindex)
        time.sleep(0.1)
    except Exception:
        pass

    ipr.tc("add", "clsact", ifindex)
    ipr.tc(
        "add-filter", "bpf", ifindex, ":1",
        fd=fn_ingress.fd, name=fn_ingress.name,
        parent="ffff:fff2", classid=1, direct_action=True,
    )
    ipr.tc(
        "add-filter", "bpf", ifindex, ":2",
        fd=fn_egress.fd, name=fn_egress.name,
        parent="ffff:fff3", classid=1, direct_action=True,
    )
    log_message(f"[TC] eBPF hooks attached to {CAPTURE_INTERFACE}")


def detach_tc_hooks() -> None:
    global ipr, ifindex
    if ipr is None or ifindex is None:
        return
    try:
        ipr.tc("del", "clsact", ifindex)
        log_message("[TC] eBPF hooks detached")
    except Exception as e:
        log_message(f"[TC] Detach failed: {type(e).__name__}: {e}")
    try:
        ipr.close()
    except Exception:
        pass
    ipr = None
    ifindex = None

# =============================================================================
# SIGNALS AND MAIN
# =============================================================================

def signal_handler(sig, frame) -> None:
    log_message(f"[SIGNAL] Received signal {sig}. Shutting down gracefully...")
    capture_stop_event.set()


def main() -> None:
    global bpf_obj, shutdown_phase

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    log_message("=" * 80)
    log_message("[INIT] pi_ebpf_streamer_v1.2 - Proactive Adaptation (Packet-Preserving)")
    log_message(f"[INIT] CPUs: {num_cpus} | Perf pages: {PERF_PAGE_CNT} (64 MB)")
    log_message(f"[INIT] Raw queue: {CHUNK_QUEUE_MAXSIZE} | Compressed queue: {COMPRESS_QUEUE_MAXSIZE}")
    log_message(f"[INIT] Mode 1 (normal): snaplen={MODE1_SNAPLEN}, sample=1:{MODE1_SAMPLE_RATE}")
    log_message(f"[INIT] Mode 2 (degraded): snaplen={MODE2_SNAPLEN}, sample=1:{MODE2_SAMPLE_RATE}")
    log_message("[INIT] Mode 3 (critical): snaplen=128, sample=1:10->1:20->1:50->1:100 dynamic")
    log_message(f"[INIT] Proactive triggers: HighRateIntervals>={HIGH_RATE_INTERVALS_TO_DEGRADE} or PerfLost>0")
    log_message(f"[INIT] Chunk header size: {CHUNK_HEADER_SIZE} bytes protocol_version={CHUNK_VERSION}")
    log_message(f"[INIT] Startup capture wait for Vault: {START_CAPTURE_AFTER_VAULT_CONNECTED}")
    log_message("=" * 80)

    log_message("[BPF] Loading eBPF program...")
    try:
        bpf_obj = BPF(text=ebpf_source)
    except Exception as e:
        sys.exit(f"[-] Failed to load eBPF: {e}")
    log_message("[BPF] eBPF program loaded successfully")

    log_message("[BPF] Initializing runtime config...")
    set_runtime_config(MODE1_SNAPLEN, MODE1_SAMPLE_RATE, 1, force=True)
    log_message("[BPF] Runtime config initialized")

    compression_threads = []
    for i in range(NUM_COMPRESSION_WORKERS):
        t = threading.Thread(target=compression_worker, args=(i,), daemon=False)
        t.start()
        compression_threads.append(t)

    egress_thread = threading.Thread(target=network_sender, args=(0,), daemon=False)
    egress_thread.start()

    if START_CAPTURE_AFTER_VAULT_CONNECTED:
        log_message(f"[MAIN] Waiting up to {VAULT_STARTUP_WAIT_SEC}s for Vault connection before attaching capture...")
        if not egress_connected_event.wait(timeout=VAULT_STARTUP_WAIT_SEC):
            capture_stop_event.set()
            drain_stop_event.set()
            shutdown_phase = 3
            log_message("[-] Vault did not connect before timeout. Start vault_receiver first or check firewall/port.")
            egress_thread.join(timeout=5)
            return
        log_message("[MAIN] Vault connected. Proceeding with TC attach and capture.")

    try:
        attach_tc_hooks(bpf_obj)
    except Exception as e:
        drain_stop_event.set()
        capture_stop_event.set()
        sys.exit(f"[-] TC attachment failed: {e}")

    log_message(f"[PERF] Opening perf buffer ({PERF_PAGE_CNT} pages)...")
    try:
        bpf_obj["skb_events"].open_perf_buffer(on_packet, lost_cb=on_lost, page_cnt=PERF_PAGE_CNT)
    except Exception as e:
        detach_tc_hooks()
        drain_stop_event.set()
        capture_stop_event.set()
        sys.exit(f"[-] Perf buffer open failed: {e}")
    log_message("[PERF] Perf buffer opened successfully")

    flush_thread = threading.Thread(target=timeout_flush_worker, daemon=True)
    flush_thread.start()

    monitor_thread = threading.Thread(target=monitor_stats, daemon=True)
    monitor_thread.start()

    log_message("[MAIN] All threads started. Entering perf poll loop...")
    log_message("[MAIN] Press Ctrl+C to stop.")

    try:
        while not capture_stop_event.is_set():
            bpf_obj.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        log_message("[MAIN] Keyboard interrupt received")
    except Exception as e:
        log_message(f"[ERROR] Perf poll error: {type(e).__name__}: {e}")

    log_message("[SHUTDOWN] Detaching TC hooks to stop new capture...")
    detach_tc_hooks()

    log_message("[SHUTDOWN] Phase 1: Flushing CPU chunk builders...")
    with cpu_chunks_lock:
        for builder in cpu_chunks.values():
            builder.flush()

    shutdown_phase = 1
    log_message(f"[SHUTDOWN] Phase 2: Draining raw queue (timeout {QUEUE_DRAIN_TIMEOUT_SEC}s)...")
    if bounded_queue_join(raw_chunk_queue, "raw_chunk_queue", QUEUE_DRAIN_TIMEOUT_SEC):
        log_message("[SHUTDOWN] Raw queue drained successfully")
    else:
        log_message("[WARN] Raw queue drain incomplete, counting abandoned items as drops")
        drain_abandoned_raw_queue()

    shutdown_phase = 2
    log_message(f"[SHUTDOWN] Phase 3: Draining compressed queue (timeout {QUEUE_DRAIN_TIMEOUT_SEC}s)...")
    if bounded_queue_join(compressed_queue, "compressed_queue", QUEUE_DRAIN_TIMEOUT_SEC):
        log_message("[SHUTDOWN] Compressed queue drained successfully")
    else:
        log_message("[WARN] Compressed queue drain incomplete, counting abandoned items as egress drops")
        drain_abandoned_compressed_queue()

    drain_stop_event.set()
    shutdown_phase = 3
    log_message("[SHUTDOWN] Phase 4: Stopping workers...")

    for t in compression_threads:
        t.join(timeout=5)
    egress_thread.join(timeout=5)

    final = snapshot_stats()
    log_message("=" * 80)
    log_message("[FINAL STATS]")
    log_message(f"  Events Enqueued: {final['events_enqueued']}")
    log_message(f"  Events Sent: {final['events_sent']}")
    log_message(f"  Bytes Sent: {final['bytes_sent']:,}")
    log_message(f"  Compression Ratio: {final['compression_ratio']:.2%}")
    log_message(f"  Raw Packet Drops: {final['raw_packet_drops']}")
    log_message(f"  Compressed Packet Drops: {final['compress_packet_drops']}")
    log_message(f"  Egress Packet Drops: {final['egress_packet_drops']}")
    log_message(f"  Perf Lost: {final['perf_lost']}")
    log_message(f"  Sampled Out (intentional): {final['sampled_out']}")
    log_message(f"  Send Errors: {final['send_errors']}")
    log_message(f"  Send Timeouts: {final['send_timeouts']}")
    log_message(f"  Mode Changes: {final['mode_changes']}")

    total_observed_pipeline = final['events_enqueued'] + final['raw_packet_drops'] + final['perf_lost']
    if total_observed_pipeline > 0:
        pipeline_loss = (
            final['raw_packet_drops']
            + final['compress_packet_drops']
            + final['egress_packet_drops']
            + final['perf_lost']
        )
        loss_pct = (pipeline_loss / total_observed_pipeline) * 100
        effective_input = total_observed_pipeline + final['sampled_out']
        log_message(f"  Pipeline Loss (excl. sampling): {loss_pct:.3f}%")
        log_message(f"  Effective Input (incl. sampled): {effective_input:,}")

    log_message("=" * 80)
    log_message("[SHUTDOWN] Complete.")


if __name__ == "__main__":
    main()
