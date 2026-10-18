#!/usr/bin/env python3
"""
vault_router_v1.2.py

Vault receiver for the v5.3 Pi eBPF streamer with restored v4-style persistence:
- Receives v5.3 chunked/compressed TCP stream from the Pi sensor.
- Validates v5.3 packed headers and CRC32.
- Writes reconstructed Ethernet frames to rotating PCAP files.
- Optionally streams packet events to Kafka.
- Keeps the v5.4 transport hardening: receive timeout, large SO_RCVBUF,
  sequence gap detection, CRC validation, and protocol telemetry.

Wire protocol compatibility
---------------------------
The Pi streamer still sends protocol version 3 with this packed 62-byte header:
    >IHHQQQIBHHBQQI

Frame payload format after decompression:
    >QIIIQQ + Ethernet frame bytes
    seq, cap_len, orig_len, direction, wall_ts_ns, kernel_ts_ns, payload

Kafka notes
-----------
Kafka is optional and disabled unless --kafka-bootstrap is provided or
--kafka-enable is set. The script tries confluent_kafka first, then kafka-python.
If neither library is installed, PCAP writing still works and Kafka is disabled.

Recommended run
---------------
    python3 vault_router_v1.2_pcap_kafka.py \
        --port 9999 \
        --timeout 60 \
        --rcvbuf 64M \
        --output /home/rafagana/phd/ebpf/pcap

With Kafka metadata-only events:
    python3 vault_router_v1.2_pcap_kafka.py \
        --port 9999 \
        --timeout 60 \
        --rcvbuf 64M \
        --output /home/rafagana/phd/ebpf/pcap \
        --kafka-bootstrap 127.0.0.1:9092 \
        --kafka-topic ebpf-packets

With Kafka payloads included as base64. This is heavier:
    add --kafka-payload-base64
"""

import argparse
import base64
import json
import os
import socket
import struct
import threading
import time
import zlib
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

import zstandard as zstd

# =============================================================================
# PROTOCOL LAYOUTS
# =============================================================================

FRAME_HEADER_STRUCT = struct.Struct(">QIIIQQ")
FRAME_HEADER_SIZE = FRAME_HEADER_STRUCT.size

V51_CHUNK_HEADER_STRUCT = struct.Struct(">IHHQQQIQQ")
V51_CHUNK_HEADER_SIZE = V51_CHUNK_HEADER_STRUCT.size

V52_CHUNK_HEADER_STRUCT = struct.Struct(">IHHQQQIBHBQQ")
V52_CHUNK_HEADER_SIZE = V52_CHUNK_HEADER_STRUCT.size

V53_CHUNK_HEADER_STRUCT = struct.Struct(">IHHQQQIBHHBQQI")
V53_CHUNK_HEADER_SIZE = V53_CHUNK_HEADER_STRUCT.size

CHUNK_MAGIC = 0x43484E4B  # "CHNK"

DEFAULT_MAX_COMPRESSED_SIZE = 16 * 1024 * 1024
DEFAULT_MAX_UNCOMPRESSED_SIZE = 64 * 1024 * 1024
DEFAULT_RCVBUF = 32 * 1024 * 1024
DEFAULT_RECV_TIMEOUT = 60.0

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHIIII",
    0xA1B2C3D4,  # magic
    2,           # version major
    4,           # version minor
    0,           # thiszone
    0,           # sigfigs
    65535,       # snaplen
    1,           # LINKTYPE_ETHERNET
)

DIR_NAMES = {0: "ingress", 1: "egress"}
MODE_NAMES = {1: "normal", 2: "pressure", 3: "critical"}


# =============================================================================
# HELPERS
# =============================================================================

def parse_size(value: str) -> int:
    value = str(value).strip().lower()
    multiplier = 1
    if value.endswith("k"):
        multiplier = 1024
        value = value[:-1]
    elif value.endswith("m"):
        multiplier = 1024 * 1024
        value = value[:-1]
    elif value.endswith("g"):
        multiplier = 1024 * 1024 * 1024
        value = value[:-1]
    return int(value) * multiplier


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def pcap_ts_from_ns(ns: int) -> Tuple[int, int]:
    sec = ns // 1_000_000_000
    usec = (ns % 1_000_000_000) // 1_000
    return int(sec), int(usec)


# =============================================================================
# PCAP WRITER
# =============================================================================

class RotatingPcapWriter:
    def __init__(
        self,
        output_dir: str,
        prefix: str = "capture",
        rotate_bytes: int = 1024 * 1024 * 1024,
        rotate_seconds: int = 300,
        flush_packets: int = 1024,
        enabled: bool = True,
    ):
        self.output_dir = Path(output_dir)
        self.prefix = prefix
        self.rotate_bytes = rotate_bytes
        self.rotate_seconds = rotate_seconds
        self.flush_packets = max(1, flush_packets)
        self.enabled = enabled
        self.file = None
        self.file_path: Optional[Path] = None
        self.file_index = 0
        self.file_start_time = 0.0
        self.file_bytes = 0
        self.packet_count = 0
        self.total_packets = 0
        self.total_bytes = 0
        self.lock = threading.Lock()

        if self.enabled:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self._open_new_file_locked()

    def log(self, msg: str) -> None:
        print(f"[{now_ts()}] {msg}", flush=True)

    def _open_new_file_locked(self) -> None:
        if not self.enabled:
            return

        if self.file is not None:
            try:
                self.file.flush()
                os.fsync(self.file.fileno())
            except Exception:
                pass
            try:
                self.file.close()
            except Exception:
                pass
            self.log(f"[PCAP] Closed {self.file_path} packets={self.packet_count} bytes={self.file_bytes}")

        # Format: sensor-20260804-181042-123456789.pcap (matching v4 format)
        nano_id = time.time_ns() % 1_000_000_000
        self.file_path = self.output_dir / f"{self.prefix}-{time.strftime('%Y%m%d-%H%M%S')}-{nano_id:09d}.pcap"
        self.file_index += 1
        self.file = open(self.file_path, "wb", buffering=1024 * 1024)
        self.file.write(PCAP_GLOBAL_HEADER)
        self.file_start_time = time.time()
        self.file_bytes = len(PCAP_GLOBAL_HEADER)
        self.packet_count = 0
        self.log(f"[PCAP] Writing {self.file_path}")

    def _should_rotate_locked(self) -> bool:
        if not self.enabled or self.file is None:
            return False
        if self.rotate_bytes > 0 and self.file_bytes >= self.rotate_bytes:
            return True
        if self.rotate_seconds > 0 and (time.time() - self.file_start_time) >= self.rotate_seconds:
            return True
        return False

    def write_packet(self, wall_ts_ns: int, payload: bytes, orig_len: int) -> None:
        if not self.enabled:
            return

        incl_len = len(payload)
        sec, usec = pcap_ts_from_ns(wall_ts_ns)
        record_header = struct.pack("<IIII", sec, usec, incl_len, int(orig_len))

        with self.lock:
            if self._should_rotate_locked():
                self._open_new_file_locked()

            self.file.write(record_header)
            self.file.write(payload)
            written = len(record_header) + incl_len
            self.file_bytes += written
            self.packet_count += 1
            self.total_packets += 1
            self.total_bytes += written

            if self.packet_count % self.flush_packets == 0:
                self.file.flush()

    def close(self) -> None:
        if not self.enabled:
            return
        with self.lock:
            if self.file is not None:
                try:
                    self.file.flush()
                    os.fsync(self.file.fileno())
                except Exception:
                    pass
                try:
                    self.file.close()
                except Exception:
                    pass
                self.log(f"[PCAP] Closed {self.file_path} packets={self.packet_count} bytes={self.file_bytes}")
                self.file = None


# =============================================================================
# FRAME ARCHIVE WRITER
# =============================================================================

class RotatingFrameWriter:
    """Writes exact binary frame archives preserving V4/V5 wire format."""
    def __init__(
        self,
        output_dir: str,
        prefix: str = "sensor",
        rotate_bytes: int = 100 * 1024 * 1024,
        enabled: bool = False,
    ):
        self.output_dir = Path(output_dir) / "frames"
        self.prefix = prefix
        self.rotate_bytes = rotate_bytes
        self.enabled = enabled
        self.file = None
        self.file_path: Optional[Path] = None
        self.file_bytes = 0
        self.frame_count = 0
        self.total_frames = 0
        self.total_bytes = 0
        self.lock = threading.Lock()

        if self.enabled:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self._open_new_file_locked()

    def log(self, msg: str) -> None:
        print(f"[{now_ts()}] {msg}", flush=True)

    def _open_new_file_locked(self) -> None:
        if not self.enabled:
            return

        if self.file is not None:
            try:
                self.file.flush()
                os.fsync(self.file.fileno())
            except Exception:
                pass
            try:
                self.file.close()
            except Exception:
                pass
            self.log(f"[FRAME] Closed {self.file_path} frames={self.frame_count} bytes={self.file_bytes}")

        # Format: sensor-20260804-181042-123456789.frames
        nano_id = time.time_ns() % 1_000_000_000
        self.file_path = self.output_dir / f"{self.prefix}-{time.strftime('%Y%m%d-%H%M%S')}-{nano_id:09d}.frames"
        self.file = open(self.file_path, "wb", buffering=1024 * 1024)
        self.file_bytes = 0
        self.frame_count = 0
        self.log(f"[FRAME] Writing {self.file_path}")

    def write_frame(self, header: bytes, payload: bytes) -> None:
        """Write 36-byte frame header + payload to archive."""
        if not self.enabled:
            return

        with self.lock:
            record_size = len(header) + len(payload)
            if self.rotate_bytes > 0 and self.file_bytes + record_size >= self.rotate_bytes:
                self._open_new_file_locked()

            self.file.write(header)
            self.file.write(payload)
            self.file_bytes += record_size
            self.frame_count += 1
            self.total_frames += 1
            self.total_bytes += record_size

    def close(self) -> None:
        if not self.enabled:
            return
        with self.lock:
            if self.file is not None:
                try:
                    self.file.flush()
                    os.fsync(self.file.fileno())
                except Exception:
                    pass
                try:
                    self.file.close()
                except Exception:
                    pass
                self.log(f"[FRAME] Closed {self.file_path} frames={self.frame_count} bytes={self.file_bytes}")
                self.file = None


# =============================================================================
# KAFKA PRODUCER WRAPPER
# =============================================================================

class OptionalKafkaProducer:
    def __init__(
        self,
        bootstrap: Optional[str],
        topic: str,
        client_id: str = "vault-router-v1.2",
        include_payload_b64: bool = False,
        enabled: bool = False,
        linger_ms: int = 20,
        batch_size: int = 65536,
    ):
        self.bootstrap = bootstrap
        self.topic = topic
        self.client_id = client_id
        self.include_payload_b64 = include_payload_b64
        self.enabled = bool(enabled or bootstrap)
        self.backend = None
        self.producer = None
        self.sent = 0
        self.errors = 0
        self.lock = threading.Lock()

        if not self.enabled:
            return

        if not self.bootstrap:
            print(f"[{now_ts()}] [KAFKA] Disabled: no bootstrap servers provided", flush=True)
            self.enabled = False
            return

        # Try confluent_kafka first.
        try:
            from confluent_kafka import Producer  # type: ignore
            self.producer = Producer({
                "bootstrap.servers": self.bootstrap,
                "client.id": self.client_id,
                "linger.ms": linger_ms,
                "batch.num.messages": 10000,
                "queue.buffering.max.messages": 200000,
            })
            self.backend = "confluent_kafka"
            print(f"[{now_ts()}] [KAFKA] Enabled via confluent_kafka bootstrap={self.bootstrap} topic={self.topic}", flush=True)
            return
        except Exception as e:
            print(f"[{now_ts()}] [KAFKA] confluent_kafka unavailable: {type(e).__name__}: {e}", flush=True)

        # Fallback to kafka-python.
        try:
            from kafka import KafkaProducer  # type: ignore
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap.split(","),
                client_id=self.client_id,
                linger_ms=linger_ms,
                batch_size=batch_size,
                value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode("utf-8"),
                key_serializer=lambda k: str(k).encode("utf-8"),
            )
            self.backend = "kafka-python"
            print(f"[{now_ts()}] [KAFKA] Enabled via kafka-python bootstrap={self.bootstrap} topic={self.topic}", flush=True)
            return
        except Exception as e:
            print(f"[{now_ts()}] [KAFKA] kafka-python unavailable: {type(e).__name__}: {e}", flush=True)

        print(f"[{now_ts()}] [KAFKA] Disabled: install confluent-kafka or kafka-python", flush=True)
        self.enabled = False

    def _delivery_report(self, err, msg) -> None:
        if err is not None:
            with self.lock:
                self.errors += 1

    def send_packet(
        self,
        seq: int,
        cap_len: int,
        orig_len: int,
        direction: int,
        wall_ts_ns: int,
        kernel_ts_ns: int,
        mode: int,
        snaplen: int,
        sample_rate: int,
        chunk_id: int,
        payload: bytes,
    ) -> None:
        if not self.enabled or self.producer is None:
            return

        event = {
            "seq": seq,
            "cap_len": cap_len,
            "orig_len": orig_len,
            "direction": direction,
            "direction_name": DIR_NAMES.get(direction, "unknown"),
            "wall_ts_ns": wall_ts_ns,
            "kernel_ts_ns": kernel_ts_ns,
            "mode": mode,
            "mode_name": MODE_NAMES.get(mode, "unknown"),
            "snaplen": snaplen,
            "sample_rate": sample_rate,
            "chunk_id": chunk_id,
        }
        if self.include_payload_b64:
            event["payload_b64"] = base64.b64encode(payload).decode("ascii")

        try:
            if self.backend == "confluent_kafka":
                data = json.dumps(event, separators=(",", ":")).encode("utf-8")
                self.producer.produce(self.topic, key=str(seq).encode("utf-8"), value=data, callback=self._delivery_report)
                # Poll with zero timeout to serve callbacks without blocking.
                self.producer.poll(0)
            elif self.backend == "kafka-python":
                self.producer.send(self.topic, key=seq, value=event)
            with self.lock:
                self.sent += 1
        except BufferError:
            # Queue full. Do not block receiver path indefinitely.
            with self.lock:
                self.errors += 1
            try:
                self.producer.poll(0.01)
            except Exception:
                pass
        except Exception:
            with self.lock:
                self.errors += 1

    def flush(self, timeout: float = 5.0) -> None:
        if not self.enabled or self.producer is None:
            return
        try:
            self.producer.flush(timeout)
        except TypeError:
            self.producer.flush()
        except Exception:
            pass


# =============================================================================
# VAULT RECEIVER
# =============================================================================

class VaultReceiver:
    def __init__(
        self,
        host: str,
        port: int,
        output_dir: str,
        recv_timeout: float,
        rcvbuf: int,
        max_compressed_size: int,
        max_uncompressed_size: int,
        debug: bool,
        pcap_writer: RotatingPcapWriter,
        frame_writer: RotatingFrameWriter,
        kafka_producer: OptionalKafkaProducer,
    ):
        self.host = host
        self.port = port
        self.output_dir = output_dir
        self.recv_timeout = recv_timeout
        self.rcvbuf = rcvbuf
        self.max_compressed_size = max_compressed_size
        self.max_uncompressed_size = max_uncompressed_size
        self.debug = debug
        self.running = True
        self.pcap_writer = pcap_writer
        self.frame_writer = frame_writer
        self.kafka_producer = kafka_producer

        self.stats = {
            "total_bytes": 0,
            "pcap_packets": 0,
            "frame_archives": 0,
            "kafka_events": 0,
            "v4_frames": 0,
            "v5_chunks": 0,
            "v51_chunks": 0,
            "v52_chunks": 0,
            "v53_chunks": 0,
            "sequence_gaps": 0,
            "chunk_gaps": 0,
            "duplicates": 0,
            "validation_errors": 0,
            "crc_errors": 0,
            "recv_timeouts": 0,
            "connections": 0,
            "disconnects": 0,
        }

        self.last_seq = 0
        self.last_chunk_id = 0
        self.decompressor = zstd.ZstdDecompressor()
        self.stats_lock = threading.Lock()
        self.start_time = time.time()

        self.mode_stats = {
            1: {"chunks": 0, "packets": 0},
            2: {"chunks": 0, "packets": 0},
            3: {"chunks": 0, "packets": 0},
        }

    def log(self, msg: str) -> None:
        print(f"[{now_ts()}] {msg}", flush=True)

    def dlog(self, msg: str) -> None:
        if self.debug:
            self.log(msg)

    def inc_stat(self, key: str, value: int = 1) -> None:
        with self.stats_lock:
            self.stats[key] += value

    def configure_connection(self, conn: socket.socket, addr: tuple) -> None:
        conn.settimeout(self.recv_timeout)
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        except OSError as e:
            self.log(f"[WARN] Could not set SO_RCVBUF={self.rcvbuf}: {e}")
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        actual_rcvbuf = conn.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        self.log(f"[CONN] Client connected: {addr} SO_RCVBUF={actual_rcvbuf} timeout={self.recv_timeout}s")

    def recv_exact(self, conn: socket.socket, n: int, label: str) -> Optional[bytes]:
        if n < 0:
            self.log(f"[ERROR] recv_exact negative length label={label} n={n}")
            self.inc_stat("validation_errors")
            return None

        buf = bytearray()
        start = time.time()
        try:
            while len(buf) < n:
                part = conn.recv(n - len(buf))
                if not part:
                    self.dlog(f"[DEBUG] recv_exact EOF label={label} wanted={n} got={len(buf)}")
                    return None
                buf.extend(part)
            if self.debug:
                elapsed_ms = (time.time() - start) * 1000.0
                self.dlog(f"[DEBUG] recv_exact OK label={label} bytes={n} elapsed_ms={elapsed_ms:.1f}")
            return bytes(buf)
        except socket.timeout:
            self.log(f"[ERROR] recv_exact timeout label={label} wanted={n} got={len(buf)} timeout={self.recv_timeout}s")
            self.inc_stat("recv_timeouts")
            return None
        except Exception as e:
            self.log(f"[ERROR] recv_exact failed label={label} wanted={n} got={len(buf)}: {type(e).__name__}: {e}")
            self.inc_stat("validation_errors")
            return None

    def validate_chunk_sizes(self, chunk_id: int, uncompressed_size: int, compressed_size: int, version: str) -> bool:
        if compressed_size <= 0 or compressed_size > self.max_compressed_size:
            self.log(f"[ERROR] {version} invalid compressed_size={compressed_size} chunk_id={chunk_id}")
            self.inc_stat("validation_errors")
            return False
        if uncompressed_size <= 0 or uncompressed_size > self.max_uncompressed_size:
            self.log(f"[ERROR] {version} invalid uncompressed_size={uncompressed_size} chunk_id={chunk_id}")
            self.inc_stat("validation_errors")
            return False
        return True

    def update_gap_state(self, chunk_id: int, first_seq: int, last_seq: int, version: str) -> bool:
        # Returns True if this is a new in-order or gapped-forward chunk, False for duplicate/old.
        if self.last_chunk_id > 0:
            if chunk_id <= self.last_chunk_id:
                self.log(f"[DUP] {version} duplicate/old chunk_id={chunk_id} last_chunk_id={self.last_chunk_id}")
                self.inc_stat("duplicates")
                return False
            if chunk_id != self.last_chunk_id + 1:
                gap = chunk_id - self.last_chunk_id - 1
                self.log(f"[GAP] {version} Chunk gap: {gap} chunks missing ({self.last_chunk_id} -> {chunk_id})")
                with self.stats_lock:
                    self.stats["sequence_gaps"] += gap
                    self.stats["chunk_gaps"] += gap

        if self.last_seq > 0 and first_seq != self.last_seq + 1:
            gap = first_seq - self.last_seq - 1
            if gap > 0:
                self.log(f"[GAP] {version} Sequence gap: {gap} sequences missing ({self.last_seq} -> {first_seq})")
                self.inc_stat("sequence_gaps", gap)
            else:
                self.log(f"[DUP] {version} non-increasing sequence first_seq={first_seq} last_seq={self.last_seq}")
                self.inc_stat("duplicates")
                return False

        self.last_chunk_id = chunk_id
        self.last_seq = last_seq
        return True

    def process_decompressed_frames(
        self,
        chunk: bytes,
        expected_packet_count: Optional[int],
        chunk_id: int,
        version: str,
        mode: int = 0,
        snaplen: int = 0,
        sample_rate: int = 1,
    ) -> int:
        frame_count = 0
        offset = 0
        chunk_len = len(chunk)

        while offset + FRAME_HEADER_SIZE <= chunk_len:
            try:
                seq, cap_len, orig_len, direction, wall_ts_ns, kernel_ts_ns = FRAME_HEADER_STRUCT.unpack_from(chunk, offset)
            except struct.error:
                self.log(f"[WARN] {version} chunk_id={chunk_id}: malformed frame header offset={offset}")
                self.inc_stat("validation_errors")
                break
            offset += FRAME_HEADER_SIZE

            if cap_len <= 0:
                self.log(f"[WARN] {version} chunk_id={chunk_id}: invalid cap_len={cap_len} frame={frame_count}")
                self.inc_stat("validation_errors")
                break

            next_offset = offset + cap_len
            if next_offset > chunk_len:
                self.log(f"[WARN] {version} chunk_id={chunk_id}: truncated frame seq={seq} cap_len={cap_len}")
                self.inc_stat("validation_errors")
                break

            payload = chunk[offset:next_offset]
            offset = next_offset
            frame_count += 1

            # Write to PCAP (standard Wireshark format)
            self.pcap_writer.write_packet(wall_ts_ns, payload, orig_len)
            
            # Write to frame archive (exact wire format with metadata)
            frame_header = chunk[offset - FRAME_HEADER_SIZE - cap_len:offset - cap_len]
            self.frame_writer.write_frame(frame_header, payload)
            
            # Send to Kafka
            self.kafka_producer.send_packet(
                seq=seq,
                cap_len=cap_len,
                orig_len=orig_len,
                direction=direction,
                wall_ts_ns=wall_ts_ns,
                kernel_ts_ns=kernel_ts_ns,
                mode=mode,
                snaplen=snaplen,
                sample_rate=sample_rate,
                chunk_id=chunk_id,
                payload=payload,
            )

        if offset != chunk_len:
            self.log(f"[WARN] {version} chunk_id={chunk_id}: trailing bytes={chunk_len - offset}")
            self.inc_stat("validation_errors")

        if expected_packet_count is not None and frame_count != expected_packet_count:
            self.log(f"[WARN] {version} chunk_id={chunk_id}: expected {expected_packet_count} frames, got {frame_count}")
            self.inc_stat("validation_errors")

        with self.stats_lock:
            self.stats["pcap_packets"] += frame_count
            self.stats["frame_archives"] = self.frame_writer.total_frames if self.frame_writer.enabled else 0
            self.stats["kafka_events"] = self.kafka_producer.sent

        return frame_count

    # -------------------------------------------------------------------------
    # Protocol handlers
    # -------------------------------------------------------------------------

    def handle_v4_frame(self, conn: socket.socket, first_bytes: bytes) -> bool:
        rest = self.recv_exact(conn, FRAME_HEADER_SIZE - len(first_bytes), "v4-rest-header")
        if rest is None:
            return False
        frame_header = first_bytes + rest
        seq, cap_len, orig_len, direction, wall_ts_ns, kernel_ts_ns = FRAME_HEADER_STRUCT.unpack(frame_header)
        payload = self.recv_exact(conn, cap_len, f"v4-payload-seq-{seq}")
        if payload is None:
            return False

        self.pcap_writer.write_packet(wall_ts_ns, payload, orig_len)
        self.frame_writer.write_frame(frame_header, payload)
        self.kafka_producer.send_packet(seq, cap_len, orig_len, direction, wall_ts_ns, kernel_ts_ns, 0, 0, 1, 0, payload)

        with self.stats_lock:
            self.stats["v4_frames"] += 1
            self.stats["total_bytes"] += FRAME_HEADER_SIZE + cap_len
            self.stats["pcap_packets"] += 1
            self.stats["frame_archives"] = self.frame_writer.total_frames if self.frame_writer.enabled else 0
            self.stats["kafka_events"] = self.kafka_producer.sent
        return True

    def handle_v5_chunk(self, conn: socket.socket, uncompressed_size: int) -> bool:
        compressed_size_bytes = self.recv_exact(conn, 8, "v5-compressed-size")
        if compressed_size_bytes is None:
            return False
        compressed_size = struct.unpack(">Q", compressed_size_bytes)[0]
        if not self.validate_chunk_sizes(0, uncompressed_size, compressed_size, "v5"):
            return False
        compressed = self.recv_exact(conn, compressed_size, f"v5-compressed-{compressed_size}")
        if compressed is None:
            return False
        try:
            chunk = self.decompressor.decompress(compressed)
            if len(chunk) != uncompressed_size:
                self.log(f"[WARN] v5 size mismatch: expected {uncompressed_size}, got {len(chunk)}")
                self.inc_stat("validation_errors")
            frames = self.process_decompressed_frames(chunk, None, 0, "v5")
            with self.stats_lock:
                self.stats["v5_chunks"] += 1
                self.stats["total_bytes"] += 16 + compressed_size
            self.dlog(f"[DEBUG] v5 processed frames={frames}")
        except Exception as e:
            self.log(f"[ERROR] v5 processing failed: {type(e).__name__}: {e}")
            self.inc_stat("validation_errors")
        return True

    def handle_v51_chunk(self, conn: socket.socket, first_bytes: bytes) -> bool:
        rest_header = self.recv_exact(conn, V51_CHUNK_HEADER_SIZE - len(first_bytes), "v5.1-rest-header")
        if rest_header is None:
            return False
        header = first_bytes + rest_header
        magic, version, flags, chunk_id, first_seq, last_seq, packet_count, uncompressed_size, compressed_size = V51_CHUNK_HEADER_STRUCT.unpack(header)
        if not self.validate_chunk_sizes(chunk_id, uncompressed_size, compressed_size, "v5.1"):
            return False
        compressed = self.recv_exact(conn, compressed_size, f"v5.1-compressed-chunk-{chunk_id}")
        if compressed is None:
            return False
        try:
            chunk = self.decompressor.decompress(compressed)
            if len(chunk) != uncompressed_size:
                self.log(f"[WARN] v5.1 size mismatch chunk_id={chunk_id}: expected {uncompressed_size}, got {len(chunk)}")
                self.inc_stat("validation_errors")
            is_new = self.update_gap_state(chunk_id, first_seq, last_seq, "v5.1")
            if is_new:
                self.process_decompressed_frames(chunk, packet_count, chunk_id, "v5.1")
            with self.stats_lock:
                self.stats["v51_chunks"] += 1
                self.stats["total_bytes"] += V51_CHUNK_HEADER_SIZE + compressed_size
        except Exception as e:
            self.log(f"[ERROR] v5.1 processing failed chunk_id={chunk_id}: {type(e).__name__}: {e}")
            self.inc_stat("validation_errors")
        return True

    def handle_v52_chunk(self, conn: socket.socket, first_bytes: bytes) -> bool:
        rest_header = self.recv_exact(conn, V52_CHUNK_HEADER_SIZE - len(first_bytes), "v5.2-rest-header")
        if rest_header is None:
            return False
        header = first_bytes + rest_header
        magic, version, flags, chunk_id, first_seq, last_seq, packet_count, mode, snaplen, sample_rate, uncompressed_size, compressed_size = V52_CHUNK_HEADER_STRUCT.unpack(header)
        if not self.validate_chunk_sizes(chunk_id, uncompressed_size, compressed_size, "v5.2"):
            return False
        compressed = self.recv_exact(conn, compressed_size, f"v5.2-compressed-chunk-{chunk_id}")
        if compressed is None:
            return False
        try:
            chunk = self.decompressor.decompress(compressed)
            if len(chunk) != uncompressed_size:
                self.log(f"[WARN] v5.2 size mismatch chunk_id={chunk_id}: expected {uncompressed_size}, got {len(chunk)}")
                self.inc_stat("validation_errors")
            is_new = self.update_gap_state(chunk_id, first_seq, last_seq, "v5.2")
            frames = 0
            if is_new:
                frames = self.process_decompressed_frames(chunk, packet_count, chunk_id, "v5.2", mode, snaplen, sample_rate)
            if mode in self.mode_stats:
                with self.stats_lock:
                    self.mode_stats[mode]["chunks"] += 1
                    self.mode_stats[mode]["packets"] += packet_count
            with self.stats_lock:
                self.stats["v52_chunks"] += 1
                self.stats["total_bytes"] += V52_CHUNK_HEADER_SIZE + compressed_size
            self.dlog(f"[DEBUG] v5.2 processed chunk_id={chunk_id} frames={frames}")
        except Exception as e:
            self.log(f"[ERROR] v5.2 processing failed chunk_id={chunk_id}: {type(e).__name__}: {e}")
            self.inc_stat("validation_errors")
        return True

    def handle_v53_chunk(self, conn: socket.socket, first_bytes: bytes) -> bool:
        rest_header = self.recv_exact(conn, V53_CHUNK_HEADER_SIZE - len(first_bytes), "v5.3-rest-header")
        if rest_header is None:
            return False
        header = first_bytes + rest_header
        (
            magic, version, flags, chunk_id, first_seq, last_seq,
            packet_count, mode, snaplen, sample_rate, padding,
            uncompressed_size, compressed_size, crc32_expected,
        ) = V53_CHUNK_HEADER_STRUCT.unpack(header)

        if magic != CHUNK_MAGIC or version != 3:
            self.log(f"[ERROR] Invalid v5.3 header magic=0x{magic:08x} version={version}")
            self.inc_stat("validation_errors")
            return False
        if not self.validate_chunk_sizes(chunk_id, uncompressed_size, compressed_size, "v5.3"):
            return False

        compressed = self.recv_exact(conn, compressed_size, f"v5.3-compressed-chunk-{chunk_id}")
        if compressed is None:
            self.log(f"[ERROR] v5.3 chunk_id={chunk_id}: incomplete compressed payload")
            return False

        crc32_actual = zlib.crc32(compressed) & 0xffffffff
        if crc32_actual != crc32_expected:
            self.log(f"[CRC ERROR] v5.3 chunk_id={chunk_id}: expected=0x{crc32_expected:08x} actual=0x{crc32_actual:08x}")
            with self.stats_lock:
                self.stats["crc_errors"] += 1
                self.stats["validation_errors"] += 1
            return False

        try:
            chunk = self.decompressor.decompress(compressed)
            if len(chunk) != uncompressed_size:
                self.log(f"[WARN] v5.3 size mismatch chunk_id={chunk_id}: expected {uncompressed_size}, got {len(chunk)}")
                self.inc_stat("validation_errors")
            is_new = self.update_gap_state(chunk_id, first_seq, last_seq, "v5.3")
            frames = 0
            if is_new:
                frames = self.process_decompressed_frames(chunk, packet_count, chunk_id, "v5.3", mode, snaplen, sample_rate)
            if mode in self.mode_stats:
                with self.stats_lock:
                    self.mode_stats[mode]["chunks"] += 1
                    self.mode_stats[mode]["packets"] += packet_count
            with self.stats_lock:
                self.stats["v53_chunks"] += 1
                self.stats["total_bytes"] += V53_CHUNK_HEADER_SIZE + compressed_size
            self.dlog(f"[DEBUG] v5.3 processed chunk_id={chunk_id} frames={frames}")
        except Exception as e:
            self.log(f"[ERROR] v5.3 processing failed chunk_id={chunk_id}: {type(e).__name__}: {e}")
            self.inc_stat("validation_errors")
        return True

    # -------------------------------------------------------------------------
    # Connection/server
    # -------------------------------------------------------------------------

    def handle_connection(self, conn: socket.socket, addr: tuple) -> None:
        self.configure_connection(conn, addr)
        self.inc_stat("connections")
        try:
            while self.running:
                first_bytes = self.recv_exact(conn, 8, "protocol-first-8")
                if first_bytes is None:
                    break

                magic = struct.unpack(">I", first_bytes[:4])[0]
                if magic == CHUNK_MAGIC:
                    version = struct.unpack(">H", first_bytes[4:6])[0]
                    if version == 3:
                        if not self.handle_v53_chunk(conn, first_bytes):
                            break
                    elif version == 2:
                        if not self.handle_v52_chunk(conn, first_bytes):
                            break
                    else:
                        if not self.handle_v51_chunk(conn, first_bytes):
                            break
                else:
                    first_qword = struct.unpack(">Q", first_bytes)[0]
                    if first_qword > 1_000_000_000:
                        if not self.handle_v5_chunk(conn, first_qword):
                            break
                    else:
                        if not self.handle_v4_frame(conn, first_bytes):
                            break
        except Exception as e:
            self.log(f"[ERROR] Connection error from {addr}: {type(e).__name__}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self.inc_stat("disconnects")
            self.log(f"[CONN] Client disconnected: {addr}")

    def telemetry_worker(self) -> None:
        while self.running:
            time.sleep(5)
            with self.stats_lock:
                s = dict(self.stats)
                mode_s = {k: dict(v) for k, v in self.mode_stats.items()}
            uptime = max(0.001, time.time() - self.start_time)
            mb_total = s["total_bytes"] / 1_000_000
            mbps = (s["total_bytes"] * 8) / uptime / 1_000_000
            mode_summary = " | ".join(
                f"M{mode}: {mode_s[mode]['chunks']}c/{mode_s[mode]['packets']}p"
                for mode in sorted(mode_s.keys())
                if mode_s[mode]["chunks"] > 0
            )
            kafka_sent = self.kafka_producer.sent if self.kafka_producer else 0
            kafka_errs = self.kafka_producer.errors if self.kafka_producer else 0
            frame_status = f"Frames: {s['frame_archives']}f" if self.frame_writer.enabled else ""
            self.log(
                f"[TELEMETRY] Up: {uptime:.0f}s | "
                f"Conn: {s['connections']}/{s['disconnects']} | "
                f"v4: {s['v4_frames']} | v5: {s['v5_chunks']} | v5.1: {s['v51_chunks']} | "
                f"v5.2: {s['v52_chunks']} | v5.3: {s['v53_chunks']} | "
                f"SeqGaps: {s['sequence_gaps']} | ChunkGaps: {s['chunk_gaps']} | Dup: {s['duplicates']} | "
                f"ValErrs: {s['validation_errors']} | CrcErrs: {s['crc_errors']} | RecvTimeouts: {s['recv_timeouts']} | "
                f"PCAP: {s['pcap_packets']}p | {frame_status} | Kafka: {kafka_sent}e/{kafka_errs}err | "
                f"MB: {mb_total:.1f} | Mbps: {mbps:.1f}"
                + (f" | {mode_summary}" if mode_summary else "")
            )

    def run(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        except OSError:
            pass
        server.bind((self.host, self.port))
        server.listen(16)
        actual_server_rcvbuf = server.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        self.log(
            f"[SERVER] Listening on {self.host}:{self.port} SO_RCVBUF={actual_server_rcvbuf} "
            f"timeout={self.recv_timeout}s debug={self.debug} output={self.output_dir}"
        )

        telemetry_thread = threading.Thread(target=self.telemetry_worker, daemon=True)
        telemetry_thread.start()

        try:
            while self.running:
                server.settimeout(1.0)
                try:
                    conn, addr = server.accept()
                    t = threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            self.log("[SERVER] Keyboard interrupt")
        finally:
            self.running = False
            try:
                server.close()
            except Exception:
                pass
            self.pcap_writer.close()
            self.frame_writer.close()
            self.kafka_producer.flush(timeout=5.0)
            self.log("[SERVER] Shutdown complete")


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Vault router v1.2 with PCAP and optional Kafka output")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=9999, help="TCP port")
    parser.add_argument("--output", type=str, default="/home/rafagana/phd/ebpf/pcap", help="Directory for PCAP output")
    parser.add_argument("--timeout", type=float, default=DEFAULT_RECV_TIMEOUT, help="Per-connection recv timeout seconds")
    parser.add_argument("--rcvbuf", type=parse_size, default=DEFAULT_RCVBUF, help="TCP receive buffer, e.g. 64M")
    parser.add_argument("--max-compressed", type=parse_size, default=DEFAULT_MAX_COMPRESSED_SIZE, help="Max compressed chunk size")
    parser.add_argument("--max-uncompressed", type=parse_size, default=DEFAULT_MAX_UNCOMPRESSED_SIZE, help="Max uncompressed chunk size")
    parser.add_argument("--debug", action="store_true", help="Verbose diagnostics")

    parser.add_argument("--no-pcap", action="store_true", help="Disable PCAP writing")
    parser.add_argument("--pcap-prefix", type=str, default="sensor", help="PCAP filename prefix")
    parser.add_argument("--pcap-rotate-mb", type=int, default=1024, help="Rotate PCAP after N MB, 0 disables size rotation")
    parser.add_argument("--pcap-rotate-sec", type=int, default=300, help="Rotate PCAP after N seconds, 0 disables time rotation")
    parser.add_argument("--pcap-flush-packets", type=int, default=4096, help="Flush PCAP every N packets")

    parser.add_argument("--enable-frame-archive", action="store_true", help="Enable binary frame archiving (preserves seq/direction/timestamps)")
    parser.add_argument("--frame-rotate-mb", type=int, default=100, help="Rotate frame archive after N MB")

    parser.add_argument("--kafka-enable", action="store_true", help="Enable Kafka even if bootstrap is empty")
    parser.add_argument("--kafka-bootstrap", type=str, default="", help="Kafka bootstrap servers, e.g. 127.0.0.1:9092")
    parser.add_argument("--kafka-topic", type=str, default="ebpf-packets", help="Kafka topic")
    parser.add_argument("--kafka-client-id", type=str, default="vault-router-v1.2", help="Kafka client ID")
    parser.add_argument("--kafka-payload-base64", action="store_true", help="Include packet payload as base64 in Kafka JSON events")
    parser.add_argument("--kafka-linger-ms", type=int, default=20, help="Kafka linger.ms")

    args = parser.parse_args()

    pcap_writer = RotatingPcapWriter(
        output_dir=args.output,
        prefix=args.pcap_prefix,
        rotate_bytes=args.pcap_rotate_mb * 1024 * 1024 if args.pcap_rotate_mb > 0 else 0,
        rotate_seconds=args.pcap_rotate_sec,
        flush_packets=args.pcap_flush_packets,
        enabled=not args.no_pcap,
    )

    frame_writer = RotatingFrameWriter(
        output_dir=args.output,
        prefix=args.pcap_prefix,
        rotate_bytes=args.frame_rotate_mb * 1024 * 1024,
        enabled=args.enable_frame_archive,
    )

    kafka_producer = OptionalKafkaProducer(
        bootstrap=args.kafka_bootstrap or None,
        topic=args.kafka_topic,
        client_id=args.kafka_client_id,
        include_payload_b64=args.kafka_payload_base64,
        enabled=args.kafka_enable,
        linger_ms=args.kafka_linger_ms,
    )

    receiver = VaultReceiver(
        host=args.host,
        port=args.port,
        output_dir=args.output,
        recv_timeout=args.timeout,
        rcvbuf=args.rcvbuf,
        max_compressed_size=args.max_compressed,
        max_uncompressed_size=args.max_uncompressed,
        debug=args.debug,
        pcap_writer=pcap_writer,
        frame_writer=frame_writer,
        kafka_producer=kafka_producer,
    )
    receiver.run()


if __name__ == "__main__":
    main()
