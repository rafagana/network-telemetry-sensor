#!/usr/bin/env python3

# Copyright 2026 Rafael Garcia Navarro
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ctypes
import os
import queue
import socket
import struct
import sys
import threading
import time
from bcc import BPF
from pyroute2 import IPRoute

# -----------------------------
# Configuration & Documentation
# -----------------------------
VAULT_IP = "192.168.10.137"
VAULT_PORT = 9999

CAPTURE_INTERFACE = "eth1"

# The standard maximum transmission unit (MTU) size for Ethernet frames including VLAN headers
SNAPLEN = 1522

QUEUE_MAXSIZE = 100000

# Kernel ring buffer allocation size (in pages). 
# A larger cushion catches the initial blast of packets while the Python thread wakes up
PERF_PAGE_CNT = 8192

# --- Dataset Integrity Guards (ML Data Leakage Prevention) ---
# To prevent Observer Contamination, we completely drop any traffic involving the monitoring Pi.
PI_MGMT_IP = "192.168.10.31"

# Explicit Endianness Handling:
# 1. socket.inet_aton() converts the string to network byte order.
# 2. struct.unpack("!I") explicitly interprets those bytes as a Big-Endian 32-bit integer.
# This guarantees PI_MGMT_IP_INT is exactly 0xC0A80A1F regardless of host architecture.
PI_MGMT_IP_INT = struct.unpack("!I", socket.inet_aton(PI_MGMT_IP))[0]

# C-friendly unsigned hexadecimal literal used inside the eBPF source.
PI_MGMT_IP_C_LITERAL = f"0x{PI_MGMT_IP_INT:08X}U"

# Frame structure for the streaming protocol: cap_len (u32), orig_len (u32), wall_ts_ns (u64), kernel_mono_ns (u64)
FRAME_HEADER_STRUCT = struct.Struct(">IIQQ")

if os.geteuid() != 0:
    sys.exit("[-] Run as root: sudo python3 pi_ebpf_streamer.py")

packet_queue = queue.Queue(maxsize=QUEUE_MAXSIZE)

stats = {
    "events_received": 0,
    "sent": 0,
    "user_queue_drops": 0,
    "perf_lost": 0,
    "socket_reconnects": 0,
    "send_errors": 0,
}

stats_lock = threading.Lock()

# Approximate conversion: bpf_ktime_get_ns() gives monotonic time, but PCAP needs wall-clock epoch time.
BOOT_WALL_OFFSET_NS = time.time_ns() - time.monotonic_ns()


class PktMeta(ctypes.Structure):
    _fields_ = [
        ("orig_len", ctypes.c_uint32),
        ("ts_ns", ctypes.c_uint64),
    ]

# Note: Python f-string variables are injected using standard single braces { },
# while literal C code structural blocks are protected using escaped double braces {{ }}.
ebpf_source = f"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/in.h>

struct vlan_hdr {{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
}};

#define SNAPLEN {SNAPLEN}

struct pkt_meta {{
    u32 orig_len;
    u64 ts_ns;
}};

BPF_PERF_OUTPUT(skb_events);

static __always_inline int parse_eth_proto(void **nh, void *data_end, u16 *eth_proto) {{
    struct ethhdr *eth = *nh;

    if ((void *)(eth + 1) > data_end)
        return -1;

    *eth_proto = eth->h_proto;
    *nh = eth + 1;

    if (*eth_proto == bpf_htons(ETH_P_8021Q) || *eth_proto == bpf_htons(ETH_P_8021AD)) {{
        struct vlan_hdr *vh = *nh;
        if ((void *)(vh + 1) > data_end)
            return -1;
        *eth_proto = vh->h_vlan_encapsulated_proto;
        *nh = vh + 1;

        if (*eth_proto == bpf_htons(ETH_P_8021Q) || *eth_proto == bpf_htons(ETH_P_8021AD)) {{
            vh = *nh;
            if ((void *)(vh + 1) > data_end)
                return -1;
            *eth_proto = vh->h_vlan_encapsulated_proto;
            *nh = vh + 1;
        }}
    }}

    return 0;
}}

int physical_tc_tap(struct __sk_buff *skb) {{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    void *nh = data;
    u16 eth_proto = 0;

    if (parse_eth_proto(&nh, data_end, &eth_proto) < 0)
        return TC_ACT_OK;

    if (eth_proto == bpf_htons(ETH_P_IP)) {{
        struct iphdr *ip = nh;

        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        if (ip->ihl < 5)
            return TC_ACT_OK;

        // --- EXCLUDE PI TELEMETRY & MANAGEMENT TRAFFIC ---
        // PI_MGMT_IP_C_LITERAL is generated from the human-readable PI_MGMT_IP,
        // e.g. "192.168.10.31" -> 0xC0A80A1FU.
        // bpf_htonl() converts the C integer literal into the representation expected
        // when comparing against ip->saddr/ip->daddr loaded from the packet.
        if (ip->saddr == bpf_htonl({PI_MGMT_IP_C_LITERAL}) || ip->daddr == bpf_htonl({PI_MGMT_IP_C_LITERAL})) {{
            return TC_ACT_OK;
        }}

        void *l4 = (void *)ip + (ip->ihl * 4);
        if (l4 > data_end)
            return TC_ACT_OK;
    }}

    u32 pkt_len = data_end - data;
    u32 capture_len = pkt_len > SNAPLEN ? SNAPLEN : pkt_len;

    struct pkt_meta meta = {{}}; 
    meta.orig_len = pkt_len;
    meta.ts_ns = bpf_ktime_get_ns();

    skb_events.perf_submit_skb(skb, capture_len, &meta, sizeof(meta));

    return TC_ACT_OK;
}}
"""


def connect_to_vault():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            print(f"[*] Connecting to Vault at {VAULT_IP}:{VAULT_PORT}...")
            s.connect((VAULT_IP, VAULT_PORT))
            print("[+] Connected to Vault.")
            return s

        except socket.error as e:
            print(f"[!] Vault connection failed: {e}; retrying in 3 seconds...")
            time.sleep(3)


def network_sender():
    client_socket = connect_to_vault()

    while True:
        item = packet_queue.get()

        if item is None:
            packet_queue.task_done()
            continue

        orig_len, wall_ts_ns, kernel_mono_ns, raw_bytes = item
        cap_len = len(raw_bytes)

        frame = FRAME_HEADER_STRUCT.pack(
            cap_len,
            orig_len,
            wall_ts_ns,
            kernel_mono_ns,
        ) + raw_bytes

        while True:
            try:
                client_socket.sendall(frame)
                with stats_lock:
                    stats["sent"] += 1
                break

            except socket.error as e:
                with stats_lock:
                    stats["send_errors"] += 1
                    stats["socket_reconnects"] += 1

                print(f"[!] Send failed: {e}; reconnecting...")
                try:
                    client_socket.close()
                except Exception:
                    pass

                client_socket = connect_to_vault()

        packet_queue.task_done()


def on_packet(cpu, data, size):
    meta_size = ctypes.sizeof(PktMeta)

    if size <= meta_size:
        return

    meta = ctypes.cast(data, ctypes.POINTER(PktMeta)).contents
    
    # Defensive programming: ensure we never read past the actual buffer size 
    # delivered by the kernel, even if the packet claims a larger orig_len.
    actual_cap_len = min(int(meta.orig_len), SNAPLEN, size - meta_size)
    raw_bytes = ctypes.string_at(data + meta_size, actual_cap_len)

    kernel_mono_ns = int(meta.ts_ns)
    wall_ts_ns = BOOT_WALL_OFFSET_NS + kernel_mono_ns

    try:
        packet_queue.put_nowait(
            (
                int(meta.orig_len),
                int(wall_ts_ns),
                int(kernel_mono_ns),
                raw_bytes,
            )
        )

        with stats_lock:
            stats["events_received"] += 1

    except queue.Full:
        with stats_lock:
            stats["user_queue_drops"] += 1


def on_lost(count):
    print(f"[!] Warning: Dropped {count} packets from kernel ring buffer!")
    with stats_lock:
        stats["perf_lost"] += int(count)


def attach_tc_ingress(bpf):
    fn = bpf.load_func("physical_tc_tap", BPF.SCHED_CLS)

    ip = IPRoute()
    matches = ip.link_lookup(ifname=CAPTURE_INTERFACE)

    if not matches:
        raise RuntimeError(f"Interface not found: {CAPTURE_INTERFACE}")

    idx = matches[0]

    try:
        ip.tc("del", "clsact", idx)
    except Exception:
        pass

    ip.tc("add", "clsact", idx)

    ip.tc(
        "add-filter",
        "bpf",
        idx,
        ":1",
        fd=fn.fd,
        name=fn.name,
        parent="ffff:fff2",
        classid=1,
        direct_action=True,
    )

    return ip, idx


def main():
    print("[*] Compiling eBPF TC ingress filter...")
    print(f"[*] Excluding Pi management IP: {PI_MGMT_IP} ({PI_MGMT_IP_C_LITERAL})")
    bpf = BPF(text=ebpf_source)

    ip, idx = attach_tc_ingress(bpf)

    bpf["skb_events"].open_perf_buffer(
        on_packet,
        page_cnt=PERF_PAGE_CNT,
        lost_cb=on_lost,
    )

    threading.Thread(target=network_sender, daemon=True).start()

    print(f"[+] eBPF active on {CAPTURE_INTERFACE} TC ingress. Monitoring framework active...")
    print("[*] Press Ctrl+C to stop cleanly.")
    
    try:
        while True:
            bpf.perf_buffer_poll(timeout=5)
    except KeyboardInterrupt:
        print("\n[-] Detaching filters and breaking execution loop.")
    finally:
        try:
            ip.tc("del", "clsact", idx)
        except Exception:
            pass
        print("[+] Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    main()