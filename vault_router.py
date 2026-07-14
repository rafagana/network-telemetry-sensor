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

import os
import socket
import struct
import time
import threading
from confluent_kafka import Producer

# -----------------------------
# Configuration
# -----------------------------
BIND_IP = "0.0.0.0"
BIND_PORT = 9999

PCAP_DIR = "/home/rafagana/phd/ebpf/pcap"
KAFKA_BROKER = "127.0.0.1:9092"
KAFKA_TOPIC = "iot-raw-telemetry"

SNAPLEN = 1522
MAX_PCAP_SIZE = 100 * 1024 * 1024

# Using '=' for native byte order alignment matching the Pi's C-struct memory layout
FRAME_HEADER_STRUCT = struct.Struct(">IIQQ")
FRAME_HEADER_SIZE = FRAME_HEADER_STRUCT.size

# Frame format from Pi to Vault:
# cap_len:          uint32
# orig_len:         uint32
# wall_ts_ns:       uint64
# kernel_mono_ns:   uint64

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHIIII",
    0xA1B2C3D4,
    2,
    4,
    0,
    0,
    SNAPLEN,
    1,
)

stats = {
    "connections": 0,
    "packets": 0,
    "bytes": 0,
    "pcap_rotations": 0,
    "kafka_enqueued": 0,
    "kafka_dropped_local": 0,
    "kafka_delivery_errors": 0,
    "malformed_frames": 0,
}

def kafka_delivery_report(err, msg):
    if err is not None:
        stats["kafka_delivery_errors"] += 1


producer = Producer(
    {
        "bootstrap.servers": KAFKA_BROKER,
        "acks": 0,
        "linger.ms": 10,
        "batch.num.messages": 10000,
        "queue.buffering.max.messages": 100000,
        "compression.type": "lz4",
    }
)


def ensure_dirs():
    os.makedirs(PCAP_DIR, exist_ok=True)


def get_new_pcap():
    filename = f"{PCAP_DIR}/sensor-{time.strftime('%Y%m%d-%H%M%S')}.pcap"
    f = open(filename, "wb", buffering=1024 * 1024)
    f.write(PCAP_GLOBAL_HEADER)

    stats["pcap_rotations"] += 1

    print(f"[*] Opened new PCAP: {filename}")
    return f, filename, len(PCAP_GLOBAL_HEADER)


def read_exact(sock, num_bytes):
    """Highly optimized exact-byte reader using memoryviews to prevent buffer copying."""
    buf = bytearray(num_bytes)
    view = memoryview(buf)
    received = 0

    while received < num_bytes:
        chunk = sock.recv_into(view[received:], num_bytes - received)

        if chunk == 0:
            return None

        received += chunk

    return bytes(buf)


def write_pcap_packet(pcap_file, wall_ts_ns, cap_len, orig_len, packet_data):
    sec = wall_ts_ns // 1_000_000_000
    usec = (wall_ts_ns % 1_000_000_000) // 1000

    pcap_hdr = struct.pack(
        "<IIII",
        int(sec),
        int(usec),
        int(cap_len),
        int(orig_len),
    )

    pcap_file.write(pcap_hdr)
    pcap_file.write(packet_data)

    return len(pcap_hdr) + len(packet_data)


def produce_kafka(packet_data, wall_ts_ns, kernel_mono_ns, orig_len, cap_len):
    headers = [
        ("wall_ts_ns", str(wall_ts_ns).encode("utf-8")),
        ("kernel_mono_ns", str(kernel_mono_ns).encode("utf-8")),
        ("orig_len", str(orig_len).encode("utf-8")),
        ("cap_len", str(cap_len).encode("utf-8")),
    ]

    try:
        producer.produce(
            topic=KAFKA_TOPIC,
            value=packet_data,
            headers=headers,
            callback=kafka_delivery_report,
        )
        producer.poll(0)
        stats["kafka_enqueued"] += 1

    except BufferError:
        # Kafka local queue is full.
        # PCAP remains the durable source of truth.
        stats["kafka_dropped_local"] += 1
        producer.poll(0.05)

    except Exception as e:
        stats["kafka_dropped_local"] += 1
        print(f"[!] Kafka produce error: {e}")


def print_stats_periodically():
    last_packets = 0
    last_bytes = 0
    last_time = time.time()

    while True:
        time.sleep(5)

        now = time.time()
        elapsed = max(now - last_time, 0.001)

        packet_delta = stats["packets"] - last_packets
        byte_delta = stats["bytes"] - last_bytes

        last_packets = stats["packets"]
        last_bytes = stats["bytes"]
        last_time = now

        mbps = (byte_delta * 8) / elapsed / 1_000_000

        print(
            "[STATS] "
            f"connections={stats['connections']} "
            f"packets={stats['packets']} "
            f"pps={packet_delta / elapsed:.0f} "
            f"mbps={mbps:.2f} "
            f"kafka_enqueued={stats['kafka_enqueued']} "
            f"kafka_local_drops={stats['kafka_dropped_local']} "
            f"kafka_delivery_errors={stats['kafka_delivery_errors']} "
            f"malformed={stats['malformed_frames']} "
            f"pcap_rotations={stats['pcap_rotations']}"
        )


def handle_client(conn, addr, pcap_state):
    pcap_file, current_file, current_size = pcap_state

    print(f"[+] Sensor stream connected from {addr}")
    stats["connections"] += 1

    try:
        while True:
            # 1. Read the strict 24-byte header
            header = read_exact(conn, FRAME_HEADER_SIZE)

            if header is None:
                print(f"[-] Sensor disconnected cleanly: {addr}")
                break

            cap_len, orig_len, wall_ts_ns, kernel_mono_ns = FRAME_HEADER_STRUCT.unpack(header)

            # Sanity check the unpacked values
            if cap_len == 0 or cap_len > SNAPLEN or orig_len < cap_len:
                stats["malformed_frames"] += 1
                print(
                    f"[!] Malformed frame from {addr}: "
                    f"cap_len={cap_len}, orig_len={orig_len}"
                )
                break

            # 2. Read strictly the exact payload size
            packet_data = read_exact(conn, cap_len)

            if packet_data is None:
                print(f"[-] Sensor disconnected mid-packet: {addr}")
                break

            # 3. PCAP Rotation Logic
            if current_size >= MAX_PCAP_SIZE:
                pcap_file.flush()
                os.fsync(pcap_file.fileno())
                pcap_file.close()
                pcap_file, current_file, current_size = get_new_pcap()

            # 4. Write out to disk and Kafka
            written = write_pcap_packet(
                pcap_file,
                wall_ts_ns,
                cap_len,
                orig_len,
                packet_data,
            )

            current_size += written

            produce_kafka(
                packet_data,
                wall_ts_ns,
                kernel_mono_ns,
                orig_len,
                cap_len,
            )

            stats["packets"] += 1
            stats["bytes"] += cap_len

    except Exception as e:
        print(f"[!] Stream error from {addr}: {e}")

    finally:
        try:
            conn.close()
        except Exception:
            pass

        try:
            pcap_file.flush()
        except Exception:
            pass

    return pcap_file, current_file, current_size


def main():
    ensure_dirs()

    pcap_state = get_new_pcap()

    threading.Thread(target=print_stats_periodically, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(5)

    print(f"[*] Vault active on {BIND_IP}:{BIND_PORT}")
    print(f"[*] PCAP directory: {PCAP_DIR}")
    print(f"[*] Kafka broker: {KAFKA_BROKER}")
    print(f"[*] Kafka topic: {KAFKA_TOPIC}")
    print("[*] Kafka is best-effort; PCAP is durable truth.")

    while True:
        conn, addr = server.accept()
        pcap_state = handle_client(conn, addr, pcap_state)


if __name__ == "__main__":
    main()