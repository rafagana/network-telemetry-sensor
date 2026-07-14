# FlowVault-eBPF - network-telemetry-sensor

---

# FlowVault-eBPF: High-Fidelity Distributed Network Telemetry for AI Research

Many AI-driven Intrusion Detection Systems (IDS) fail in real-world deployments because they are trained on low-resolution, synthetic, or out-of-context datasets. Obtaining clean, real-time, high-fidelity packet telemetry has historically been blocked by three major roadblocks:

1. **The Physical TAP Bottleneck:** High-fidelity data collection traditionally relies on expensive, physical hardware TAPs. This is cost-prohibitive and highly restrictive to deploy across distributed edge, IoT, or enterprise environments.
2. **The Batch-Processing Lag:** Traditional PCAP capture tools are designed for offline, forensic analysis. They lack the real-time streaming interfaces required to feed active, online AI inference engines.
3. **The Data Resolution Crisis:** Standard user-space interface-based packet capture (such as raw `libpcap`) suffers from severe packet drops under high throughput and poor timestamp resolution, leading to degraded feature quality for AI models.

**FlowVault-eBPF** is a lightweight, production-grade, distributed data engineering pipeline that resolves these issues. By leveraging kernel-space **eBPF (Extended Berkeley Packet Filter)** at the Traffic Control (TC) layer and low-cost hardware, it captures, structures, and streams raw network telemetry with zero-copy efficiency.

---

## 🚀 Architectural Overview

```
                                              [ SWITCH SPAN / PORT MIRROR ]
                                                            │
                                             (Inbound & Outbound Traffic)
                                                            │
                                                            ▼
                                             ┌─────────────────────────────┐
                                             │  Raspberry Pi 4 Edge Node   │
                                             │                             │
                                             │   Kernel Space (eBPF)       │
                                             │   ┌─────────────────────┐   │
  [ Edge Management / SSH ] ─────────────────┼───►  IP Filter Hook     │   │  <-- Dynamically discards Pi's
  (Observer Contamination Dropped)           │   └──────────┬──────────┘   │      own control telemetry!
                                             │              │              │
                                             │              ▼ (Raw Frames) │
                                             │   ┌─────────────────────┐   │
                                             │   │ skb_events Ringbuf  │   │  <-- Nanosecond monotonic timestamps
                                             │   └──────────┬──────────┘   │
                                             │              │              │
                                             │   User Space │ (ctypes)     │
                                             │   ┌──────────▼──────────┐   │
                                             │   │   socket_streamer   │   │  <-- Double-buffered network sender
                                             │   └──────────┬──────────┘   │
                                             └──────────────┼──────────────┘
                                                            │  TCP Stream (Port 9999)
                                                            ▼
                                             ┌─────────────────────────────┐
                                             │  Centralized Vault (T160)   │
                                             │                             │
                                             │   ┌─────────────────────┐   │
                                             │   │    vault_router     │   │  <-- Zero-copy memoryview socket reader
                                             │   └──────┬──────────┬───┘   │
                                             │          │          │       │
                                             └──────────┼──────────┼───────┘
                        (Parallel Storage Paths)        │          │
                                   ┌────────────────────┘          └────────────────────┐
                                   ▼                                                    ▼
                       ┌──────────────────────┐                             ┌──────────────────────┐
                       │  Durable PCAP Files  │                             │  Real-Time Kafka Bus │
                       │  - Rotate at 100MB   │                             │  - Custom Headers    │
                       │  - Microsecond Epoch │                             │  - Low Latency       │
                       └──────────────────────┘                             └──────────────────────┘
                         [ AI Training/Truth ]                                [ AI Live Inference ]

```

### 1. Low-Cost, Complete Visibility

The capture node is designed to run on a budget-friendly **Raspberry Pi 4** connected directly to a centralized switch's **SPAN/Port Mirror**. This hardware positioning guarantees complete, uncompromised visibility, capturing 100% of both **North/South** (perimeter) and **East/West** (lateral) network traffic passing through the switch.

### 2. Zero-Copy Kernel-Space Capture

Instead of pulling packets into user-space via standard sockets (which incurs multiple memory copies and CPU context switches), FlowVault-eBPF loads a specialized Traffic Control (TC) program (`physical_tc_tap`) directly into the Linux kernel network pipeline. It extracts the raw Ethernet frame up to a defined MTU (`SNAPLEN = 1522` to accommodate 802.1Q tags) and forwards it directly to a ring buffer with nanosecond precision.

### 3. QinQ & VLAN Resolution

The eBPF kernel program implements a robust Ethernet protocol parser. It handles nested VLAN configurations (double-tagging / QinQ) up to two layers deep, ensuring that inner IPv4 headers are successfully parsed even in heavily segmented enterprise environments.

### 4. Dual-Path Storage Engine

Once the centralized **Vault** receive thread processes the streams, it forks the data into two paths:

* **The Ground-Truth Path (PCAP):** Writes microsecond-accurate, binary-compliant PCAP files directly to local storage, automatically rotating files when they reach `MAX_PCAP_SIZE` (100MB). This serves as the immutable dataset for offline AI model training and validation.
* **The Real-Time Path (Kafka):** Concurrently publishes raw packet payloads directly to an Apache Kafka broker. Key telemetry metadata (such as nanosecond epoch timestamps, original packet lengths, and capture lengths) is injected directly into **Kafka Message Headers**, allowing real-time downstream AI inference engines to process packet meta without having to parse the raw byte payload.

---

## 🛡️ Dataset Integrity & Observer Contamination Prevention

In AI research, **Observer Contamination** is a silent killer. If your monitoring sensor streams its own capture telemetry or SSH management traffic over the same network interface it is monitoring, your AI models will inevitably train on the sensor's own activity. This leads to artificial model bias and false performance metrics.

FlowVault-eBPF solves this at the **kernel level**. The streamer program dynamically extracts the system’s IP address (`PI_MGMT_IP`) and compiles a hardware-native 32-bit big-endian C literal representing that IP (`PI_MGMT_IP_C_LITERAL`):

```c
if (ip->saddr == bpf_htonl(0xC0A80A1FU) || ip->daddr == bpf_htonl(0xC0A80A1FU)) {
    return TC_ACT_OK;
}

```

*(Example literal generated dynamically from `192.168.10.31`)*

If the incoming packet's source or destination IP matches this management signature, the eBPF filter skips submitting it to the user-space ring buffer, completely dropping it from the telemetry output.

---

## ⚙️ Pre-Flight Configuration

Before executing the pipeline, you **must** adjust several environment-specific variables located at the top of the scripts:

### 1. Configure the Central Vault Receiver (`router-t140/vault_router.py`)

Ensure these parameters match your target storage layout and local network:

* `BIND_IP = "0.0.0.0"` — IP address to bind the listening socket to.
* `BIND_PORT = 9999` — TCP port to accept incoming stream traffic.
* `PCAP_DIR = "/your/custom/storage/path/pcap"` — Directory where rotated PCAP files will be written.
* `KAFKA_BROKER = "127.0.0.1:9092"` — Address of your active Apache Kafka broker.
* `MAX_PCAP_SIZE = 100 * 1024 * 1024` — PCAP rollover threshold (default: 100MB).

### 2. Configure the Edge Sensor (`sensor-pi/pi_ebpf_streamer.py`)

Modify these variables to establish link connectivity and preserve data integrity:

* `VAULT_IP = "192.168.10.137"` — The IP address of your centralized Vault server.
* `CAPTURE_INTERFACE = "eth1"` — The physical interface connected to the switch's SPAN/mirror port (e.g., `eth1`).
* `PI_MGMT_IP = "192.168.10.31"` — The IP address used by the Pi for control and SSH. This is used for kernel-level filtering.
* `PERF_PAGE_CNT = 8192` — Ring buffer size in memory pages. Increase this if you experience packet drops from the kernel ring buffer during burst traffic.

---

## 📁 Protocol Framing Format

Between the edge sensor and the centralized vault receiver, data is transmitted over raw TCP sockets. To minimize transmission overhead, a custom **24-byte binary frame header** is prepended to every packet payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Capture Length (uint32)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Original Length (uint32)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Wall-Clock Epoch (uint64)                  +
|                          (Nanoseconds)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Kernel Monotonic (uint64)                  +
|                          (Nanoseconds)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        Raw Frame Bytes                        |
|                     (Size = Capture Length)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

*(Structured mapping: `FRAME_HEADER_STRUCT = struct.Struct(">IIQQ")`)*

---

## ⚡ Quickstart

### Step 1: Install System Dependencies

On the **Edge Sensor Node** (Raspberry Pi 4), install the required kernel libraries and eBPF dependencies:

```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc python3-pyroute2

```

On the **Centralized Vault Node** (Server), install the Python Kafka client:

```bash
pip install confluent-kafka

```

### Step 2: Spin Up the Kafka Broker

On your central server, run the provided Docker Compose environment:

```bash
docker-compose up -d

```

This launches a local Zookeeper container alongside a Confluent-Kafka container configured to bind directly to the host's networking stack on port `9092`.

### Step 3: Start the Central Vault Receiver

Initialize the vault receiver on your central server. It will start listening on port `9999` and pre-allocate the PCAP storage space:

```bash
python3 vault_router.py

```

### Step 4: Run the eBPF Streamer on the Edge Sensor

Once the central vault is listening, execute the streamer on your Raspberry Pi 4. Because this loader interacts directly with the Linux kernel's TC subsystem, it **must** be executed with root privileges:

```bash
sudo python3 pi_ebpf_streamer.py

```

The streamer will automatically hook into your defined `CAPTURE_INTERFACE`, establish a connection to your Vault node, filter out management traffic, and start streaming raw packet frames.

---

## 📄 License & Attribution

This project is licensed under the **Apache License 2.0**. For complete legal rights, permissions, and conditions, refer to the `LICENSE` and `NOTICE` files included in the root of this repository.
