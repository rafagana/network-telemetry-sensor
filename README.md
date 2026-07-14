# network-telemetry-sensor
Real-time, observer-contamination-free network packet streaming.
Here is a highly professional, technically precise, and engaging rewrite of your `README.md` introduction.

This version speaks directly to the pain points of network security researchers and clearly positions your project as the elegant, low-cost solution they’ve been looking for.

---

# FlowVault-eBPF: High-Fidelity Distributed Network Telemetry for ML Research

Most machine learning-driven Intrusion Detection Systems (IDS) are trained on synthetic, low-resolution, or out-of-context datasets. Generating high-quality, real-time network data for AI research has traditionally been blocked by three systemic hurdles:

1. **The Physical TAP Bottleneck:** High-fidelity data collection usually relies on expensive physical network TAPs, which are cost-prohibitive and highly restrictive to deploy across distributed edge or enterprise environments.
2. **The Batch-Processing Lag:** Traditional PCAP capture tools are designed for offline forensic analysis. They lack the real-time streaming capabilities required to feed active, online machine learning inference engines.
3. **The Data Resolution Crisis:** Traditional user-space interface-based packet capture (like standard `libpcap`) suffers from packet drops under load and poor timestamp resolution, leading to degraded feature quality for ML models.

**FlowVault-eBPF** breaks these barriers. It is a lightweight, production-grade, distributed data engineering pipeline designed to capture, structure, and stream raw network telemetry with zero-copy efficiency.

---

## 🚀 The Architecture

By combining the power of Linux **eBPF (Extended Berkeley Packet Filter)** at the kernel layer with low-cost edge hardware, this pipeline achieves enterprise-grade data fidelity without the enterprise price tag.

* **Low-Cost, High-Fidelity Edge Capture:** Deployed on a budget-friendly **Raspberry Pi 4** connected to a centralized switch's **SPAN/Port Mirror**. This positioning guarantees complete visibility, capturing 100% of both **North/South** (perimeter) and **East/West** (lateral) network traffic.
* **Kernel-Level eBPF TC Tap:** Captures packets directly at the Traffic Control (TC) ingress layer using an eBPF program. This bypasses the heavy overhead of the user-space network stack, recording raw frames with nanosecond-precision kernel timestamps (`bpf_ktime_get_ns()`).
* **Real-Time & Durable Dual-Path Pipeline:** * **The Real-Time Path (Kafka):** Raw packet data and metadata headers are streamed instantly to an Apache Kafka bus for real-time ML model consumption and inference.
* **The Ground-Truth Path (PCAP):** Concurrently, the pipeline writes microsecond-accurate, rotated PCAP files directly to local storage as an immutable, durable source of truth for offline training and validation.

---

## 🛠️ Key Features

* **Data Leakage & Contamination Prevention:** Built-in kernel-level filters dynamically drop the monitoring Pi's own management and telemetry traffic. This ensures your ML models are trained exclusively on clean network traffic, completely eliminating **Observer Contamination**.
* **Zero-Copy Memory Management:** The streaming agent leverages Python `memoryview` buffers to prevent expensive CPU-bound data copying when handling raw network frames.
* **Resilient TCP Streaming:** Features auto-reconnecting socket-based streaming from the edge sensor to the central storage vault, guaranteeing packet delivery even during temporary network interruptions.

---

## 📁 Repository Structure

```text
flowvault-ebpf/
├── LICENSE                 # Apache 2.0 License
├── NOTICE                  # Attribution notice
├── docker-compose.yml      # Local Kafka & Zookeeper environment for quick deployment
├── requirements.txt        # Global Python dependencies
│
├── sensor-pi/              # Deployment directory for the Raspberry Pi 4 capture node
│   └── pi_ebpf_streamer.py # eBPF TC engine and socket streamer
│
└── router-t140/            # Deployment directory for the centralized collection node
    └── vault_router.py     # High-throughput PCAP writer and Kafka producer

```

---

## ⚡ Quickstart

### 1. Spin up the centralized infrastructure

On your central server (e.g., your T160 vault), start your Kafka broker:

```bash
docker-compose up -d

```

### 2. Launch the Central Vault Receiver

Start the vault router to listen for incoming sensor streams, write PCAPs, and produce to Kafka:

```bash
python3 router-t140/vault_router.py

```

### 3. Deploy the eBPF Streamer on the Raspberry Pi 4

With your Pi hooked up to your switch's SPAN port, run the kernel tap (requires root privileges to load the eBPF program into the kernel):

```bash
sudo python3 sensor-pi/pi_ebpf_streamer.py

```
