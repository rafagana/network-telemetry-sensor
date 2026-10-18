# Network Telemetry Sensor

A production-candidate network telemetry sensor for full-fidelity packet capture on Raspberry Pi/Linux nodes using eBPF TC hooks, adaptive capture control, Zstandard-compressed transport, and a vault-side receiver that reconstructs packets into rotating PCAP files with optional Kafka event streaming.

## Release status

Current repository update: **v1.2.0**

This release packages:

- `sensor/pi_ebpf_streamer_v5.4.py`: Raspberry Pi/Linux eBPF packet streamer.
- `vault/vault_router_v5.5.py`: TCP vault receiver, PCAP writer, frame archive writer, and optional Kafka publisher.
- Documentation for architecture, deployment, protocol, Kafka, operations, troubleshooting, and performance.
- Example systemd units and install scripts.

## What is new in v1.2.0

### Sensor

- Maintains protocol version `3` with a packed 62-byte chunk header.
- Uses CRC32-protected Zstandard-compressed chunks.
- Adds proactive adaptive capture before packet loss occurs.
- Introduces a three-mode capture ladder:
  - **Mode 1, normal:** full fidelity, `snaplen=1522`, `sample=1:1`.
  - **Mode 2, degraded:** payload truncation, all packets preserved, `snaplen=512`, `sample=1:1`.
  - **Mode 3, critical:** emergency sampling, `snaplen=128`, adaptive `sample=1:10` to `1:100`.
- Starts capture after the vault connection is established to avoid startup queue overflow.
- Tracks perf loss, raw queue pressure, compression queue pressure, transport backpressure, send errors, send timeouts, and reconnects.
- Uses TCP keepalive, TCP_NODELAY, send timeouts, and Linux TCP_USER_TIMEOUT when available.

### Vault

- Receives compressed chunk streams from the sensor over TCP.
- Validates chunk magic, protocol version, header length, payload sizes, sequence continuity, and CRC32.
- Decompresses chunks and reconstructs original Ethernet frames.
- Writes rotating PCAP files with Ethernet link type.
- Optionally writes binary frame archives preserving sequence, direction, and timestamps.
- Optionally publishes metadata or payload-inclusive JSON events to Kafka.

## Repository layout

```text
network-telemetry-sensor/
├── README.md
├── CHANGELOG.md
├── RELEASE_NOTES_v1.2.0.md
├── requirements-sensor.txt
├── requirements-vault.txt
├── sensor/
│   └── pi_ebpf_streamer_v5.4.py
├── vault/
│   └── vault_router_v5.5.py
├── docs/
│   ├── architecture.md
│   ├── deployment.md
│   ├── protocol.md
│   ├── kafka.md
│   ├── operations.md
│   ├── performance.md
│   └── troubleshooting.md
├── systemd/
│   ├── network-telemetry-sensor.service
│   └── network-telemetry-vault.service
├── scripts/
│   ├── install_sensor_deps.sh
│   ├── install_vault_deps.sh
│   └── run_vault_example.sh
└── examples/
    └── kafka_event.json
```

## High-level architecture

```text
+----------------------+       TCP/ZSTD/CRC32 chunks       +----------------------+
| Raspberry Pi Sensor  |  --------------------------------> | Vault Receiver       |
|                      |                                    |                      |
| eBPF TC ingress/egress                                   | Decompress + validate|
| Perf ring buffers    |                                    | Sequence checks      |
| Adaptive modes       |                                    | Rotating PCAP        |
| ZSTD compression     |                                    | Optional Kafka       |
+----------------------+                                    +----------------------+
```

The sensor attaches TC/eBPF hooks to the capture interface, collects ingress and egress Ethernet frames, batches them, compresses chunks with Zstandard, and sends them to the vault. The vault validates the protocol header and CRC32, decompresses the chunk, rebuilds Ethernet frames, writes PCAP files, and optionally publishes JSON packet events to Kafka.

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/rafagana/network-telemetry-sensor.git
cd network-telemetry-sensor
```

### 2. Install vault dependencies

On the vault host:

```bash
bash scripts/install_vault_deps.sh
```

Optional Kafka support:

```bash
python3 -m pip install confluent-kafka kafka-python
```

### 3. Run the vault receiver

```bash
python3 vault/vault_router_v5.5.py \
  --host 0.0.0.0 \
  --port 9999 \
  --timeout 60 \
  --rcvbuf 64M \
  --output ./pcap \
  --pcap-prefix sensor
```

With Kafka metadata events:

```bash
python3 vault/vault_router_v5.5.py \
  --host 0.0.0.0 \
  --port 9999 \
  --output ./pcap \
  --kafka-bootstrap 127.0.0.1:9092 \
  --kafka-topic ebpf-packets
```

With payload included as base64:

```bash
python3 vault/vault_router_v5.5.py \
  --host 0.0.0.0 \
  --port 9999 \
  --output ./pcap \
  --kafka-bootstrap 127.0.0.1:9092 \
  --kafka-topic ebpf-packets \
  --kafka-payload-base64
```

### 4. Configure the sensor

Edit these constants in `sensor/pi_ebpf_streamer_v5.4.py`:

```python
VAULT_IP = "192.168.10.137"
VAULT_PORT = 9999
CAPTURE_INTERFACE = "eth1"
PI_MGMT_IP = "192.168.10.31"
```

### 5. Install sensor dependencies

On the Raspberry Pi or Linux sensor host:

```bash
bash scripts/install_sensor_deps.sh
```

### 6. Run the sensor

```bash
sudo python3 sensor/pi_ebpf_streamer_v5.4.py
```

## Documentation

- [Architecture](docs/architecture.md)
- [Deployment](docs/deployment.md)
- [Protocol](docs/protocol.md)
- [Kafka Integration](docs/kafka.md)
- [Operations](docs/operations.md)
- [Performance](docs/performance.md)
- [Troubleshooting](docs/troubleshooting.md)

## Safety and privacy note

This tool captures real network packets. Only run it on networks and interfaces where you have authorization to monitor traffic. PCAP files and Kafka payload events can contain sensitive information.
