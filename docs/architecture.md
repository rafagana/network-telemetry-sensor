# Architecture

## Components

### Sensor

The sensor is a Python/BCC application that attaches eBPF TC hooks to a Linux network interface. It captures ingress and egress Ethernet frames, adds per-frame metadata, batches frames into chunks, compresses each chunk with Zstandard, and sends the chunks over TCP to the vault receiver.

Core responsibilities:

- Attach TC ingress and egress hooks to the configured capture interface.
- Exclude management traffic from the Pi management IP when configured.
- Read packet events from BPF perf buffers.
- Batch frames per CPU into chunk payloads.
- Apply proactive adaptive capture modes.
- Compress chunks and transmit them to the vault.
- Track telemetry for packet rates, queue pressure, perf loss, transport errors, reconnects, and mode changes.

### Vault

The vault is a TCP server that accepts compressed chunk streams from one or more sensors. It validates the protocol header and CRC32, decompresses the payload, reconstructs Ethernet frames, writes PCAP records, optionally stores binary frame archives, and optionally publishes Kafka events.

Core responsibilities:

- Accept sensor TCP connections.
- Validate chunk protocol fields.
- Detect sequence gaps.
- Decompress payloads with Zstandard.
- Reconstruct Ethernet frames from frame records.
- Write rotating PCAP files.
- Publish Kafka JSON events when configured.

## Data path

```text
Network interface
  -> TC ingress/egress eBPF hook
  -> BPF perf output
  -> Python packet callback
  -> Per-CPU chunk builder
  -> Raw chunk queue
  -> ZSTD compression worker
  -> Compressed queue
  -> TCP sender
  -> Vault TCP receiver
  -> Header + CRC validation
  -> ZSTD decompression
  -> Frame parser
  -> PCAP writer / frame archive / Kafka
```

## Adaptive capture ladder

| Mode | Name | Snaplen | Sampling | Purpose |
|---|---:|---:|---:|---|
| 1 | Normal | 1522 | 1:1 | Full-fidelity capture |
| 2 | Degraded | 512 | 1:1 | Reduce per-packet overhead while preserving packet count |
| 3 | Critical | 128 | 1:10 to 1:100 | Emergency loss control |

The design intentionally avoids jumping directly from critical to normal. It recovers gradually to prevent oscillation during unstable traffic conditions.

## Persistence options

- **PCAP:** Standard packet capture output suitable for Wireshark, tshark, Zeek ingest, and offline research.
- **Frame archive:** Binary archive preserving additional sensor metadata such as sequence, direction, and timestamps.
- **Kafka:** Real-time JSON event stream for analytics pipelines.
