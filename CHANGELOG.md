# Changelog

## v1.2.0

### Added

- Added `sensor/pi_ebpf_streamer_v5.4.py` with proactive adaptive eBPF packet capture.
- Added `vault/vault_router_v5.5.py` with PCAP output, optional Kafka publishing, and frame archive support.
- Added docs for architecture, deployment, protocol, operations, Kafka, performance, and troubleshooting.
- Added example systemd units for sensor and vault.
- Added installation scripts for sensor and vault dependencies.

### Changed

- The sensor now degrades capture proactively after sustained high-rate intervals rather than waiting for packet loss.
- Degraded mode preserves all packets that drain from the perf ring by reducing snaplen instead of sampling.
- Critical mode uses adaptive emergency sampling only when loss is severe.
- Capture starts after successful vault connection to reduce startup queue pressure.
- Vault-side persistence now restores rotating PCAP output and optional binary frame archive output.

### Compatibility

- Wire protocol version remains `3`.
- Chunk header format remains `>IHHQQQIBHHBQQI`.
- Frame payload format remains `>QIIIQQ + Ethernet frame bytes`.
