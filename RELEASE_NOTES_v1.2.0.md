# Release Notes: v1.2.0

## Summary

Version 1.2.0 is a major reliability and observability update for the network telemetry sensor. The sensor now adapts before loss whenever sustained high packet rates are detected, while the vault receiver reconstructs validated Ethernet frames into rotating PCAP files and can optionally emit Kafka events.

## Highlights

- **Proactive adaptation:** The sensor enters degraded mode after sustained high-rate intervals, before perf ring loss occurs.
- **Packet-preserving degraded mode:** Mode 2 reduces copied payload size while keeping `sample=1:1`.
- **Emergency critical mode:** Mode 3 applies adaptive sampling only for severe loss conditions.
- **Hardened TCP transport:** Keepalive, send timeout, TCP_NODELAY, reconnect handling, and Linux TCP_USER_TIMEOUT support.
- **Validated chunk protocol:** Magic, version, header length, payload bounds, sequence counters, and CRC32 checks.
- **Rotating PCAP output:** Vault writes Ethernet frames to rotating PCAP files for Wireshark/tshark workflows.
- **Optional Kafka output:** Metadata-only events by default, payload-inclusive events when explicitly enabled.

## Upgrade notes

1. Replace the existing sensor script with `sensor/pi_ebpf_streamer_v5.4.py`.
2. Replace the existing vault script with `vault/vault_router_v5.5.py`.
3. Review `VAULT_IP`, `VAULT_PORT`, `CAPTURE_INTERFACE`, and `PI_MGMT_IP` in the sensor script.
4. Start the vault before starting the sensor.
5. Validate PCAP output and inspect logs for mode changes, reconnects, sequence gaps, and CRC errors.

## Suggested tag

```bash
git tag -a v1.2.0 -m "Release v1.2.0: adaptive eBPF sensor and vault PCAP/Kafka receiver"
git push origin v1.2.0
```
