# Operations Guide

## Startup order

Start the vault before the sensor. The sensor waits for TCP connectivity before attaching capture, which prevents immediate queue buildup during startup.

## Routine checks

On the vault:

```bash
ls -lh ./pcap
journalctl -u network-telemetry-vault.service -n 100
```

On the sensor:

```bash
journalctl -u network-telemetry-sensor.service -n 100
```

## Important telemetry counters

- `events_enqueued`: packets accepted from perf callbacks.
- `events_sent`: packets sent to the vault.
- `perf_lost`: packets dropped by the BPF perf ring.
- `raw_queue_drops`: chunks dropped before compression.
- `compress_queue_drops`: chunks dropped before TCP egress.
- `egress_chunk_drops`: compressed chunks abandoned or dropped in egress path.
- `send_timeouts`: TCP send operations that timed out.
- `socket_reconnects`: sensor reconnect attempts that succeeded.
- `mode_changes`: adaptive mode transitions.

## PCAP rotation

Vault flags:

```bash
--pcap-rotate-mb 1024
--pcap-rotate-sec 300
--pcap-flush-packets 4096
```

Set `--pcap-rotate-mb 0` to disable size-based rotation. Set `--pcap-rotate-sec 0` to disable time-based rotation.

## Frame archive

Enable frame archive when you need exact binary records with sensor metadata:

```bash
python3 vault/vault_router_v5.5.py \
  --output ./pcap \
  --enable-frame-archive \
  --frame-rotate-mb 100
```
