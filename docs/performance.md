# Performance Notes

## Design goals

The v1.2.0 sensor prioritizes research preservation under high packet rates. It first reduces per-packet copy cost and payload size before applying sampling.

## Adaptation strategy

1. **Normal mode:** Full-fidelity capture.
2. **Degraded mode:** Triggered proactively by sustained high packet rate or early perf loss. It keeps sampling at `1:1` but reduces snaplen to `512`.
3. **Critical mode:** Triggered by severe perf loss or persistent overload. It reduces snaplen to `128` and applies emergency sampling.

## Why degraded mode is packet-preserving

Reducing snaplen reduces memory copy cost, queue pressure, compression cost, and TCP egress load. Keeping sampling at `1:1` preserves every packet that can be drained from the perf ring, which is useful for research datasets where packet presence matters even when payload is truncated.

## Key tuning variables

Sensor constants:

```python
PERF_PAGE_CNT = 16384
CHUNK_QUEUE_MAXSIZE = 512
COMPRESS_QUEUE_MAXSIZE = 128
BATCH_BYTES = 1024 * 1024
BATCH_MAX_PACKETS = 2048
BATCH_TIMEOUT_MS = 50
TELEMETRY_INTERVAL_SEC = 3
BURST_RATE_THRESHOLD = 50000
HIGH_RATE_INTERVALS_TO_DEGRADE = 3
HIGH_RATE_INTERVALS_TO_CRITICAL = 10
```

Vault flags:

```bash
--rcvbuf 64M
--max-compressed 16M
--max-uncompressed 64M
--pcap-flush-packets 4096
```

## Practical advice

- Increase `--rcvbuf` on the vault for high-throughput links.
- Keep Kafka payload publishing disabled unless needed.
- Pin the sensor to a quiet interface and avoid capturing management traffic when possible.
- Store PCAP output on fast local disk or a high-throughput dedicated volume.
- Monitor mode changes and perf loss during load testing.
