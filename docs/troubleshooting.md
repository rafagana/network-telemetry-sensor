# Troubleshooting

## Sensor exits with root error

The sensor requires root privileges because it attaches TC/eBPF hooks.

```bash
sudo python3 sensor/pi_ebpf_streamer_v5.4.py
```

## Interface not found

Check the configured interface:

```bash
ip link show
```

Update:

```python
CAPTURE_INTERFACE = "eth1"
```

## Vault connection fails

Verify the vault is listening:

```bash
ss -ltnp | grep 9999
```

Check firewall rules and confirm `VAULT_IP` and `VAULT_PORT` in the sensor.

## No PCAP files appear

- Confirm the sensor is connected.
- Confirm traffic is present on the capture interface.
- Confirm the vault output directory exists and is writable.
- Run the vault with `--debug`.

## CRC errors

CRC errors usually indicate corrupted, truncated, or misaligned chunk reads. Check:

- TCP connection stability.
- Sensor and vault protocol compatibility.
- Vault `--max-compressed` and `--max-uncompressed` limits.

## Frequent critical mode

Possible causes:

- Traffic exceeds sensor CPU capacity.
- Perf ring buffer pressure.
- Compression bottleneck.
- Vault receiver or disk too slow.
- Kafka payload publishing is enabled and too heavy.

Recommended actions:

- Increase vault receive buffer with `--rcvbuf 64M` or higher.
- Use faster storage for PCAP output.
- Keep Kafka payload publishing disabled.
- Increase sensor perf page count if memory allows.
- Lower snaplen thresholds for your research workload.
