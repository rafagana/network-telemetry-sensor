# Deployment Guide

## Recommended topology

```text
Sensor host / Raspberry Pi               Vault host
---------------------------              ---------------------------
eBPF TC capture on eth1        TCP 9999   Vault receiver
ZSTD chunk compression  ----------------> PCAP output directory
Adaptive capture modes                  Optional Kafka broker
```

## Vault deployment

Install dependencies:

```bash
bash scripts/install_vault_deps.sh
```

Create output directory:

```bash
mkdir -p ./pcap
```

Run vault:

```bash
python3 vault/vault_router_v5.5.py \
  --host 0.0.0.0 \
  --port 9999 \
  --timeout 60 \
  --rcvbuf 64M \
  --output ./pcap \
  --pcap-prefix sensor
```

## Sensor deployment

Install dependencies:

```bash
bash scripts/install_sensor_deps.sh
```

Edit the sensor configuration constants:

```python
VAULT_IP = "<vault-ip>"
VAULT_PORT = 9999
CAPTURE_INTERFACE = "<interface>"
PI_MGMT_IP = "<sensor-management-ip>"
```

Run sensor:

```bash
sudo python3 sensor/pi_ebpf_streamer_v5.4.py
```

## systemd deployment

Copy service units:

```bash
sudo cp systemd/network-telemetry-vault.service /etc/systemd/system/
sudo cp systemd/network-telemetry-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Enable vault:

```bash
sudo systemctl enable --now network-telemetry-vault.service
```

Enable sensor:

```bash
sudo systemctl enable --now network-telemetry-sensor.service
```

Check logs:

```bash
journalctl -u network-telemetry-vault.service -f
journalctl -u network-telemetry-sensor.service -f
```
