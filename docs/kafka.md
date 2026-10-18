# Kafka Integration

Kafka publishing is optional. PCAP writing works even if Kafka libraries are not installed.

## Enable Kafka metadata events

```bash
python3 vault/vault_router_v5.5.py \
  --output ./pcap \
  --kafka-bootstrap 127.0.0.1:9092 \
  --kafka-topic ebpf-packets
```

## Include payloads as base64

Use this only when downstream consumers require packet payloads. It increases bandwidth, storage, and privacy exposure.

```bash
python3 vault/vault_router_v5.5.py \
  --output ./pcap \
  --kafka-bootstrap 127.0.0.1:9092 \
  --kafka-topic ebpf-packets \
  --kafka-payload-base64
```

## Producer backends

The vault tries Kafka clients in this order:

1. `confluent_kafka`
2. `kafka-python`

If neither is available, Kafka is disabled and PCAP output continues.

## Example event

See `examples/kafka_event.json`.
