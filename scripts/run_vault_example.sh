#!/usr/bin/env bash
set -euo pipefail

mkdir -p ./pcap
python3 vault/vault_router_v5.5.py \
  --host 0.0.0.0 \
  --port 9999 \
  --timeout 60 \
  --rcvbuf 64M \
  --output ./pcap \
  --pcap-prefix sensor
