#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y python3 python3-pip

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-vault.txt || true
python3 -m pip install zstandard

echo "Vault dependencies installed. Kafka libraries are optional."
