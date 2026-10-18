#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  python3 \
  python3-pip \
  python3-bpfcc \
  bpfcc-tools \
  linux-headers-$(uname -r) \
  iproute2

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-sensor.txt

echo "Sensor dependencies installed."
