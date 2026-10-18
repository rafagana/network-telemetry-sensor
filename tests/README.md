# Tests

Recommended validation before release:

```bash
python3 -m py_compile sensor/pi_ebpf_streamer_v5.4.py vault/vault_router_v5.5.py
python3 vault/vault_router_v5.5.py --help
```

The sensor requires root privileges and Linux eBPF/BCC support, so full runtime validation must be performed on the target sensor host.
