# Wire Protocol

## Overview

The sensor sends a stream of compressed chunks over TCP. Each chunk contains:

1. A fixed-size packed chunk header.
2. A Zstandard-compressed payload.
3. A CRC32 value in the header covering the compressed payload.

The vault reads the header, validates size and protocol fields, reads the compressed payload, verifies CRC32, decompresses the payload, and parses frame records.

## Chunk header

Protocol version: `3`

Magic: `0x43484E4B`, ASCII `CHNK`

Python struct format:

```python
CHUNK_HEADER_STRUCT = struct.Struct(">IHHQQQIBHHBQQI")
```

Total size: `62` bytes

## Frame payload

Each decompressed chunk contains one or more frame records.

Python struct format:

```python
FRAME_HEADER_STRUCT = struct.Struct(">QIIIQQ")
```

Frame record layout:

```text
seq, cap_len, orig_len, direction, wall_ts_ns, kernel_ts_ns, ethernet_frame_bytes
```

## Direction values

```text
0 = ingress
1 = egress
```

## Capture mode values

```text
1 = normal
2 = degraded
3 = critical
```

## Validation performed by the vault

The vault validates:

- Chunk magic.
- Protocol version.
- Header size.
- Compressed and uncompressed size limits.
- CRC32 of compressed payload.
- Sequence continuity.
- Frame boundaries inside the decompressed payload.

## Compatibility notes

The current sensor and vault pair maintain protocol version `3`. The vault code also declares older v5.1/v5.2 header layouts for compatibility and diagnostics, but the active sensor sends the v5.3 packed header.
