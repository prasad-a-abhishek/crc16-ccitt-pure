# crc_main seed corpus

Total seeds: 50

Deterministic boundary + canonical + stress inputs for the algorithm-correctness surface (Surface 1 from card 01 SURFACES.md). Each seed is stored as a separate file under `corpus/` with a stable name so re-runs are reproducible.

## Seed categories

| Range | Category | Notes |
|---|---|---|
| 00-05 | Boundary | empty, 1-byte, 2-byte pairs |
| 10-11 | Canonical | RevEng check vector + 10-byte sweep |
| 20-23 | 256-byte patterns | zeros, FFs, alternating, walking-one |
| 30-33 | 1KB-4KB patterns | scaling check |
| 40-42 | 64KB patterns | high-water scaling |
| 50-52 | Bytes-subclass | memoryview/bytearray via `.tobytes()` |
| 60-62 | High-bit-density | repeated AB / CD / EF |
| 70-72 | Deterministic random | fixed byte sequences |
| 80-84 | Transition points | sizes near powers of two |
| 90-92 | Single-byte repeats | 64, 256, 4096 |
| 100-101 | Ascending/descending | full byte-range sweeps |
| 110-111 | All-bytes | each value once / twice |
| 120-122 | MSB-polynomial | top-bit / bottom-bit / all-set |
| 130-132 | FFs | 8/16/32 byte runs |
| 140-142 | Zero-flanked | edge of init-FF behavior |
