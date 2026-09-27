# crc_oracle seed corpus

Total seeds: 59

Differential-fuzz seeds against the `crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000)` reference oracle. The harness computes `crc16_ccitt.crc(data)` AND `crcmod_oracle(data)` on each seed and asserts byte-exact equality.

## Seed categories

| Range | Category |
|---|---|
| 00-12 | Canonical (mirror of harness `_CANONICAL`) |
| 20-22 | Larger canonical patterns |
| 30-35 | Small edge sizes (1-9 bytes) |
| 40 | All-bytes-256 sweep |
| 50-51 | Walking-one bit pattern |
| 60-62 | High-bit-density repeats |
| 70-72 | Polynomial boundary (high/low bit, all-FF) |
| 80-81 | Reversed / shuffled |
| 90-95 | Size edges (255/256/257/511/512/513) |
| 100-104 | Common ASCII / JSON |
| 110-111 | Poly-flanked patterns |
| 120-122 | Deterministic random |
| 130-133 | Pathological tiny sizes |
| 140-144 | All-FF sizes 2/4/8/16/32 |
| 150-154 | All-00 sizes 2/4/8/16/32 |
| 160-162 | Alternating-AB/CD/EF |
