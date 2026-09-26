# Changelog

## v0.1.0 (cycle_128, 2026-09-26)

- Initial release of `crc16-ccitt` (CRC-16/CCITT-FALSE pure-Python reference).
- MSB-first implementation per ITU-T X.25 §2.2.3.4 (HDLC FCS).
- Parameter set: width=16, poly=0x1021, init=0xFFFF, refin=false, refout=false,
  xorout=0x0000. RevEng check `crc(b"123456789") == 0x29B1` verified.
- 369 pytest items across 12 categories (AC1-AC12 1:1 coverage).
- Zero runtime dependencies (`dependencies = []`).
- CLI: `crc16-ccitt-pure-compute` and `crc16-ccitt-pure-self-test`; `python3 -m crc16_ccitt`.
- Fresh-venv smoke verified; secret-scan CLEAN.
- Adversary cycle pending.
