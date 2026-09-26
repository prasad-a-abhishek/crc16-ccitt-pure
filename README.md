# crc16-ccitt

[![PyPI](https://img.shields.io/badge/PyPI-crc16--ccitt--pure-blue)](https://github.com/prasad-a-abhishek/crc16-ccitt-pure)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-369%20passing-brightgreen)](tests/test_crc16_ccitt.py)

> **A zero-dependency, byte-exact, RevEng-checked reference implementation of CRC-16/CCITT-FALSE — the ITU-T X.25 HDLC Frame Checking Sequence.**

## Quick Start

```bash
pip install git+https://github.com/prasad-a-abhishek/crc16-ccitt-pure.git
```

```python
>>> from crc16_ccitt import crc
>>> crc(b"123456789")              # RevEng check value
10673
>>> hex(crc(b"123456789"))
'0x29b1'
>>> crc(b"")                       # empty stream -> init value (0xFFFF)
65535
```

That's it. No C extension, no compile, no `crcmod`, no `numpy`. Just stdlib.

## ⚡ Performance & Benchmarks

> Trade-off up front: **crcmod (C-extension) is ~10-7000× faster than our pure-Python reference loop on every workload.** That is by design — we optimize for correctness, auditability, and zero install footprint, not raw throughput. See "Why crc16-ccitt?" below.

| workload     | size_bytes | ours mean ms | ours p95 ms | crcmod mean ms | crcmod p95 ms |
|--------------|-----------:|-------------:|------------:|---------------:|--------------:|
| empty        |          0 |       0.0058 |      0.0059 |         0.0005 |        0.0007 |
| 16B_ascii    |         16 |       0.2984 |      0.2995 |         0.0005 |        0.0007 |
| 256B_zeros   |        256 |       4.2553 |      4.3348 |         0.0010 |        0.0009 |
| 1KB_random   |       1024 |      16.3916 |     16.3922 |         0.0035 |        0.0040 |
| 16KB_zeros   |      16384 |     255.8495 |    257.7847 |         0.0391 |        0.0410 |
| 64KB_zeros   |      65536 |    1027.8352 |   1030.4885 |         0.1610 |        0.1631 |
| 256KB_random |     262144 |    4293.7393 |   4311.3557 |         0.5988 |        0.5970 |

Full table with peak-memory and per-iteration stats: see [`benchmarks/BENCHMARK.md`](benchmarks/BENCHMARK.md).

Reproduce locally (auto-bootstraps crcmod in an isolated venv per Invariant 22):

```bash
git clone https://github.com/prasad-a-abhishek/crc16-ccitt-pure.git
cd crc16-ccitt-pure
pip install crcmod
python3 benchmarks/run_benchmark.py
```

## Why crc16-ccitt?

**The problem.** You need CRC-16/CCITT-FALSE for an HDLC/AX.25/Bluetooth-paging
parser, but the deployment target is a slim container, an Alpine image, a
read-only filesystem, or a PyPy interpreter where `crcmod`'s C-extension won't
build or isn't allowed. You copy a 6-line StackOverflow snippet that uses
polynomial `0x1021` and *looks* right — except the snippet uses init `0x0000`
(the XMODEM variant) when you actually need `0xFFFF` (the CCITT-FALSE variant
specified by ITU-T X.25 §2.2.3.4). For ASCII `"123456789"` the two variants
disagree: XMODEM yields `0x31C3`, CCITT-FALSE yields `0x29B1`. Your unit test
passes against a hard-coded wrong value, the parser silently corrupts every
real frame, and field reports trickle in as "intermittent frame drops."

**What breaks.** An init-value mismatch produces wrong-but-plausible CRCs that
pass unit tests against a *partial* oracle but fail against any
standards-compliant HDLC peer. For Bluetooth-paging and HDLC control frames
the bit-error is silent — the peer either drops the bad frame (no NACK) or
misinterprets it as a different opcode.

**Our trade-off.** We give up raw throughput in exchange for:

- **Zero install footprint** — `pip install` (or `pip install -e .`) with
  `dependencies = []`. No `gcc`, no `cc`, no platform wheel.
- **Parameter transparency** — `poly = 0x1021`, `init = 0xFFFF`, no
  reflection, `xorout = 0x0000` are right there in `src/crc16_ccitt/__init__.py`
  as module-level constants. Greppable, lintable, SLSA-auditable.
- **Single-purpose clarity** — 25 LOC of MSB-first shift loop, every parameter
  named, no hidden table lookups, no runtime parameter strings to misquote.
- **RevEng-grade test suite** — 369 pytest items attached to the commit,
  every test vector traces to a single RevEng parameter row.

If you need speed, use `crcmod`. If you need a byte-exact, install-anywhere,
auditable reference for regulated/embedded code, use `crc16-ccitt`.

## Key Features & Complete API / CLI Reference

**Public API:**

```python
from crc16_ccitt import crc

# Single-shot CRC of a bytes-like object
crc(b"hello")                    # -> int in [0, 0xFFFF]
crc(bytearray(b"hello"))         # bytes-like equivalence
crc(memoryview(b"hello"))        # bytes-like equivalence

# Override init/xorout for multi-block stream chaining
crc(b"block1", init=0xFFFF)      # default init
crc(b"block2", init=crc(b"block1"))  # chained

# xorout is parameterized for the related CCITT (0xFFFF) variant
crc(b"123456789", xorout=0xFFFF)  # yields 0xD64E, the CCITT-TRUE check
```

**Type-error safety (AC12):**

```python
crc(None)        # -> TypeError: crc() expected bytes-like, got NoneType
crc("hello")     # -> TypeError: crc() expected bytes-like, got str
crc(123)         # -> TypeError: crc() expected bytes-like, got int
crc([1, 2, 3])   # -> TypeError: crc() expected bytes-like, got list
```

Bools are rejected for `init` and `xorout` — they ARE ints in Python but
almost certainly indicate a programmer error:

```python
crc(b"x", init=True)   # -> TypeError
crc(b"x", xorout=True) # -> TypeError
```

**CLI:**

```bash
# Compute CRC over a hex byte string (e.g. ASCII "123456789")
crc16-ccitt-pure-compute --data 313233343536373839
# -> 0x29b1

# Run all 6 RevEng-canonical vectors
crc16-ccitt-pure-self-test
# -> [PASS] input=''                       expected=0xffff actual=0xffff -- empty input
# -> [PASS] input='00'                     expected=0xe1f0 actual=0xe1f0 -- single 0x00
# -> [PASS] input='01'                     expected=0xf1d1 actual=0xf1d1 -- single 0x01
# -> [PASS] input='ff'                     expected=0xff00 actual=0xff00 -- single 0xFF
# -> [PASS] input='00010203040506070809'    expected=0xc241 actual=0xc241 -- bytes 0x00..0x09
# -> [PASS] input='313233343536373839'     expected=0x29b1 actual=0x29b1 -- RevEng check
# -> All 6 RevEng vectors PASS

# Or via Python module:
python3 -m crc16_ccitt             # runs the same self-test
python3 -m crc16_ccitt compute --data 313233343536373839
python3 -m crc16_ccitt self-test
```

**Test the installed package:**

```bash
git clone https://github.com/prasad-a-abhishek/crc16-ccitt-pure.git
cd crc16-ccitt-pure
pip install -e ".[test]"          # editable install + pytest + crcmod
pytest -q                          # 369 passed
```

**Limitations:**

- NOT a cryptographic primitive. CRC-16 detects accidental bit-errors; it does
  NOT authenticate or defend against an active attacker. Use `hashlib` for that.
- NOT optimized for throughput. Pure-Python bit-by-bit loop is ~7000× slower
  than `crcmod` on large inputs. Use `crcmod` for hot-path code.
- NOT a streaming API. `crc()` consumes the whole `bytes`-like object in one
  call. For multi-megabyte streams, chunk the input and chain the `init`
  parameter.
- NOT a generic CRC library. Only CRC-16/CCITT-FALSE (init=0xFFFF). The
  related CCITT-TRUE (init=0x0001, xorout=0xFFFF) and XMODEM (init=0x0000)
  variants are out of scope — each would be a separate repo.
- Pure Python ≥3.10 only. No Cython, no mypyc, no PyPy-specific tricks.

## License

MIT — see [`LICENSE`](LICENSE). Author: Prasad A Abhishek.
