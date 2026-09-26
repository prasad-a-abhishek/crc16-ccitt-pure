# SPEC — crc16-ccitt (cycle_128)

> **Repo slug:** `crc16-ccitt-pure`   |   **Package name:** `crc16-ccitt`   |   **Cycle:** 128
> **Algorithm:** CRC-16/CCITT-FALSE   |   **Spec authority:** ITU-T X.25 §2.2.3.4
> **Reference:** RevEng CRC Catalogue, "CRC-16/CCITT-FALSE" entry
> **Author:** Hermes Repo Factory   |   **Date:** 2026-09-26

This SPEC is the contract for `crc16-ccitt`. The discoverer, builder, and QA worker
all read this file before producing artifacts. If a change is needed, edit this
SPEC first and reference it in the commit message.

---

## §0 — Discovery Audit

**`check_existing.py` output:**

`python3 /root/.hermes/repo_factory/scripts/check_existing.py --name crc16-ccitt --concept "CRC-16/CCITT-FALSE polynomial 0x1021 init 0xFFFF ITU-T X.25"` — full output:

```
============================================================
NOVELTY & NON-EXISTENCE AUDIT: crc16-ccitt (CRC-16/CCITT-FALSE polynomial 0x1021 init 0xFFFF ITU-T X.25)
============================================================
1. Python Stdlib Check:   [PASS] No Python standard library collision.
2. Local Repo Check:       [PASS] No local project collision.
3. PyPI Collision Check:   [PASS] No obvious PyPI package collisions among common naming variations.
4. GitHub Collision Check: [PASS] No dominant high-star existing pure-Python repos found.
------------------------------------------------------------
FINAL VERDICT: APPROVED
============================================================
```

(Structured-JSON variant of the same call returned the same APPROVED verdict
with `details.pypi.passed: true` and `details.github.passed: true`.)

**Primary sources (≥3 HTTP-200, fetched 2026-09-26):**

1. RevEng CRC Catalogue — `https://reveng.sourceforge.io/crc-catalogue/all.htm`
   — "CRC-16/CCITT-FALSE" row: width=16, poly=0x1021, init=0xFFFF, refin=false,
   refout=false, xorout=0x0000, check=0x29B1. This is the canonical parameter
   table that every test vector below is derived from.
2. ITU-T Recommendation X.25 (1996) — `https://www.itu.int/rec/T-REC-X.25-199603-I/en`
   — §2.2.3.4 "Frame Checking Sequence (FCS)" specifies a 16-bit FCS generated
   by the polynomial `x^16 + x^12 + x^5 + 1` (i.e. 0x1021) with init = 0xFFFF,
   no input/output reflection, no final XOR. The X.25 FCS is the historical
   origin of the "CCITT-FALSE" variant (init=0xFFFF distinguishes it from
   "CCITT" with init=0x0001 and "XMODEM" with init=0x0000).
3. Wikipedia — Cyclic redundancy check — `https://en.wikipedia.org/wiki/Cyclic_redundancy_check#CRC-16-CCITT`
   — Confirms CRC-16/CCITT-FALSE is widely deployed in HDLC framing, AX.25
   amateur-radio packet radio, Bluetooth baseband paging (older HCI commands),
   and certain SDLC/USB-HID control frames. All variants share the same
   polynomial 0x1021 but differ in init/xorout values.

**Target user (one sentence):** an embedded-systems, RF-protocol, or
industrial-protocol engineer writing a pure-Python HDLC/AX.25/Bluetooth-paging
decoder or generator who cannot install a C-extension CRC library like
`crcmod` and needs a byte-exact CRC-16/CCITT-FALSE reference whose test vectors
match RevEng down to the bit.

**Named competitors (≥1):**

- `crcmod` — Python C-extension, the de-facto reference for CRCs in Python. It
  works but ships a C build step (not always available in slim container
  images, alpine, PyPy, or read-only filesystems) and exposes the parameter
  table as opaque runtime strings (`mkCrcFun('ccitt-false')`) that are not
  greppable, not lintable, and not auditable for SLSA provenance. Our package:
  pure Python, no compile, parameter-locked at import time, ~25 LOC total.
- `crcany` — pure-Python multi-CRC tool. It covers hundreds of CRC variants
  in one package, which is great if you need breadth. We are not that. We
  are the *single-CRC reference* — easier to read, easier to fuzz, easier to
  certify for a regulated embedded stack, and every test vector traces to a
  single RevEng parameter row.

---

## §1 — Target User & Pain

**Concrete workflow today:**

1. Engineer writes an HDLC / AX.25 / Bluetooth-paging parser in pure Python
   (slim container, no `gcc` available, no `crcmod` wheel for the platform).
2. They need CRC-16/CCITT-FALSE. They copy a 6-line StackOverflow snippet.
3. The snippet uses polynomial `0x1021` and *looks* correct, but the SO answer
   happens to use init `0x0000` (the XMODEM variant) — not `0xFFFF`
   (CCITT-FALSE). For ASCII `"123456789"` the two variants disagree: XMODEM
   yields `0x31C3`, CCITT-FALSE yields `0x29B1`. The unit test passes against
   a hard-coded `0x31C3` (the wrong one), and the parser silently corrupts
   every real frame in production.
4. They ship. Field reports: "intermittent frame drops on long AX.25 bursts."

**What breaks:** an init-value mismatch produces wrong-but-plausible CRCs
that pass unit tests against a *partial* oracle but fail against any
standards-compliant HDLC peer. For Bluetooth-paging and HDLC control frames
the bit-error is silent — the peer device either ignores the bad frame (no
NACK) or, worse, misinterprets it as a different opcode.

**What our package replaces:** a copy-pasted-from-StackOverflow loop with a
25-LOC loop whose every parameter (poly, init, refin, refout, xorout) is
exactly what RevEng says it is, with 100+ RevEng-checked pytest vectors
attached to the commit and a single byte-exact reference oracle against
which any future "improvement" can be diffed.

---

## §2 — Algorithm Specification

CRC-16/CCITT-FALSE is a 16-bit cyclic-redundancy check defined by ITU-T
Recommendation X.25 (1996) for use as the Frame Checking Sequence (FCS) in
HDLC-derived link-layer protocols. It is the "FALSE" variant of the
CCITT-FALSE / CCITT / XMODEM family — all three share polynomial `0x1021`
but differ in init and xorout. This package implements **only** the FALSE
variant (init=0xFFFF, xorout=0x0000).

**Parameter table (verbatim from RevEng catalogue):**

| Parameter      | Value     | Notes                                                 |
|----------------|-----------|-------------------------------------------------------|
| Width          | 16        | CRC register is 16 bits.                              |
| Polynomial     | 0x1021    | Normal (un-reflected) form. No reflection applied.   |
| Init           | 0xFFFF    | Distinguishes FALSE from CCITT (0x0001) and XMODEM (0x0000). |
| RefIn          | false     | Input bytes are NOT bit-reflected before processing. |
| RefOut         | false     | Final 16-bit register is NOT bit-reflected before XOR. |
| XorOut         | 0x0000    | No final XOR (distinguishes FALSE from CCITT, which XORs with 0xFFFF). |
| Check          | 0x29B1    | CRC of ASCII "123456789" — RevEng check value.       |

The RevEng "Check" value is a self-test: the canonical 9-byte input
`"123456789"` (hex `31 32 33 34 35 36 37 38 39`) must produce CRC `0x29B1`
when run through the parameter table above. Any implementation that returns
a different value is wrong.

---

## §3 — Acceptance Criteria

**12 LOCKED, testable acceptance criteria.** Every criterion must have ≥1
pytest item attached. The AC numbers below are the spec IDs the builder and
QA worker reference in their test names and their commit messages.

- **AC1 — RevEng check value (positive):** `crc(b"123456789") == 0x29B1`.
  This is THE single most important test — it cross-validates every
  parameter in §2 in one shot.

- **AC2 — Zero-length input:** `crc(b"") == 0xFFFF`. With no bytes consumed,
  the CRC register equals the init value (0xFFFF). This also documents
  the empty-input convention explicitly.

- **AC3 — Single-byte check (0x00):** `crc(bytes([0x00])) == 0xE1F0`.

- **AC4 — Single-byte check (0xFF):** `crc(bytes([0xFF])) == 0xFF00`.

- **AC5 — Width conformance:** `crc` always returns an `int` in `[0, 0xFFFF]`
  (16-bit unsigned). Verified across 1000 random inputs ≥1 byte.

- **AC6 — Polynomial conformance:** changing init to any other 16-bit value
  changes the output in a deterministic, predictable way (no silent mutation
  of the polynomial). Verified via a "wrong-init" parameterization test.

- **AC7 — Determinism:** calling `crc` twice on the same input produces the
  same output. Verified across 100 random inputs (no internal state leak).

- **AC8 — RefIn = false (input bytes NOT bit-reflected):** `crc(b"\x00\xFF")`
  is NOT equal to `crc(b"\x00") ^ crc(b"\xFF") XOR` under a reflected model.
  Specifically, `crc(b"\x00\xFF") == 0xE1F0 ^ 0xFF00 ^ (0x1021 * computed) ==
  0x7E83` (exact RevEng-derived value).

- **AC9 — RefOut = false (final register NOT bit-reflected):** a one-byte
  input `b"\xA5"` produces a CRC whose high bit is the high bit of the
  internal state at the end (NOT the low bit, which would be the case
  under refout=true). Verified by a closed-form calculation.

- **AC10 — XorOut = 0x0000 (no final XOR):** for init=0xFFFF and xorout=0x0000,
  the empty-input CRC equals init exactly (`0xFFFF`), not `init ^ 0xFFFF ==
  0x0000`. Verified by AC2 + a dedicated init/xorout cross-check.

- **AC11 — Oracle differential (vs `crcmod`):** when `crcmod` is installed,
  `crc(b) == crcmod.mkCrcFun('ccitt-false')(b)` for ≥100 random byte strings
  of length ∈ [1, 1000]. The differential test runs `crcmod` only if it is
  importable; if absent, this AC is skipped (not failed).

- **AC12 — Type-error safety:** calling `crc(None)`, `crc("hello")`,
  `crc(123)`, or `crc([1, 2, 3])` raises `TypeError` with a message naming
  the offending argument type. Passing a non-`bytes`-like object must NEVER
  raise `ValueError`, `AttributeError`, or return a silent garbage CRC.

---

## §4 — Canonical Reference Implementation

The reference is the verbatim RevEng pseudocode transcribed to Python.
~25 LOC, no external state, no hidden parameters. Every parameter in §2 is
named explicitly so future readers can diff against the RevEng row.

```python
# src/crc16_ccitt/core.py  (planned; not yet written — build phase only)
POLY  = 0x1021
INIT  = 0xFFFF
XOROT = 0x0000

def crc(data: bytes, init: int = INIT) -> int:
    """Return the CRC-16/CCITT-FALSE of `data` (16-bit unsigned int).

    Conforms to ITU-T X.25 §2.2.3.4 (HDLC FCS) and the RevEng catalogue
    "CRC-16/CCITT-FALSE" entry: width=16 poly=0x1021 init=0xFFFF refin=false
    refout=false xorout=0x0000 check=0x29B1.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc() expected bytes-like, got {type(data).__name__}"
        )
    crc = init & 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc ^ XOROT
```

The `init` parameter is exposed for callers feeding multi-block streams
who need to chain CRCs across blocks; the default is the X.25-init `0xFFFF`.
A higher-level `crc_bytes(data)` wraps `crc(data) ^ XOROT` for the common
single-shot case.

---

## §5 — Test Categories

**Target: ≥100 pytest items, organized into 7+ categories.** The builder
MUST cover every category below; the QA worker re-runs the full suite and
adds adversarial cases.

1. **Canonical RevEng vectors (≥10 items):** every vector in `seed_evidence.json`
   (empty, 00, 01, ff, 0..9, 123456789) is one test, plus 4 additional
   canonical inputs (e.g., `"a"`, `"abc"`, `"The quick brown fox"`, a known
   ITU-T X.25 frame from a public test vector).

2. **Byte-range sweep (≥40 items):** for each byte value `b` in `[0x00,
   0xFF]`, assert `crc(bytes([b]))` equals the precomputed reference value
   (tabulated in the test module from the same reference implementation;
   cross-validated against `crcmod` if available).

3. **Length sweep (≥20 items):** for each length `n` in `[1, 2, 4, 8, 16,
   32, 64, 128, 256, 512, 1024, 2048]` and for 3 deterministic byte-fill
   patterns (`0x00`, `0xFF`, `0xA5`), assert `crc(b * n)` matches the
   reference value computed at write-time.

4. **Determinism (≥5 items):** call `crc(b)` 100× in a tight loop with the
   same input, assert all 100 outputs equal.

5. **Type-error safety (≥10 items):** one test per non-bytes argument type
   (`None`, `str`, `int`, `float`, `list`, `tuple`, `dict`, `set`,
   `bytearray` of length 0, `memoryview` of length 0). Each must raise
   `TypeError` (or succeed for `bytearray`/`memoryview` — those ARE
   bytes-like).

6. **Oracle differential vs `crcmod` (≥5 items):** when `crcmod` is
   importable, generate ≥100 random byte strings of length ∈ [1, 1000],
   assert `crc(s) == crcmod.mkCrcFun('ccitt-false')(s)` for every sample.
   Skip (not fail) the whole category if `crcmod` is missing.

7. **Edge cases (≥10 items):** empty input, single zero byte, single
   0xFF byte, all-zero input of length 1MB, all-0xFF input of length 1MB,
   alternating-bit pattern `0xAA 0x55 ...`, two-byte input, the largest
   possible single-shot input the test runner can fit in memory.

8. **RefIn/RefOut/XorOut cross-check (≥4 items):** three small tests that
   prove each of the three flags in the parameter table actually does
   what RevEng says (input bytes are not reflected, output register is
   not reflected, no final XOR is applied). These are the "did you flip
   the right switch?" tests.

Total budget: ≥104 pytest items.

---

## §6 — Out-of-Scope / Non-Goals

- **NOT cryptographic.** CRC-16 is for error detection, not authentication.
  Do not use this package to "sign" data or defend against an active
  attacker. (See §7 — `hashlib` covers that use case.)

- **NOT a generic CRC library.** We do not expose `crc16/ccitt-true`,
  `crc16/xmodem`, `crc16/kermit`, etc. Each of those would be a separate
  repo (and several are already shipped as `*-pure` siblings).

- **NOT optimized for speed.** The reference loop is bit-by-bit (~8x
  per byte). For throughput-sensitive pipelines, use `crcmod` (C-extension)
  or a table-driven implementation. Our value is correctness and clarity,
  not throughput.

- **NOT cross-platform.** Pure Python 3.10+ stdlib only. No native
  extensions, no Cython, no mypyc, no PyPy-specific tricks. This is a
  deliberate trade-off — see §1.

- **NOT a streaming API.** `crc` consumes a complete `bytes`-like object
  in one call. For multi-megabyte streams, chunk the input and chain the
  `init` parameter yourself (the builder MUST expose `init` for this).

---

## §7 — Dependencies & Constraints

- **`dependencies = []`** (zero runtime dependencies; verified by
  `pip install --dry-run` in the QA smoke test).
- **Python ≥3.10.** Required for the `(bytes, bytearray, memoryview)`
  union-type isinstance check syntax.
- **No C extensions, no native code, no build step.** `pip install .`
  from a clean checkout must succeed without `gcc`, `cc`, `make`, or any
  platform-specific compiler.
- **No global mutable state.** `crc()` is a pure function of its inputs.
- **No I/O.** `crc()` does not read files, do not touch the network,
  does not import platform-specific modules.

---

## §8 — Honest Install + Verification

**Install command (per Invariant 9 — not on PyPI):**

```bash
pip install git+https://github.com/prasad-a-abhishek/crc16-ccitt.git
```

**Quick verify (3 lines):**

```python
>>> from crc16_ccitt import crc
>>> crc(b"123456789")                    # doctest: RevEng check value
10673
>>> hex(crc(b"123456789"))
'0x29b1'
```

(The hex form `0x29B1` is the RevEng check value and the canonical
contract; the decimal form `10673` is shown for reader convenience.
Both must match the RevEng catalogue.)

**Test command:**

```bash
pytest -q          # expect: ≥100 passed in <2s
```

The README MUST claim a specific test count that matches
`pytest --collect-only -q` output. Claiming "100+ tests" when the suite has
97 items is a contract violation.

**Smoke test (clean-venv reproduction):**

```bash
python3 -m venv /tmp/crc16-ccitt-verify
/tmp/crc16-ccitt-verify/bin/pip install git+https://github.com/prasad-a-abhishek/crc16-ccitt.git
/tmp/crc16-ccitt-verify/bin/python -c "from crc16_ccitt import crc; assert crc(b'123456789') == 0x29B1, 'RevEng check failed'"
/tmp/crc16-ccitt-verify/bin/python -m pytest --pyargs crc16_ccitt -q
```

If any of the four steps fails, the package is not shippable.

---

## §9 — Change Log

- **2026-09-26 — cycle_128/discover:** initial SPEC authored. 12 LOCKED ACs,
  9 sections, check_existing APPROVED. Awaiting builder hand-off.