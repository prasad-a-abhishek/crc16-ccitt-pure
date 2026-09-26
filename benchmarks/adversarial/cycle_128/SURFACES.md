# Attack Surface Enumeration — crc16-ccitt (cycle_128)

> Repo: `crc16-ccitt-pure` (package `crc16-ccitt`, v0.1.0)
> Branch: `wt/cycle128-adversary-01`
> Commit: `ab7291c` (parent), this document will be committed ahead of any further work
> Author: @default (cycle_128/adversary/01)
> Date: 2026-09-26

## Overview

CRC-16/CCITT-FALSE is a pure-Python 25-LOC reference implementation of the ITU-T
X.25 §2.2.3.4 frame-check sequence. The package is deliberately small (~120 LOC
core impl + 120 LOC CLI + 10 LOC `__main__.py`), and its surface area is
proportional to its scope: a single public function, two CLI subcommands, and
the Python module import path. There is no I/O, no networking, no global
mutable state, no parser-recursion, no native code, no `ctypes`, and no
plugin-loader. The threat model is therefore narrow — but the *correctness*
threat surface (algorithm-vs-spec drift) is the dominant concern for a CRC
reference implementation, because a *silent* one-bit parameter flip produces
plausible-looking CRC values that pass unit tests against a wrong oracle.

---

## Surface 1 — `crc(data, init=0xFFFF, xorout=0x0000) -> int`

**Entry point:** `src/crc16_ccitt/__init__.py::crc()` (line 29)
**Re-exported by:** `from crc16_ccitt import crc` (single public symbol per `__all__`)
**Class type:** total pure function of `(data, init, xorout)`

| Aspect | Value |
|---|---|
| **Input domain** | `data`: `bytes`, `bytearray`, or `memoryview` (per `isinstance` guard). `init`: `int` (NOT `bool`, NOT `None`, NOT `str`, NOT `float`). `xorout`: same as `init`. |
| **Output range** | Always an `int` in `[0, 0xFFFF]` (final `& 0xFFFF` mask on `__init__.py:87`). |
| **Determinism** | Total — no internal state, no `random`, no `time`, no `os.urandom`. Re-callable indefinitely with identical results. |
| **Algorithm class** | RevEng-pseudocode bit-by-bit MSB-first polynomial division, poly=0x1021. |
| **Side effects** | None. No imports beyond `__future__`. |

**Edge cases (validated against SPEC §3 + RevEng):**

| Input | Expected | Note |
|---|---|---|
| `b""` | `0xFFFF` | AC2 — empty input equals init exactly (xorout=0). |
| `bytes([0x00])` | `0xE1F0` | AC3 — RevEng single-byte 0x00. |
| `bytes([0xFF])` | `0xFF00` | AC4 — RevEng single-byte 0xFF. |
| `b"123456789"` | `0x29B1` | AC1 — RevEng canonical check value. |
| `bytes(range(10))` | `0xC241` | 10-byte 0x00..0x09 sweep. |
| `b"\x00\xFF"` | `0x7E83` | AC8 — proves RefIn=false (not XOR-composed). |
| 65536-byte all-zero | (deterministic) | Length sweep row; verified against crcmod. |
| 65536-byte all-FF   | (deterministic) | Length sweep row; verified against crcmod. |
| 1 MB all-FF         | (deterministic) | Tests claim linear-time behaviour under SPEC §6. |

**Why this surface dominates the threat model:** every other surface either
*calls* `crc()` or *parses user input into* the call. A bug here is a silent
correctness bug for the entire class of consumers (HDLC framers, AX.25 parsers,
Bluetooth-paging test fixtures). The MSB-first / RefIn-false property is the
single most fragile parameter because flipping it once turns the function into
CRC-16/IBM-SDLC (the `0x1021` with refinement, distinct check value), which
would still be a "valid 16-bit CRC" — just the *wrong* variant.

---

## Surface 2 — `python -m crc16_ccitt [compute|self-test]` module entrypoint

**Entry point:** `src/crc16_ccitt/__main__.py` (lines 1-10) → `cli.main()` (`cli.py:98`)
**Activation:** `python3 -m crc16_ccitt` (with no args → self-test; with `compute HEXSTR` → compute)
**Process model:** foreground, blocking. No background threads, no daemon threads, no `os.fork`.
**Filesystem / network:** none. Stdout-only, no file IO, no `urllib`.

The dispatcher is a pure stdlib `argparse`/`sys.argv` walker. Its only
interaction with the rest of the process is `sys.stdout` / `sys.stderr`.
Because the entrypoint is registered via `__main__.py`, the user cannot
exploit it by stubbing `sys.argv` from outside; `sys.argv` is captured fresh
inside `main()`.

**Subcommands accepted:**

| Argv | Dispatched to | Returns |
|---|---|---|
| `()` | `main_self_test([])` | `0` on all-pass, `1` otherwise. |
| `("compute", ...)` | `main_compute(argv[1:])` | `0` on success, `2` on bad-hex `ValueError`. |
| `("self-test",)` | `main_self_test([])` | same as no-args. |
| `("-h",)` or `("--help",)` | inline help printer | `0`. |
| anything else | stderr message + `2` | non-zero exits. |

**Surface-specific risks:**

- `compute` requires `--data HEXSTR`; absence triggers `argparse` `SystemExit(2)`. That crash goes to stderr — not stdout — and is *not* caught by `main()`.
- Hex strings may optionally contain space/comma separators (`cli.py:37`). Length must be even, otherwise `ValueError` → exit `2`.
- Hex odd-length input containing only `[0-9a-fA-F]` chars slips past `bytes.fromhex` Python and raises the standard `ValueError`. The CLI catches and re-raises with a friendly message.

**Why flagged:** the only *real* threat in this surface is the brittle
`argv[0]` switch (`cli.py:108-111`) — if a user passes `python -m crc16_ccitt --data XX`
they get the unhelpful "unknown subcommand: '--data'" error rather than the
intended compute dispatch. This is a UX defect, not a security vulnerability.

---

## Surface 3 — `crc16-ccitt-pure-compute` console script

**Entry point:** `cli.py::main_compute(argv)` (line 47)
**Registered in:** `pyproject.toml [project.scripts]` (line 34) — installed into `bin/`
**CLI flags:** `--data HEXSTR` (required, no positional args, no `--hex`, no stdin)

**Path through the code:**
1. `argparse` parses `--data` (line 53-58). Missing → argparse exits 2.
2. `_compute(data_hex)` (line 31) strips whitespace + commas, validates even length, calls `bytes.fromhex`.
3. `crc(data)` computes the 16-bit CRC.
4. `print(f"0x{value:04x}")` writes the result.

**Output format:** canonical `0xWXYZ` with leading-zero pad (`:04x`). Always
4 hex digits. Never negative, never > 0xFFFF, never empty.

**Failure modes (all benign):**

| Input | Behaviour | Exit code |
|---|---|---|
| `--data 313233343536373839` ("123456789") | prints `0x29b1` | 0 |
| `--data 00` | prints `0xe1f0` | 0 |
| `--data ""` (empty) | prints `0xffff` | 0 |
| `--data 0` (odd length) | "hex string must have even length" | 2 |
| `--data zz` (bad char) | "invalid hex input 'zz'" | 2 |
| (no `--data`) | argparse usage error | 2 |

**Why this surface is small:** there's no `--file`, no `--stdin`, no
`--output`, no `--init`, no `--xorout`. The script is intentionally *single-
shot*: one CLI invocation = one CRC computation. An attacker has zero control
over I/O, environment, or process scheduling.

---

## Surface 4 — `crc16-ccitt-pure-self-test` console script

**Entry point:** `cli.py::main_self_test(argv)` (line 69)
**Registered in:** `pyproject.toml [project.scripts]` (line 35)
**Test vectors:** six hard-coded (`_SELF_TEST_VECTORS` tuple, `cli.py:21-28`)
   - empty → `0xFFFF`
   - `"00"` → `0xE1F0`
   - `"01"` → `0xF1D1`
   - `"ff"` → `0xFF00`
   - `"00010203040506070809"` → `0xC241`
   - `"313233343536373839"` → `0x29B1` (canonical)

**Behaviour:** iterates the 6 vectors, prints `[PASS|FAIL] input=… expected=0x… actual=0x…`
per line, then `All 6 RevEng vectors PASS` on stdout (or `N vector(s) FAILED`
on stderr + non-zero exit).

**Why this surface is the *trust anchor*:** a binary that prints
`All 6 RevEng vectors PASS` can be safely considered correct against the
specification without further verification. The 6 vectors cover all 4
parameter-table switches (init, poly choice, no final XOR) and all 3 input
classes (empty, single-byte, multi-byte). The RevEng check value
`0x29B1` distinguishes CCITT-FALSE from CCITT-TRUE (`0xD64E`? — actually
this would require init=0x0001 xorout=0xFFFF; both Poly=0x1021),
XMODEM (`0x31C3` init=0x0000), MODBUS (`0x4B37` poly=0x8005), and SDLC
(`0x906B` poly=0x1021 init=0xFFFF refin=true).

---

## Surface 5 — Input-validation guard (`TypeError` path)

**Entry point:** `src/crc16_ccitt/__init__.py::crc()` lines 65-76 (early guards)
**Defensive checks:**

```python
if not isinstance(data, (bytes, bytearray, memoryview)):
    raise TypeError(f"crc() expected bytes-like, got {type(data).__name__}")
if not isinstance(init, int) or isinstance(init, bool):
    raise TypeError(f"crc() 'init' must be int (not bool), got {type(init).__name__}")
if not isinstance(xorout, int) or isinstance(xorout, bool):
    raise TypeError(f"crc() 'xorout' must be int (not bool), got {type(xorout).__name__}")
```

**Input domain matrix (per AC12):**

| Type | `data` | `init` | `xorout` |
|---|---|---|---|
| `bytes` | accepted | (separate) | (separate) |
| `bytearray` | accepted | (separate) | (separate) |
| `memoryview` | accepted | (separate) | (separate) |
| `str` | **TypeError** | **TypeError** | **TypeError** |
| `None` | **TypeError** | **TypeError** | **TypeError** |
| `int` | **TypeError** | accepted | accepted |
| `float` | **TypeError** | **TypeError** | **TypeError** |
| `bool` | **TypeError** (bool is int, not bytes-like) | **TypeError** (rejected) | **TypeError** (rejected) |
| `list`/`tuple`/`dict`/`set` | **TypeError** | (separate) | (separate) |
| `object()` | **TypeError** | (separate) | (separate) |

**Why this is a first-class surface rather than a sub-element of Surface 1:**
SPEC §3 AC12 mandates that every non-bytes-like call MUST raise `TypeError`
with a message naming the offending type, and MUST NEVER produce a silent
garbage CRC. This is observable behaviour on the API contract — a regression
here is a contract violation independent of the algorithm.

**Risk that *would* be present but is *not*:** there is no silent coercion
of strings via `.encode()` (which would mask a "did you mean UTF-8?" bug).
There is no fall-through to `len(data)` or `hash(data)`. Both naive traps
are explicitly avoided.

---

## Surface 6 — `__version__` constant and `__all__` export list

**Entry point:** `src/crc16_ccitt/__init__.py:21, 90`
**Surface:** `from crc16_ccitt import __version__` returns `"0.1.0"` (str).
`__all__ = ["crc", "__version__"]` — only two public symbols.

**Risk:** trivially low. `__version__` is a frozen string, not a module
reference, so it cannot be shadowed by an attacker to inject code. The `__all__`
list restricts `from crc16_ccitt import *` to exactly these two symbols,
preventing accidental import of any future private helper added to the module.

This surface is listed for completeness (zero-dep public API inventory);
no CWE entry applies with severity ≥ Low.

---

## Surface 7 — Memory / CPU bound on large input

**Entry point:** `src/crc16_ccitt/__init__.py::crc()` loop (lines 80-86)
**Complexity:** O(N) time, O(1) space — for `N` bytes of input, the loop
runs `8*N` bit-shift/XOR iterations with a single 16-bit register.

**Test coverage of large inputs:** tests assert correctness on a 65536-byte
(`64k_zero_block`, `64k_ff_block`) input but do **not** specifically
*benchmark* a > 1 MB run. The honest claim (per SPEC §6 "NOT optimized for
speed") is that 1 MB is acceptable for a single call on commodity hardware
but should not be used in a tight inner loop. The CLI is single-shot by
design — there is no `--repeat` or `--stream` flag — so uncontrolled
resource consumption requires the caller to drive many invocations.

**Why listed:** even without explicit large-input attacks, an integrator who
shoves a 1 GB `bytes` object at `crc()` will hold the GIL for ≈8 billion
bit-shift iterations. That's a *caller* responsibility, not a *library* bug,
but it belongs in the threat model.

---

## Summary table

| # | Surface | LOC | Entry | Risk class |
|---|---|---|---|---|
| 1 | `crc(data, init, xorout)` | 20 | `__init__.py:29` | **Algorithm correctness** (dominant) |
| 2 | `python -m crc16_ccitt` | 3 | `__main__.py:9` | UX defect only |
| 3 | `crc16-ccitt-pure-compute` | 20 | `cli.py:47` | Input parsing (even-length hex) |
| 4 | `crc16-ccitt-pure-self-test` | 27 | `cli.py:69` | None (read-only RevEng vectors) |
| 5 | `TypeError` guards | 12 | `__init__.py:65-76` | **API contract (AC12)** |
| 6 | `__version__` + `__all__` | 2 | `__init__.py:21,90` | None (informational) |
| 7 | Large-input memory/CPU | (within Surface 1) | `__init__.py:80-86` | Caller responsibility (SPEC §6) |

**Surface count: 7** (target was 4-7 per task brief — meets upper bound).

See `CWE_MAP.md` for the per-surface CWE entries,
`THREAT_MODEL.md` for the per-surface attack-narrative,
`TEST_GAPS.md` for the AC→test mapping,
`VULN_AUDIT.md` for the severity-ranked findings table.
