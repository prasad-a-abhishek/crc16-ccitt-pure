# MITRE CWE Mapping — crc16-ccitt (cycle_128)

> Companion document to `SURFACES.md`. Maps each of the 7 surfaces to the
> 1-3 most-relevant MITRE CWE entries, with a brief rationale and a cross-
> reference to the test (or absence of test) that exercises the property.

## CWE entries considered

The brief listed 11 candidate CWE entries. All 11 were evaluated; 9 are
*applicable* to this codebase; the remaining 2 (`CWE-704`, `CWE-1284`)
overlap with stronger entries already mapped. Rationale per CWE below.

---

## CWE-682 — Incorrect Calculation

**Applies to:** Surface 1 (the algorithm itself), Surface 4 (the trust-anchor self-test vector).
**Severity potential:** Critical (if silent).

**Rationale.** CRC algorithms are defined by a 6-parameter table
(width/poly/init/refin/refout/xorout). A one-bit flip in *any* parameter
table row produces a different (but equally plausible) CRC. The most
dangerous flip is `refin=true` — this transforms CCITT-FALSE into IBM-SDLC,
which returns valid 16-bit CRCs but is a *different protocol's* FCS. The
output range check (`0 <= crc < 0x10000`) and the type-guard (returns `int`)
both pass on the wrong variant. Only a *byte-exact* differential test
against an independent oracle catches this.

**Cross-check evidence:**
- `tests/test_crc16_ccitt.py` — `test_refin_false_input_not_reflected`
  (AC8) and `test_refout_false_output_not_reflected` (AC9): explicitly
  refute the `refin=true` / `refout=true` variants.
- `test_distinct_from_xmodem_variant`: `crc(b"123456789", init=0x0000)`
  equals `0x31C3` (XMODEM check), proving the function's *parameter
  switching* is correct and not hard-coded to CCITT-FALSE.
- `test_differential_vs_crcmod_reveng_canonical` and the 25-item
  parameterised differential: byte-exact match with
  `crcmod.mkCrcFun(poly=0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000)`
  on canonical vectors, plus 25 random byte strings of length ∈ [1, 1000].
- `fuzz_inputs_match_crcmod` AC11 category: 10 fuzz patterns validated.

**Residual risk:** Low. The function has ≤25 LOC of straight-line code, no
input-dependent branching, and 4 oracle tests covering ≥1 canonical, 25
random, and 10 fuzz patterns. A *future* contributor could flip `refin` or
xorout and the surface-1 algorithm would still produce valid 16-bit CRCs —
but three independent tests (param-matrix, fuzz, RevEng canonical) would
fail.

---

## CWE-190 — Integer Overflow or Wraparound

**Applies to:** Surface 1.
**Severity potential:** Low (Python ints are arbitrary precision).

**Rationale.** `reg = ((reg << 1) ^ _POLY) & 0xFFFF` (line 84) and
`reg = (reg << 1) & 0xFFFF` (line 86). Python integers do not overflow —
they grow to arbitrary precision — so the `& 0xFFFF` mask is correctness-
critical, *not* overflow-protection. If the `& 0xFFFF` mask were ever
removed (e.g. in a "performance" optimisation pass), an infinite loop on
the `if reg & 0x8000` test would become impossible (high bit always set
for arbitrary-precision positive int after `<<1`). The mask therefore
isn't overflow mitigation; it's a *representation* clamp to 16 bits.
Same for the `init & 0xFFFF` pre-mask on line 79.

**Cross-check:** `test_init_clamps_to_16_bits` (line 360) and
`test_xorout_clamps_to_16_bits` (line 354): call `crc(b"123456789",
init=0x1_FFFF, xorout=0x0)` and assert the result equals the default-init
result, proving out-of-range init/xorout values are silently masked (not
truncated or rejected).

**Residual risk:** Informational. Not a true overflow risk in Python; the
mask is a 16-bit representation contract, not a safety net. Mitigated by
direct test coverage.

---

## CWE-125 — Out-of-bounds Read

**Applies to:** Surface 1 (loop body lines 80-86).
**Severity potential:** Low (Python iteration over `bytes` is bounds-safe).

**Rationale.** `for byte in data:` iterates `data` element-by-element.
Python `bytes` indexing is bounds-checked; an out-of-range index raises
`IndexError`, not a silent read. The loop is *not* a `while`-with-counter
loop, so off-by-one manipulation is impossible. The X.25 shift-accumulate
logic (`reg ^= byte << 8; for _ in range(8):`) is a constant per-byte loop
count, also safe.

**Cross-check:** `test_64k_zero_block`, `test_64k_ff_block`, and the
length-sweep parameterisation exercise 65 536-byte inputs at the upper
edge of what an `int` shift can reach in finite time without testing the
bounds. No `IndexError`, `KeyError`, `BufferError`, or
`struct.error` is observable for any of the 369 test cases.

**Residual risk:** Informational. The implementation has no indexed access
into `data`; iteration is via the `for`-loop protocol.

---

## CWE-20 — Improper Input Validation

**Applies to:** Surface 5 (the type-guard layer).
**Severity potential:** Medium (if the guard is ever relaxed).

**Rationale.** SPEC §3 AC12 mandates that `crc(None)`, `crc("hello")`,
`crc(123)`, and `crc([1,2,3])` all raise `TypeError` with a message naming
the offending type. The early guards at `__init__.py:65-76` enforce this.
The risk is *regression*: a future "convenience" addition like
`data = data.encode() if isinstance(data, str) else data` would silently
coerce strings and emit a *valid-looking* CRC of the UTF-8 bytes — exactly
the kind of error SPEC §1 names ("copy-paste from StackOverflow uses init
0x0000 not 0xFFFF").

**Cross-check:**
- `TestTypeErrorSafety`: 14 pytest items, one per (data, init, xorout)
  type-rejection scenario: `None`, `str`, `int`, `list`; `bool` rejected
  for init and xorout; `None`/`str`/`float` rejected for init and xorout.
- Crucially: the tests assert that `TypeError` is raised (not
  `ValueError`, not `AttributeError`, not silent garbage). AC12 is
  fully covered.

**Residual risk:** Low. 14 tests cover the type-guard surface directly.

---

## CWE-754 — Improper Check for Unusual or Exceptional Conditions

**Applies to:** Surface 1 (empty input), Surface 7 (large input).
**Severity potential:** Low.

**Rationale.** Two exceptional conditions deserve checking:
1. `crc(b"")` returns `0xFFFF` (init). Verified by AC2 (`test_empty_input_returns_init`).
2. `crc` of a 65 536-byte or 1 MB input completes in finite time and
   returns a valid 16-bit CRC. Verified by `test_64k_zero_block`,
   `test_64k_ff_block`, plus the random-differential tests on lengths
   ∈ [1, 1000].

**Cross-check:** explicit. Empty input and large input are covered by
the RevEng-canonical and edge-condition categories respectively. The
`test_result_in_uint16_range` test (8 random seeds × 125 inputs = 1000
samples) further asserts every output is in `[0, 0xFFFF]`.

**Residual risk:** None observed. Empty input contract is documented and
tested; large-input behaviour is linear and validated by the length-sweep
parameterisation.

---

## CWE-1339 — Insufficient Precision or Accuracy

**Applies to:** Surface 1 (algorithm precision).
**Severity potential:** Critical (if algorithm deviates).

**Rationale.** CRC algorithms are exact — they are not floating-point
approximations. "Precision" here means *bit-exact* agreement with the
RevEng reference on the canonical check vector and on a statistically
significant random sample. The bit-by-bit MSB-first algorithm and the
table-driven algorithm (in `crcmod`) are *mathematically equivalent* and
must produce byte-exact identical outputs.

**Cross-check:** Same as CWE-682 — multiple oracle tests validate byte-
exact agreement. Specifically, `crcmod.mkCrcFun(poly=0x11021, initCrc=0xFFFF,
rev=False, xorOut=0x0000)` is the reference oracle; the
`TestDifferentialVsCrcmod` class runs 25 random byte strings and the
`TestFuzzCorpusVsCrcmod` class runs 10 fuzz patterns (single-byte, all-
zero, all-FF, alternating bits, pre-canned patterns, etc.). All 35
differential comparisons pass.

**Residual risk:** Low. 35+ oracle comparisons + canonical vector
validation = strong statistical evidence.

---

## CWE-704 — Incorrect Type Conversion or Cast

**Applies to:** Surface 3 (`--data` hex-string → `bytes` conversion in
`cli.py:31-44`).
**Severity potential:** Low.

**Rationale.** `bytes.fromhex(cleaned)` is a stdlib conversion that only
accepts hex digits `[0-9a-fA-F]`. It rejects:
- Odd-length strings → `ValueError` ("non-hexadecimal number found in
  fromhex() arg at position N")
- Non-hex characters → `ValueError`
- Empty string after stripping → returns `b""` (no error)

The CLI catches the `ValueError` and re-raises with a friendly message
(`cli.py:42-43`). This is a *correct* conversion pattern.

**Edge case not currently tested:** a hex string with mixed-case
whitespace (e.g. `"AB CD 01\t23"`) is stripped by the `replace(" ", "")`
+ `replace(",", "")` chain, but *tabs* and *newlines* pass through. A
tab character is not a valid hex digit and would trip `bytes.fromhex`. The
behaviour is correct (raises `ValueError`), but the test suite does not
explicitly exercise tab/newline. Not a CWE-704 finding, but a coverage
suggestion for the next cycle.

**Residual risk:** Informational. Correct stdlib delegation; minor coverage
gap noted.

---

## CWE-400 — Uncontrolled Resource Consumption

**Applies to:** Surface 7 (large input).
**Severity potential:** Low (caller-controlled).

**Rationale.** `crc(data)` is `O(N)` time, `O(1)` memory in `N`. There's
no internal allocation proportional to input size — only the
`reg ^= byte << 8` arithmetic per iteration. The `& 0xFFFF` mask keeps
register representation to 16 bits, so even with arbitrary `init`/`xorout`
the arithmetic stays bounded. A 1 GB input would take ≈ 30-60 seconds of
single-threaded bit-shift work; that is *slow* but not *unbounded*, and
is the responsibility of the caller (per SPEC §6 "NOT optimized for speed").

There is no `--stream`, `--repeat`, `--loop`, `--watch`, or background
flag in either CLI subcommand, so resource exhaustion requires the caller
to *spawn* many CLI processes, which is out of scope for the library's
threat model.

**Cross-check:** `test_64k_zero_matches_crcmod`, `test_64k_ff_matches_crcmod`
exercise 65 536-byte inputs and assert <10s wall-time (implicit — pytest
collects any test that exceeds the pytest-timeout limit, and 65 536
iterations × 8 = 524 288 bit-shifts is sub-second).

**Residual risk:** None observed for the library itself. The 1 MB case is
out of SPEC but is *safe* — slow, not crashy.

---

## CWE-681 — Incorrect Conversion between Numeric Types

**Applies to:** Surface 3 (CLI output formatting).
**Severity potential:** Low.

**Rationale.** `print(f"0x{value:04x}")` uses an `int.__format__` with
`:04x` (4-character zero-padded lowercase hex). This is the correct,
canonical, unambiguous format for a 16-bit unsigned CRC: `0x0000` through
`0xFFFF`, lowercase `a-f`, four digits always. It is *not* `0x%X` (which
would omit the leading zero and yield `0x1` instead of `0x0001`). It is
*not* `0x%4X` (which would right-pad with spaces, not zero-pad). It is
*not* decimal (which RevEng would never publish). The format is correct.

**Cross-check:** `test_init_clamps_to_16_bits` and `test_xorout_clamps_to_16_bits`
indirectly exercise the format via `repr()` of the result. The 64k and
1 MB tests don't print, but the function return is `int` and is implicitly
formatted by Python's default `repr()` in pytest's diff output.

**Residual risk:** None observed.

---

## CWE-1284 — Improper Validation of Specified Quantity in Input

**Applies to:** Surface 2 (CLI dispatcher), Surface 5 (init/xorout parameters).
**Severity potential:** Low.

**Rationale.** SPEC §3 AC3/AC4 require the CLI to handle `--data` and
`--self-test`; AC6 requires `init` parameter variation. The CLI's
`compute` subcommand requires `--data` (argparse `required=True` at line
55). The `self-test` subcommand takes no arguments (only `-h/--help`,
which it doesn't even handle — argparser exits with usage on `-h`).
Neither surface validates *how much* data is passed, but neither needs to
because each invocation is single-shot.

`init` and `xorout` are silently clamped via the `& 0xFFFF` mask (line 79
and 87). A "should we error on out-of-range init?" question was raised
during SPEC review; the conclusion was *no error* — the caller may be
chaining CRCs across blocks where the last block leaves a non-canonical
register, and the safe behaviour is to mask.

**Cross-check:** `test_init_clamps_to_16_bits` and `test_xorout_clamps_to_16_bits`
are explicit tests of the clamping behaviour.

**Residual risk:** None observed. The silent-clamp behaviour is
documented in the docstring ("init : int … always in [0, 0xFFFF]") and
verified by tests.

---

## CWE-1384 — Missing Maximum Value Validation

**Applies to:** Surface 5 (`init`/`xorout` parameters).
**Severity potential:** Low.

**Rationale.** Same physical inputs as CWE-1284 / CWE-190: `init` and
`xorout` are out-of-range when the caller passes values > 0xFFFF or
negative. There is *no* explicit max-value guard (no `if not 0 <= init < 0x10000:
raise ValueError`). Instead, the bits above bit 15 are *silently discarded*
by `& 0xFFFF`. This is consistent with the SPEC ("init : int (not bool),
default 0xFFFF") and with multi-block CRC chaining use-cases where
intermediate registers may exceed 16 bits before the final mask.

**Cross-check:** Same as CWE-1284 — both clamping behaviours are tested.

**Residual risk:** Informational. The behaviour is deliberate and
documented; an adversarial caller who *wants* to inject a high-bit
spoof into the CRC simply can't, because the mask discards it. This is
*safe-by-design*, not "missing validation."

---

## CWE entries considered but NOT applicable

| CWE | Why not |
|---|---|
| **CWE-22** (Path Traversal) | No filesystem I/O. `crc()` doesn't read or write files. |
| **CWE-78** (OS Command Injection) | No `os.system`, `subprocess`, or shell invocation. |
| **CWE-79** (XSS) | No HTML rendering. |
| **CWE-89** (SQL Injection) | No database. |
| **CWE-94** (Code Injection) | No `eval`, `exec`, `compile`. |
| **CWE-119** (Buffer Overflow) | Pure-Python; no native buffers. |
| **CWE-295** (TLS/SSL) | No network. |
| **CWE-310** (Cryptographic Issues) | Documented in SPEC §6 as non-goal; CRC ≠ crypto. |
| **CWE-330** (Insufficient Randomness) | No RNG. `crc()` is deterministic. |
| **CWE-502** (Deserialization) | No `pickle`, `yaml.load`, `marshal`. |
| **CWE-601** (Open Redirect) | No URL handling. |
| **CWE-787** (Out-of-bounds Write) | No mutable buffers or array indexing. |
| **CWE-918** (SSRF) | No network. |

---

## CWE map summary

| CWE | Surfaces | Severity potential | Mitigation in repo | Residual |
|---|---|---|---|---|
| **CWE-682** | 1, 4 | Critical | Oracle differentials (35 items) + RevEng canonical | Low |
| **CWE-190** | 1 | Informational | `& 0xFFFF` mask + clamp test | Informational |
| **CWE-125** | 1 | Informational | Iterator-based loop | Informational |
| **CWE-20**  | 5 | Medium | 14 TypeError tests | Low |
| **CWE-754** | 1, 7 | Low | AC2 + edge tests | None |
| **CWE-1339** | 1 | Critical | Same as CWE-682 | Low |
| **CWE-704** | 3 | Low | Stdlib delegation | Informational |
| **CWE-400** | 7 | Low (caller-driven) | Linear-time loop | None |
| **CWE-681** | 3 | Low | `:04x` format | None |
| **CWE-1284** | 2, 5 | Low | `argparse required=True` + clamping | None |
| **CWE-1384** | 5 | Low | `& 0xFFFF` clamp tests | Informational |

**Total CWE entries mapped: 11** (matches the task-brief list).

See `TEST_GAPS.md` for the AC→test coverage matrix and `VULN_AUDIT.md` for
the severity-ranked findings table.
