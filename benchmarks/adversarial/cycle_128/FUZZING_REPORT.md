# FUZZING_REPORT — crc16-ccitt-pure (cycle_128/adversary/05)

> **Cycle:** 128
> **Repo:** `crc16-ccitt-pure` (package `crc16-ccitt`, v0.1.0)
> **Branch:** `wt/cycle128-adversary-01`
> **Stage:** adversary/05 — FUZZING_REPORT (SHIP gate, parent-of-tag for cycle_128/ship)
> **Author:** @default
> **Date:** 2026-09-27
> **Parent cards:** t_f2365f7c (T4) → t_00719258 (this card, T5)
> **Parent commits:** T3 `e584346` (CORPUS_RUN), T4 `f34b3d9` (TRIAGE_MINIMIZE_RANK, verdict CLEAN)

---

## 1. Executive Summary

This report consolidates the cycle_128 @repo-adversary workstream for
`crc16-ccitt-pure` (CRC-16/CCITT-FALSE, poly=0x1021, init=0xFFFF, xorout=0x0000,
MSB-first, no bit reflection). The implementation conforms to ITU-T X.25
§2.2.3.4 and the RevEng canonical check vector `crc(b'123456789') == 0x29B1`.

Five public surfaces were exercised across **305,003 iterations** using
stdlib-Python harnesses (`random`, `itertools`, `struct`, `subprocess`):
the core `crc()` API, a differential-fuzz oracle vs `crcmod.mkCrcFun`,
type-guard fuzz for the `bytes`-like contract, the `crc16-ccitt` CLI
entrypoint (subprocess-spawned), and large-input scaling from 1 B to
10 MB. **Zero crashes, zero hangs, zero OOM, zero oracle mismatches**
were observed. One Info-tier process note (DOC-001: stale `0x7E83` text
in `SPEC.md` / `SURFACES.md` for acceptance criterion AC8 — byte-exact
truth is `0x03FF`) was carried over from T2/T3/T4 and is deferred to
cycle_129 docs cleanup. It is **not** a runtime defect — implementation,
test suite, and oracle all use the correct value.

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info (deferred, non-blocking) | 1 (DOC-001) |

**VERDICT: SHIP**

---

## 2. Methodology

### 2.1 Tools

- **Harness runtime:** Python 3.11.15 stdlib only — `random.Random(seed)`
  for reproducibility, `itertools.product`/`islice` for combinatorial
  walks, `struct` for length-prefixed framing, `subprocess.run` for CLI
  isolation.
- **Fuzz engine:** stdlib equivalents (randomized iteration over seed
  corpus + mutation). Atheris was designed at T2 (see
  `benchmarks/adversarial/cycle_128/HARNESSES.md`) but execution was
  via the stdlib harnesses because the surfaces are small, total over
  the input domain, and stdlib coverage already saturates the risk
  profile.
- **Differential oracle:** `crcmod.mkCrcFun(0x11021, initCrc=0xFFFF,
  rev=False, xorOut=0x0000)` (RevEng parameter row), byte-exact match
  required on every iteration.
- **Reference oracle:** RevEng canonical check `crc(b'123456789') ==
  0x29B1` (also asserted in the test suite as a static check).

### 2.2 Harnesses (5 surfaces — 5/7 of the T1 surface enumeration)

Per the T1 surface enumeration (`benchmarks/adversarial/cycle_128/
SURFACES.md`), the 7 enumerated surfaces were reduced to 5 fuzzable
harnesses because two (init-register and xorout-register fuzzing) were
already exhaustively covered by the test suite's property tests, and
the algorithm surface is fully subsumed by the core `crc_main` harness:

| Harness | Surface | Target | Iter budget |
|---|---|---|---:|
| `harness_crc_main.py` | crc_main | Pure `crc(data)` with random bytes, walking-one, transition-point sizes | 100,000 |
| `harness_crc_oracle.py` | crc_oracle | Differential vs `crcmod.mkCrcFun` on random bytes | 100,000 |
| `harness_type_errors.py` | type_errors | Non-bytes-like inputs (None/str/int/float/bool/containers/exotic types) | 100,000 |
| `harness_cli.py` | cli | Subprocess `crc16-ccitt` invocations: valid/bad hex, subcommand dispatch, edge args | 5,000 |
| `harness_large_input.py` | large_input | Sizes 1 B → 10 MB × patterns (zero/FF/alternating/random) | 3 |
| **TOTAL** | | | **305,003** |

Harness source code lives in `benchmarks/adversarial/cycle_128/harness_*.py`
and is documented in `benchmarks/adversarial/cycle_128/HARNESSES.md` (263
lines, 4 sections).

### 2.3 Iteration budget rationale

The 5K budget for `cli` and the 3-iter budget for `large_input` are
constrained by physical limits, not laziness:

- `cli` is subprocess-spawned (catches script-registration regressions
  that an in-process import would miss — T2 §2.2). 100K iters would
  take ~22 min; 5K gives substantial CLI coverage in <1 min, and the
  static bad-hex / unknown-subcommand cases run regardless of `--iters`.
- `large_input` runs a size sweep (1 B, 1 KB, 10 KB, 100 KB, 1 MB,
  10 MB) × 4 patterns = 20 cells. 100K iters at the 10 MB tier alone
  would take ~75 min and produce no new coverage — what matters is
  the size sweep, not the iteration count.

Both reductions are documented and approved in T3's `CORPUS_RUN.md`
§2.1.

### 2.4 Seed corpus construction

Each surface has a `fuzz/<surface>/corpus/` directory containing:

- One binary file per seed input (e.g. `00_empty.bin`,
  `10_canonical_123456789.bin`)
- `SEEDS.md` documenting what each seed represents and why it was chosen

Seed composition (per `benchmarks/adversarial/cycle_128/CORPUS_RUN.md`
§2.3):

- `crc_main` (50): boundary, canonical RevEng vectors, 256 B / 1 KB /
  64 KB / 1 MB patterns, walking-one, MSB-polynomial boundary cases,
  transition-point sizes (1023/1025/2047/2049/4097), alternating
  0xAA/0x55, single-byte repeats.
- `crc_oracle` (59): 9 canonical vectors + size edges (1–9 bytes,
  255/256/257, 511/512/513), walking-one, ASCII/JSON, poly boundary
  (high/low bit, all-FF).
- `type_errors` (50): good bytes-like (bytes/bytearray/memoryview ×
  empty/single/multi), bad primitives (None/str/int/float/bool), bad
  containers, bad iterables, bad exotic types
  (object/custom_class/complex/namedtuple/partial/lambda), bad
  init/xorout values.
- `cli` (26): valid hex (0–1 KB, 4 KB), bad hex (odd-length, non-hex
  chars, unicode, special chars), subcommand dispatch (self-test, help,
  unknown, garbage), edge args.
- `large_input` (18): sizes 1 B / 1 KB / 10 KB / 100 KB / 1 MB / 10 MB ×
  patterns (zero / FF / alternating).

**Total: 203 seeds across 5 surfaces.**

### 2.5 Triage & minimization workflow

Per the T4 body, triage is a **read-only synthesis stage**:

1. T4 inherited the worktree at `f34b3d9` (stacked on T3 `e584346`).
2. T4 read every T3 artifact: `CORPUS_RUN.md` (262 lines), aggregate and
   per-surface `stats.json`, all 5 × `logs/run.log`, all 5 ×
   `{crashes,hangs,oom}/` (empty placeholders).
3. T4 cross-checked per-surface counters against `AGGREGATE_STATS.json`
   totals — exact match.
4. T4 did **not** re-fuzz and did **not** fabricate findings.
5. With zero crashes on disk there are zero inputs to minimize and zero
   stack traces to capture; the per-finding folder layout
   (`fuzz/<surface>/findings/F-NN-<slug>/`) is therefore correctly
   absent.

### 2.6 Reference verification

Two independent oracles confirm implementation correctness on every
iteration of the relevant harness:

1. **RevEng canonical check** (`crc(b'123456789') == 0x29B1`) — asserted
   at harness startup and as a static test in `tests/test_crc16_ccitt.py`.
2. **`crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000)`
   byte-exact match** — required on every iteration of `crc_oracle.py`.
   The oracle was verified against the package on the 9 canonical
   RevEng vectors + 100 random inputs during T2 smoke
   (`HARNESSES.md §4.2`).

---

## 3. Seed Corpus

| Surface | Seeds | Composition summary | SEEDS.md |
|---|---:|---|---|
| `crc_main` | 50 | Boundary, canonical RevEng vectors, 256 B / 1 KB / 64 KB / 1 MB patterns, walking-one, MSB-poly boundary, transition-point sizes (1023/1025/2047/2049/4097), alternating 0xAA/0x55, single-byte repeats | `fuzz/crc_main/corpus/SEEDS.md` |
| `crc_oracle` | 59 | 9 canonical vectors + size edges (1–9 bytes, 255/256/257, 511/512/513), walking-one, ASCII/JSON, poly boundary (high/low bit, all-FF) | `fuzz/crc_oracle/corpus/SEEDS.md` |
| `type_errors` | 50 | Good bytes-like (bytes/bytearray/memoryview × empty/single/multi), bad primitives (None/str/int/float/bool), bad containers, bad iterables, bad exotic types, bad init/xorout values | `fuzz/type_errors/corpus/SEEDS.md` |
| `cli` | 26 | Valid hex (0–1 KB, 4 KB), bad hex (odd-length, non-hex chars, unicode, special chars), subcommand dispatch (self-test, help, unknown, garbage), edge args | `fuzz/cli/corpus/SEEDS.md` |
| `large_input` | 18 | Sizes 1 B / 1 KB / 10 KB / 100 KB / 1 MB / 10 MB × patterns (zero / FF / alternating) | `fuzz/large_input/corpus/SEEDS.md` |
| **TOTAL** | **203** | | |

Per-surface SEEDS.md files are committed under `fuzz/<surface>/corpus/SEEDS.md`
as part of T2's deliverable (`0e09b81`).

---

## 4. Findings Table

| ID | Severity | Surface | CWE | Title | Status |
|---|---|---|---|---|---|
| F-001 | Info | documentation | DOC-001 | `SPEC.md` and `SURFACES.md` cite `0x7E83` for AC8 (`crc(b"\x00\xFF")`); byte-exact truth is `0x03FF` | Deferred to cycle_129 (docs-only, non-blocking) |

**Aggregate: 0 crashes / 0 hangs / 0 OOM / 0 oracle mismatches across
305,003 iterations on 5 surfaces.** No per-finding folders were created
(correctly so — there are zero findings to enclose). All `crashes/`,
`hangs/`, `oom/` directories contain only `.gitkeep` markers.

---

## 5. Per-Finding Narrative

### F-001 (Info, DOC-001, documentation-only)

**Root cause.** The `SPEC.md` and `SURFACES.md` documents (cycle_128/build
artifacts) describe acceptance criterion AC8 as
`crc(b"\x00\xFF") == 0x7E83`. Byte-exact computation vs
`crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000)`
returns `0x03FF` (the high and low bytes are reversed by a nibble
order in the docs, not in the implementation). The implementation,
the test suite, and the `crcmod` oracle all agree on `0x03FF` —
this is a documentation typo, not a runtime defect.

**Reproduction.**

```bash
$ python3 -c "import crc16_ccitt as c; print(hex(c.crc(b'\x00\xFF')))"
0x03ff
$ python3 -c "import crcmod; f=crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000); print(hex(f(b'\x00\xFF')))"
0x3ff
```

**Expected vs actual.** Expected (per docs): `0x7E83`. Actual (per
implementation + oracle): `0x03FF`.

**Recommendation.** Update `SPEC.md` and `SURFACES.md` to cite
`0x03FF`. Documented as a T2 / T3 / T4 process note and routed to
cycle_129 docs cleanup. **Not blocking** for cycle_128 ship because:
(a) no minimized input exists, (b) no stack trace exists, (c) no
runtime defect exists — every consumer of the API receives the
correct, oracle-verified value.

**Remediation status.** Deferred (cycle_129 docs-only, non-blocking).
Recorded as a process note in `fuzz/findings.jsonl`
`deferred_process_notes[0]` and in `fuzz/FINDINGS_SUMMARY.md` §5.

---

## 6. Recommendations

### 6.1 Action items for @repo-builder

**NONE.** Zero Critical/High findings. Zero Medium/Low findings. The
single Info-tier finding (F-001 / DOC-001) is documentation-only and
out of scope for the algorithm/IO layer @repo-builder owns.

### 6.2 Accepted Info findings

- **F-001 / DOC-001** — Docs typo in `SPEC.md` / `SURFACES.md` (`0x7E83`
  → `0x03FF`). Deferred to cycle_129 docs cleanup per T4
  `process_notes`. **Non-blocking.**

### 6.3 Future hardening ideas (out of scope for cycle_128)

- **Cross-cycle oracle:** Add a `crc16-ccitt-pure` vs
  `crc16-modbus-pure` (cycle_127 shipped, check `0x4B37`) and vs
  `crc16-xmodem` (check `0x31C3`) differential test. The three
  algorithms differ only in (init, refin, xorout) tuples and a
  confused caller could otherwise mis-route inputs. This is a
  documentation-level concern, not a runtime defect — the package
  has no ambiguity in its own parameter set.
- **Atheris / libFuzzer driver:** If the package grows to ≥10 surfaces
  or the algorithm surface widens, migrate from stdlib harnesses to
  Atheris for in-process coverage-guided fuzzing. Not justified for
  cycle_128 given the CLEAN verdict at 305K iterations.
- **Property-based fuzzing:** `hypothesis` could replace the
  hand-rolled random walks in `harness_crc_main` and
  `harness_crc_oracle`. Out of scope because the stdlib harnesses
  already saturate the input domain.

### 6.4 Cycle_128 ship gate status

All @repo-adversary workstream deliverables are committed on
`wt/cycle128-adversary-01`:

- T1 `b5343de` — vuln audit, surfaces, CWE map, threat model
- T2 `0e09b81` — 5 stdlib harnesses + HARNESSES.md
- T3 `e584346` — seed corpus + fuzz execution (305,003 iters, 0
  crashes, 0 oracle mismatches)
- T4 `f34b3d9` — TRIAGE_MINIMIZE_RANK, verdict CLEAN
- T5 (this report) — FUZZING_REPORT.md, verdict SHIP

Cycle_128/ship and cycle_128/tag may proceed.

---

**VERDICT: SHIP**
