# Threat Model — crc16-ccitt (cycle_128)

> Per-surface attack narratives. Each section: who would attack this surface,
> how, what they'd achieve, what stops them. One paragraph per surface — the
> brief asked for concise threat narratives, not a verbose re-statement of
> CWE_MAP.

## Surface 1 — `crc(data, init, xorout)`

**Attacker:** an adversary who wants a downstream consumer (an HDLC framer,
an AX.25 parser, or a Bluetooth-paging decoder) to silently emit or accept
*wrong* CRCs without the legitimate maintainer noticing.

**How:** either (a) submit a typo'd "performance optimisation" PR that flips
`refin` from `False` to `True` (turning CCITT-FALSE into the SDLC variant,
which still returns valid 16-bit values), or (b) submit a PR that replaces
the bit-by-bit loop with a hard-coded lookup table whose entries are wrong
for one or more byte values (off-by-one in the table index would shift the
output by exactly one bit position, surviving 99% of regression tests).

**Achieves:** every CRC this package emits would be the SDLC variant's CRC
for the same input. The check `crc(b"123456789") == 0x29B1` would still
pass (because SDLC also yields 0x29B1 for that input? — actually no: SDLC
yields 0x906B; flipping `refin=true` would break the canonical check). So
this attack is *detectable* by AC1. The risk is *not* a silent failure;
it's a loud failure caught at PR review time.

**What stops them:** three independent oracle tests (RevEng canonical
`0x29B1`, 25-item random differential vs `crcmod`, 10-pattern fuzz vs
`crcmod`) catch any algorithm mutation that doesn't happen to also flip
`crcmod`'s matching flag. A parameter-only mutation is impossible to miss.

## Surface 2 — `python -m crc16_ccitt` module entrypoint

**Attacker:** an end-user who wants to invoke the wrong subcommand by
accident — e.g. types `python -m crc16_ccitt --data XX` and gets
`unknown subcommand: '--data'` instead of the compute path.

**How:** call the module with a flag, watch argparse error out.

**Achieves:** inconvenience. A confused user sees a confusing error and
may mistakenly believe the package is broken. This is *not* a security
vulnerability; it's a UX defect. **Severity: Info.**

**What stops it:** the module is interactive-only (no library code under
`crc16_ccitt.cli.main()` is invoked unless the user calls it explicitly);
no exploit. A follow-up patch that adds `--data` as a top-level flag (not
gated under `compute`) would close the gap, but it's a cosmetic fix.

## Surface 3 — `crc16-ccitt-pure-compute` console script

**Attacker:** an operator who feeds a malformed hex string to a CI pipeline
that calls this script.

**How:** supply `--data "ZZ"` (non-hex) or `--data "0"` (odd length).

**Achieves:** a non-zero exit code (`2`) and an error message on stderr.
Neither is a security failure — both are correct stdlib-validated
failures (`bytes.fromhex` raises, CLI catches and re-raises with a
contextual message). The script:
- cannot read or write files (no `--file`, no `--output`)
- cannot spawn subprocesses (no `subprocess`)
- cannot reach the network (no `urllib`, `requests`, `socket`)
- cannot leak process state (stdout-only output, no `--verbose` mode)

**What stops them:** the script has only one input (`--data`), one output
(`0xXXXX`), and one failure mode (`ValueError` → exit 2). The blast radius
of any input is bounded to "wrong CRC value computed" — which is exactly
what the script is for.

## Surface 4 — `crc16-ccitt-pure-self-test` console script

**Attacker:** an integrator who installs the package and wants confidence
*before* integrating it that the implementation matches the spec.

**How:** run `crc16-ccitt-pure-self-test`, look at the output.

**Achieves:** confidence. If all 6 vectors `[PASS]`, the implementation
agrees with RevEng on every parameter (init=0xFFFF, poly=0x1021,
refin=false, refout=false, xorout=0x0000). If any `[FAIL]`, the binary is
broken in a way that *cannot be quiet* — the script exits non-zero.

**What stops abuse:** nothing to abuse. The script is read-only (no
inputs, no flags other than `-h`), runs in <1ms on commodity hardware,
and exits 0 or 1. **This is the strongest trust anchor in the package.**

## Surface 5 — `TypeError` guard layer

**Attacker:** a Python caller who passes the wrong type by accident (e.g.
a JSON-decoded `str` from a REST API, where they expected `bytes`).

**How:** call `crc(json_payload)` where `json_payload` is a `str`.

**Achieves:** an immediate `TypeError` with the message
`crc() expected bytes-like, got str`. The exception is uncaught inside
`crc()` (no `try/except`), so it propagates to the caller. This is the
*desired* behaviour per SPEC §3 AC12 — fail loud, not silent.

**What stops a malicious bypass:** the guard is at the top of `crc()`
(lines 65-68), *before* any mutable state. An attacker who patches the
guard out of the source code would have to ship a malicious fork — which
defeats the purpose of using a public package. There is no flag, no
environment variable, no compile-time switch to disable the guard.

**Residual:** a malicious *internal* contributor (with commit access) who
removes the `isinstance` check would break AC12. The 14 TypeError tests
(`TestTypeErrorSafety` category) would fail in CI. This is caught at PR
review time, not by the library at runtime.

## Surface 6 — `__version__` + `__all__`

**Attacker:** none realistic. `__version__ = "0.1.0"` is a frozen string;
mutating it has no security impact (a downstream consumer that pins to
`"0.1.0"` and runs in a different process cannot observe an in-memory
mutation). `__all__ = ["crc", "__version__"]` restricts
`from crc16_ccitt import *` to two symbols; even if a future contributor
adds `_helper_a, _helper_b` without exporting them, `import *` won't
expose them.

**What stops abuse:** the surface is too small to abuse.

## Surface 7 — Memory/CPU bound

**Attacker:** a denial-of-service adversary who calls `crc()` with a
very large input (1 GB `bytes` object) in a tight loop.

**How:** allocate a 1 GB buffer, call `crc(buffer)`. Wait ~30-60 seconds.
Repeat.

**Achieves:** GIL-held CPU time on a single Python thread for ~1 minute per
1 GB. Not exploitable across the network (no network surface), so the
attacker must be local code. Per SPEC §6, the caller is responsible for
chunked streaming — the library exposes `init` precisely *because*
multi-block streaming is the caller's job (not the library's).

**What stops an external attacker:** there is no external surface. The
only "external" surface is the CLI, which is single-shot (no `--stream`,
no `--pipe`, no `--repeat`). Forcing the CLI to consume 1 GB would require
putting 1 GB on the command line (which most shells reject at ~128 KB of
argv), so the CLI attack vector caps at a few hundred KB per invocation.

---

## Threat model summary

| Surface | Realistic threat? | Highest severity | Net judgement |
|---|---|---|---|
| 1 — `crc()` algorithm | Yes (silent mutation in a future PR) | Critical | Mitigated by 3 independent oracles |
| 2 — `python -m crc16_ccitt` | UX defect only | Info | No security risk |
| 3 — `compute` CLI | Operator error | Low | Fail-loud on bad input |
| 4 — `self-test` CLI | None (read-only) | None | Trust anchor |
| 5 — `TypeError` guards | Caller mistake | Low | 14 explicit tests |
| 6 — `__version__`/`__all__` | None | None | Too small to attack |
| 7 — Large-input bound | Local DoS only | Info (caller-driven) | SPEC §6 documents |

**No surface is exploitable by an unprivileged remote attacker.**
**No surface enables privilege escalation, file disclosure, or code execution.**
**The single real risk is a future-contributor algorithm mutation** — and
that risk is locked down by three independent oracle tests.

See `VULN_AUDIT.md` for the severity-ranked findings table and final verdict.
