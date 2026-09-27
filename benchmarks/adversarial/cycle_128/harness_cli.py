"""harness_cli.py — stdlib-only CLI subprocess harness (Surfaces 2 + 3 + 4).

Exercises every CLI entrypoint by spawning fresh Python subprocesses
(`python -m crc16_ccitt ...`). This catches:
- regressions where the module no longer starts (Surface 2 dispatcher)
- regressions in the `compute --data HEXSTR` path (Surface 3)
- regressions in the `self-test` trust anchor (Surface 4)

The subprocess boundary is intentional: a harness that imports the
package directly cannot catch PYTHONPATH/PYTHONHOME/script-registration
problems. Running through `python -m` matches what real users do.

Usage:
    python3 harness_cli.py [--iters N]
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_WORKTREE = _HERE.parent.parent.parent  # /.../.worktrees/t_cycle128-adversary-01

SURFACE = "cli"
OUT_DIR = _HERE.parent.parent.parent / "fuzz" / SURFACE
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Use the worktree's installed-package venv (created during cycle_128/build).
# Falls back to `python3 -m` from the system interpreter if VENV_PYTHON unset.
DEFAULT_VENV = "/tmp/v_cycle128_harness/bin/python"
VENV_PYTHON = os.environ.get("HERMES_HARNESS_PYTHON", DEFAULT_VENV)

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{4}$")

# RevEng canonical check value the self-test must reach.
_SELF_TEST_MUST_CONTAIN = "0x29b1"


def _run_module(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [VENV_PYTHON, "-m", "crc16_ccitt", *args],
        capture_output=True, text=True, timeout=timeout,
    )


def run(iters: int, seed: int = 0xC11) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()
    mismatches: list[dict] = []
    crashes: list[dict] = []

    # ---- 1. Module import via subprocess (Surface 2 cold-start) ----
    try:
        proc = _run_module()  # no args → self-test by default
        if proc.returncode != 0:
            crashes.append({
                "check": "module_cold_start", "returncode": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr,
            })
        elif "PASS" not in proc.stdout:
            mismatches.append({
                "check": "module_cold_start.no_pass_marker",
                "stdout_head": proc.stdout[:400],
            })
        if _SELF_TEST_MUST_CONTAIN not in proc.stdout.lower():
            mismatches.append({
                "check": "module_cold_start.no_canonical_value",
                "stdout_head": proc.stdout[:400],
            })
    except Exception:
        crashes.append({"check": "module_cold_start",
                        "tb": traceback.format_exc()})

    # ---- 2. self-test explicit subcommand (Surface 4) ----
    try:
        proc = _run_module("self-test")
        if proc.returncode != 0:
            crashes.append({
                "check": "self_test_subcmd", "returncode": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr,
            })
        if "All 6 RevEng vectors PASS" not in proc.stdout:
            mismatches.append({
                "check": "self_test_subcmd.no_pass_summary",
                "stdout_head": proc.stdout[:400],
            })
    except Exception:
        crashes.append({"check": "self_test_subcmd",
                        "tb": traceback.format_exc()})

    # ---- 3. compute subcommand — canonical vector (Surface 3) ----
    try:
        proc = _run_module("compute", "--data", "313233343536373839")
        if proc.returncode != 0:
            crashes.append({
                "check": "compute_canonical", "returncode": proc.returncode,
                "stdout": proc.stdout, "stderr": proc.stderr,
            })
        elif proc.stdout.strip() != "0x29b1":
            mismatches.append({
                "check": "compute_canonical.output",
                "expected": "0x29b1", "actual": proc.stdout.strip(),
            })
    except Exception:
        crashes.append({"check": "compute_canonical",
                        "tb": traceback.format_exc()})

    # ---- 4. Random compute fuzz (Surface 3) ----
    for i in range(iters):
        try:
            n = rng.randint(0, 64)
            data = bytes(rng.randint(0, 255) for _ in range(n))
            hexstr = data.hex()
            proc = _run_module("compute", "--data", hexstr)
            if proc.returncode != 0:
                crashes.append({
                    "check": "compute_random", "iter": i,
                    "returncode": proc.returncode,
                    "stderr": proc.stderr[:200],
                })
                continue
            out = proc.stdout.strip()
            if not _HEX_RE.match(out):
                mismatches.append({
                    "check": "compute_random.format", "iter": i,
                    "output": out,
                })
            else:
                value = int(out, 16)
                if not (0 <= value <= 0xFFFF):
                    mismatches.append({
                        "check": "compute_random.range", "iter": i,
                        "value": value,
                    })
        except subprocess.TimeoutExpired:
            crashes.append({
                "check": "compute_random", "iter": i,
                "kind": "timeout",
            })
        except Exception:
            crashes.append({"check": "compute_random", "iter": i,
                            "tb": traceback.format_exc()})

    # ---- 5. Bad-hex inputs must exit 2 (Surface 3 input validation) ----
    for label, bad_hex in (
        ("odd_length",  "123"),         # 3 chars → odd length
        ("bad_char",    "zz"),          # not hex
        ("empty",       ""),            # empty hex → b"" → 0xFFFF (still valid)
    ):
        try:
            proc = _run_module("compute", "--data", bad_hex)
            if label == "empty":
                # Empty input is valid (computes 0xFFFF) — should exit 0.
                if proc.returncode != 0:
                    crashes.append({
                        "check": f"compute_bad.{label}",
                        "expected_rc": 0, "actual_rc": proc.returncode,
                        "stderr": proc.stderr[:200],
                    })
            else:
                # Bad hex should produce exit code 2 (per cli.py:64).
                if proc.returncode != 2:
                    mismatches.append({
                        "check": f"compute_bad.{label}.exit_code",
                        "expected": 2, "actual": proc.returncode,
                        "stderr": proc.stderr[:200],
                    })
        except Exception:
            crashes.append({"check": f"compute_bad.{label}",
                            "tb": traceback.format_exc()})

    # ---- 6. Unknown subcommand exits 2 (Surface 2 dispatcher) ----
    try:
        proc = _run_module("not-a-real-subcommand")
        if proc.returncode != 2:
            mismatches.append({
                "check": "unknown_subcommand.exit_code",
                "expected": 2, "actual": proc.returncode,
                "stderr": proc.stderr[:200],
            })
    except Exception:
        crashes.append({"check": "unknown_subcommand",
                        "tb": traceback.format_exc()})

    # ---- 7. -h / --help exits 0 (Surface 2) ----
    for flag in ("-h", "--help"):
        try:
            proc = _run_module(flag)
            if proc.returncode != 0:
                crashes.append({
                    "check": f"help.{flag}", "returncode": proc.returncode,
                    "stderr": proc.stderr[:200],
                })
        except Exception:
            crashes.append({"check": f"help.{flag}",
                            "tb": traceback.format_exc()})

    elapsed = time.perf_counter() - t0
    results = {
        "surface": SURFACE,
        "iters": iters,
        "crashes": len(crashes),
        "oracle_mismatches": len(mismatches),
        "elapsed_seconds": round(elapsed, 4),
        "extras": {
            "venv_python": VENV_PYTHON,
            "worktree": str(_WORKTREE),
        },
    }
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2))

    print(f"[{SURFACE}] iters={iters} crashes={len(crashes)} "
          f"oracle_mismatches={len(mismatches)} time={elapsed:.3f}s")
    if crashes or mismatches:
        for c in crashes[:5]:
            print(f"  CRASH: {c}", file=sys.stderr)
        for m in mismatches[:10]:
            print(f"  MISMATCH: {m}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CLI subprocess fuzz harness (covers python -m dispatcher, compute, self-test)")
    parser.add_argument("--iters", type=int, default=100,
                        help="random compute iterations (default 100)")
    parser.add_argument("--seed", type=int, default=0xC11)
    args = parser.parse_args(argv)
    return run(args.iters, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
