"""harness_large_input.py — stdlib-only scaling harness (Surface 7).

SPEC §6 declares the implementation O(N) time, O(1) memory. The package
is NOT optimized for speed but MUST handle large inputs without crashing,
hanging, or returning values outside [0, 0xFFFF].

This harness sweeps input sizes from 1 B to 10 MB and asserts:
- crc() never raises (any exception is a crash)
- result is always in [0, 0xFFFF] (no overflow leak)
- result is a Python int (never float / NaN / inf)
- runtime is roughly linear (sanity-bound via ratio check)

It also sweeps across input patterns (all-00, all-FF, alternating, random)
because pathological patterns can stress the polynomial division.

Usage:
    python3 harness_large_input.py [--iters N]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent.parent.parent / "src"))

from crc16_ccitt import crc  # noqa: E402

SURFACE = "large_input"
OUT_DIR = _HERE.parent.parent.parent / "fuzz" / SURFACE
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Sizes in bytes. 10 MB chosen as the upper bound to match SPEC §6 (the
# implementation "is acceptable for a single call on commodity hardware").
SIZES: list[int] = [1, 1000, 100_000, 1_000_000, 10_000_000]


def _measure(label: str, data: bytes, iters: int,
             mismatches: list, crashes: list) -> tuple[int, float]:
    """Run crc(data) `iters` times and return (value, mean_ms)."""
    durations: list[float] = []
    value: int | None = None
    for i in range(iters):
        t0 = time.perf_counter()
        try:
            v = crc(data)
        except Exception:
            crashes.append({"check": label, "iter": i,
                            "tb": traceback.format_exc()})
            continue
        durations.append((time.perf_counter() - t0) * 1000.0)
        if value is None:
            value = v
        # Validate each call.
        if not isinstance(v, int) or isinstance(v, bool):
            crashes.append({
                "check": f"{label}.return_type", "iter": i,
                "actual_type": type(v).__name__, "value": repr(v)[:200],
            })
        elif not (0 <= v <= 0xFFFF):
            crashes.append({
                "check": f"{label}.uint16_range", "iter": i,
                "value": v, "hex": hex(v),
            })

    if value is None:
        return 0, 0.0
    if durations:
        mean_ms = sum(durations) / len(durations)
    else:
        mean_ms = 0.0
    return value, mean_ms


def run(iters: int, seed: int = 0xB16) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()
    mismatches: list[dict] = []
    crashes: list[dict] = []
    timings: list[dict] = []

    # The 10 MB case is single-shot expensive (~30s on commodity hardware),
    # so we use `iters=1` for sizes ≥1 MB.
    def _iters_for(n: int) -> int:
        return 1 if n >= 1_000_000 else iters

    for n in SIZES:
        # Generate pattern variants for each size.
        patterns = {
            "all_00": b"\x00" * n,
            "all_FF": b"\xFF" * n,
            "alternating_AA_55": (b"\xAA\x55" * ((n // 2) + 1))[:n],
            "random": bytes(rng.randint(0, 255) for _ in range(n)),
        }
        for label, data in patterns.items():
            try:
                value, mean_ms = _measure(
                    f"size_{n}.{label}", data, _iters_for(n),
                    mismatches, crashes,
                )
                timings.append({
                    "size_bytes": n, "pattern": label,
                    "value": f"0x{value:04x}", "mean_ms": round(mean_ms, 4),
                })
            except Exception:
                crashes.append({
                    "check": f"size_{n}.{label}",
                    "tb": traceback.format_exc(),
                })

    # ---- Linear-scaling sanity check ----
    # 1000x size should NOT be >> 1000x time. Allow 20x slack to absorb GC
    # jitter and small-block overhead.
    try:
        small_times = {t["pattern"]: t["mean_ms"]
                       for t in timings if t["size_bytes"] == 1000}
        big_times = {t["pattern"]: t["mean_ms"]
                     for t in timings if t["size_bytes"] == 1_000_000}
        for pattern in small_times:
            if pattern not in big_times:
                continue
            ratio = big_times[pattern] / max(small_times[pattern], 1e-9)
            # Expected ratio ≈ 1000 (1MB / 1KB). Allow 50x slack.
            if ratio > 1000 * 50:
                mismatches.append({
                    "check": "linear_scaling",
                    "pattern": pattern,
                    "small_ms": small_times[pattern],
                    "big_ms": big_times[pattern],
                    "ratio": round(ratio, 1),
                })
    except Exception:
        crashes.append({"check": "linear_scaling",
                        "tb": traceback.format_exc()})

    elapsed = time.perf_counter() - t0
    results = {
        "surface": SURFACE,
        "iters": iters,
        "crashes": len(crashes),
        "oracle_mismatches": len(mismatches),
        "elapsed_seconds": round(elapsed, 4),
        "extras": {
            "sizes": SIZES,
            "patterns_per_size": 4,
            "timings": timings,
        },
    }
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2))

    print(f"[{SURFACE}] iters={iters} crashes={len(crashes)} "
          f"oracle_mismatches={len(mismatches)} time={elapsed:.3f}s")
    if crashes or mismatches:
        for c in crashes[:3]:
            print(f"  CRASH: {c['check']}\n{c['tb']}", file=sys.stderr)
        for m in mismatches[:10]:
            print(f"  MISMATCH: {m}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Large-input scaling harness for crc()")
    parser.add_argument("--iters", type=int, default=3,
                        help="repeat count per (size, pattern) below 1 MB "
                             "(default 3; ≥1 MB always single-shot)")
    parser.add_argument("--seed", type=int, default=0xB16)
    args = parser.parse_args(argv)
    return run(args.iters, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
