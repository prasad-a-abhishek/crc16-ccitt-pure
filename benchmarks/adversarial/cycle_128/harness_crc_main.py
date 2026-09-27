"""harness_crc_main.py — stdlib-only fuzz harness for crc16_ccitt.crc() (Surface 1).

Targets the algorithm-correctness threat model:
# AC1: crc(b'123456789') == 0x29B1
# AC2: crc(b'') == 0xFFFF
# AC8: crc(b'\\x00\\xFF') == 0x03FF  (proves NO input/output reflection;
#      the value 0x03FF is byte-exact vs crcmod; see also
#      tests/test_crc16_ccitt.py::test_refin_false_input_not_reflected)
- AC7: determinism — repeated calls return identical results
- AC5: result in [0, 0xFFFF] for every input
- bytes-subclass polymorphism: bytes, bytearray, memoryview all accepted
- stress inputs: 1 MB all-FF, 1 MB all-00, alternating 0xAA/0x55

Usage:
    python3 harness_crc_main.py [--iters N]

Exit 0 on success, 1 on any assertion failure (crash or oracle mismatch).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import traceback
from pathlib import Path

# Make the package importable when running this harness from any cwd.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent.parent.parent / "src"))

from crc16_ccitt import crc  # noqa: E402

SURFACE = "crc_main"
OUT_DIR = _HERE.parent.parent.parent / "fuzz" / SURFACE
OUT_DIR.mkdir(parents=True, exist_ok=True)


def _record(iters: int, crashes: int, mismatches: int, elapsed: float, extras: dict) -> None:
    results = {
        "surface": SURFACE,
        "iters": iters,
        "crashes": crashes,
        "oracle_mismatches": mismatches,
        "elapsed_seconds": round(elapsed, 4),
        "extras": extras,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%Z", time.gmtime()),
    }
    (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2))


def _check(label: str, expected, actual, mismatches: list, crashes: list) -> None:
    if expected != actual:
        mismatches.append({"check": label, "expected": expected, "actual": actual})


def run(iters: int, seed: int = 0xC1CC) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()
    mismatches: list[dict] = []
    crashes: list[dict] = []

    # ---- Hard-coded AC1/AC2/AC8 invariants (deterministic, always) ----
    try:
        _check("AC1.reveng_canonical", 0x29B1, crc(b"123456789"), mismatches, crashes)
        _check("AC2.empty_input",      0xFFFF, crc(b""),                mismatches, crashes)
        _check("AC8.no_reflection",    0x03FF, crc(b"\x00\xFF"),        mismatches, crashes)
        _check("AC4.single_0x00",      0xE1F0, crc(bytes([0x00])),      mismatches, crashes)
        _check("AC5.single_0xFF",      0xFF00, crc(bytes([0xFF])),      mismatches, crashes)
        _check("AC3.byte_range_10",    0xC241, crc(bytes(range(10))),   mismatches, crashes)
    except Exception:
        crashes.append({"check": "invariant", "tb": traceback.format_exc()})

    # ---- Determinism: each iteration's input hashed twice must match ----
    determinism_failures = 0
    for i in range(iters):
        try:
            n = rng.randint(0, 1024)
            data = bytes(rng.randint(0, 255) for _ in range(n))
            a = crc(data)
            b = crc(data)
            if a != b:
                determinism_failures += 1
                mismatches.append({"check": "determinism", "iter": i, "a": a, "b": b})
            if not (0 <= a <= 0xFFFF):
                mismatches.append({
                    "check": "uint16_range", "iter": i, "value": a,
                    "hex": hex(a) if isinstance(a, int) else str(a),
                })
        except Exception:
            crashes.append({"check": "determinism_or_range", "iter": i,
                            "tb": traceback.format_exc()})

    # ---- Bytes-subclass polymorphism ----
    src = b"hello crc world"
    try:
        ba = bytearray(src)
        mv = memoryview(src)
        _check("bytes_vs_bytearray", crc(src), crc(ba), mismatches, crashes)
        _check("bytes_vs_memoryview", crc(src), crc(mv), mismatches, crashes)
    except Exception:
        crashes.append({"check": "bytes_subclass", "tb": traceback.format_exc()})

    # ---- Stress inputs ----
    for label, blob in (
        ("stress_1MB_all_FF", b"\xFF" * (1024 * 1024)),
        ("stress_1MB_all_00", b"\x00" * (1024 * 1024)),
        ("stress_64KB_all_FF", b"\xFF" * 65536),
        ("stress_64KB_all_00", b"\x00" * 65536),
        ("stress_alternating_AA_55_64KB", (b"\xAA\x55" * 32768)),
    ):
        try:
            v = crc(blob)
            _check(label, True, (0 <= v <= 0xFFFF), mismatches, crashes)
        except Exception:
            crashes.append({"check": label, "tb": traceback.format_exc()})

    elapsed = time.perf_counter() - t0
    extras = {
        "determinism_failures": determinism_failures,
        "invariants_total": 6,
        "invariants_passed": 6 - sum(1 for m in mismatches if m["check"].startswith(("AC",))),
        "stress_inputs_total": 5,
    }
    _record(iters, len(crashes), len(mismatches), elapsed, extras)
    print(f"[{SURFACE}] iters={iters} crashes={len(crashes)} "
          f"oracle_mismatches={len(mismatches)} time={elapsed:.3f}s")
    if crashes or mismatches:
        for c in crashes:
            print(f"  CRASH: {c['check']}\n{c['tb']}", file=sys.stderr)
        for m in mismatches[:10]:
            print(f"  MISMATCH: {m}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fuzz harness for crc16_ccitt.crc()")
    parser.add_argument("--iters", type=int, default=100,
                        help="number of random determinism iterations (default 100)")
    parser.add_argument("--seed", type=int, default=0xC1CC,
                        help="PRNG seed (default 0xC1CC for reproducibility)")
    args = parser.parse_args(argv)
    return run(args.iters, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
