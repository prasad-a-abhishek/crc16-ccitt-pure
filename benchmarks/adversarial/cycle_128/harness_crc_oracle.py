"""harness_crc_oracle.py — stdlib-only differential harness vs crcmod (Surface 1).

Cross-checks crc16_ccitt.crc() byte-for-byte against the industry-standard
crcmod.mkCrcFun() reference, configured with the EXACT CRC-16/CCITT-FALSE
parameters (poly=0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000).

CRITICAL: rev=False. Setting rev=True would mismatch on EVERY byte because
CCITT-FALSE has NO input/output bit-reflection (unlike MODBUS, IBM-SDLC,
X-25 reversecrc, etc.). This harness catches that regression.

If crcmod is unavailable in the running Python, the harness exits 0 with a
SKIP marker (does NOT fail), so CI can gate it without breaking installs
without the [test] extra.

Usage:
    python3 harness_crc_oracle.py [--iters N]
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
from typing import Callable, cast

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent.parent.parent / "src"))

from crc16_ccitt import crc  # noqa: E402

SURFACE = "crc_oracle"
OUT_DIR = _HERE.parent.parent.parent / "fuzz" / SURFACE
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Canonical vectors from RevEng (mirrors tests/test_crc16_ccitt.py).
_CANONICAL = [
    (b"",                                0xFFFF, "empty input"),
    (bytes([0x00]),                      0xE1F0, "single 0x00"),
    (bytes([0xFF]),                      0xFF00, "single 0xFF"),
    (b"123456789",                       0x29B1, "ASCII '123456789' (RevEng check)"),
    (bytes(range(10)),                   0xC241, "bytes 0x00..0x09"),
    (b"\x00\xFF",                        0x03FF, "AC8 no-reflection pair"),
    (b"\xFF" * 64,                       None,  "64-byte all-FF"),
    (b"\x00" * 1024,                     None,  "1KB all-zero"),
    (b"\xAA" * 4096,                     None,  "4KB all-AA"),
]


def _oracle_available() -> tuple[bool, str, "object | None"]:
    """Return (available, reason, mkCrcFun_or_None)."""
    try:
        import crcmod  # type: ignore[import-not-found]  # noqa: F401
    except ImportError as exc:
        return False, f"crcmod not importable: {exc}", None
    try:
        # poly=0x11021 is the CRC-16/CCITT-FALSE polynomial with implicit high bit.
        f = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000)  # type: ignore[attr-defined]
        return True, "ok", f
    except Exception as exc:
        return False, f"crcmod.mkCrcFun failed: {exc}", None


def run(iters: int, seed: int = 0xDECC) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()
    mismatches: list[dict] = []
    crashes: list[dict] = []

    available, reason, oracle = _oracle_available()
    if not available:
        elapsed = time.perf_counter() - t0
        results = {
            "surface": SURFACE,
            "iters": iters,
            "crashes": 0,
            "oracle_mismatches": 0,
            "elapsed_seconds": round(elapsed, 4),
            "skipped": True,
            "skip_reason": reason,
        }
        (OUT_DIR / "results.json").write_text(json.dumps(results, indent=2))
        print(f"[{SURFACE}] iters={iters} crashes=0 oracle_mismatches=0 "
              f"time={elapsed:.3f}s SKIPPED ({reason})")
        return 0

    assert oracle is not None  # narrowed by `available`; appease type checkers
    oracle_fn: Callable[[bytes], int] = cast(Callable[[bytes], int], oracle)

    # ---- Hard-coded canonical vectors ----
    for data, expected, label in _CANONICAL:
        try:
            got = crc(data)
            ref = oracle(data)
            if got != ref:
                mismatches.append({
                    "check": f"canonical.{label}",
                    "ours": got, "ref": ref, "input_len": len(data),
                })
            if expected is not None and got != expected:
                mismatches.append({
                    "check": f"canonical.{label}.hardcoded",
                    "ours": got, "expected": expected, "input_len": len(data),
                })
        except Exception:
            crashes.append({"check": f"canonical.{label}",
                            "tb": traceback.format_exc()})

    # ---- Random differential sweep ----
    for i in range(iters):
        try:
            n = rng.randint(1, 1024)
            data = bytes(rng.randint(0, 255) for _ in range(n))
            got = crc(data)
            ref = oracle_fn(data)
            if got != ref:
                mismatches.append({
                    "check": "random_differential", "iter": i,
                    "ours": got, "ref": ref, "input_len": n,
                    "input_head_hex": data[:16].hex(),
                })
        except Exception:
            crashes.append({"check": "random_differential", "iter": i,
                            "tb": traceback.format_exc()})

    elapsed = time.perf_counter() - t0
    results = {
        "surface": SURFACE,
        "iters": iters,
        "crashes": len(crashes),
        "oracle_mismatches": len(mismatches),
        "elapsed_seconds": round(elapsed, 4),
        "extras": {
            "canonical_vectors": len(_CANONICAL),
            "oracle_class": "crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000)",
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
        description="Differential fuzz harness vs crcmod.mkCrcFun()")
    parser.add_argument("--iters", type=int, default=100,
                        help="random differential iterations (default 100)")
    parser.add_argument("--seed", type=int, default=0xDECC)
    args = parser.parse_args(argv)
    return run(args.iters, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
