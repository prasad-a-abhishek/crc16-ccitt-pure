"""harness_type_errors.py — stdlib-only fuzz harness for the AC12 type guards (Surface 5).

SPEC §3 AC12 mandates that crc() raises TypeError (NOT ValueError,
AttributeError, RuntimeError, or silent garbage) for every non-bytes-like
data argument, and for non-int init/xorout arguments.

This harness:
- Iterates over a curated matrix of bad types
- Asserts that TypeError is raised CLEANLY (caught and counted, not uncaught)
- Asserts that bool is rejected for init/xorout (bool is subclass of int)
- Asserts that bytes-subclasses are ACCEPTED (bytes, bytearray, memoryview)
- Fuzzes random non-bytes-like Python objects (custom classes, iterators)
  to ensure the guard does not regress to attribute-access-based coercion

Usage:
    python3 harness_type_errors.py [--iters N]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import traceback
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent.parent.parent / "src"))

from crc16_ccitt import crc  # noqa: E402

SURFACE = "type_errors"
OUT_DIR = _HERE.parent.parent.parent / "fuzz" / SURFACE
OUT_DIR.mkdir(parents=True, exist_ok=True)


# (label, value, should_raise)
_BAD_DATA_CASES: list[tuple[str, Any, bool]] = [
    ("None",                       None,        True),
    ("str_ascii",                  "hello",     True),
    ("str_empty",                  "",          True),
    ("int_zero",                   0,           True),
    ("int_positive",               42,          True),
    ("int_negative",               -1,          True),
    ("float",                      3.14,        True),
    ("bool_true",                  True,        True),  # bool is not bytes-like
    ("bool_false",                 False,       True),
    ("list_ints",                  [1, 2, 3],   True),
    ("list_bytes",                 [b"\x00"],   True),
    ("tuple",                      (1, 2),      True),
    ("dict",                       {1: 2},      True),
    ("set",                        {1, 2},      True),
    ("object_instance",            object(),    True),
    ("generator",                  (i for i in range(3)),  True),
    ("iter_range",                 iter(range(3)),         True),
]

# Bytes-subclasses MUST be accepted (the implementation explicitly handles these).
_GOOD_BYTES_LIKE: list[tuple[str, Any]] = [
    ("bytes_empty",      b""),
    ("bytes_single",     b"\x00"),
    ("bytes_multi",      b"\x00\x01\x02"),
    ("bytearray_empty",  bytearray()),
    ("bytearray_multi",  bytearray(b"\x00\x01\x02")),
    ("memoryview_empty", memoryview(b"")),
    ("memoryview_multi", memoryview(b"\x00\x01\x02")),
]

_BAD_INIT_CASES: list[tuple[str, Any, bool]] = [
    ("None",   None,   True),
    ("str",    "0",    True),
    ("float",  1.5,    True),
    ("bool_t", True,   True),   # bool is int subclass but rejected
    ("bool_f", False,  True),
    ("list",   [1],    True),
    ("tuple",  (1,),   True),
    ("object", object(), True),
]

_BAD_XOROUT_CASES: list[tuple[str, Any, bool]] = _BAD_INIT_CASES  # symmetric


def _check_rejects(label: str, fn, expected: bool, mismatches: list, crashes: list) -> None:
    """Verify `fn()` either raises TypeError (if expected) or returns cleanly.

    expected=True  → fn() MUST raise TypeError.
    expected=False → fn() MUST return without raising (any return value OK).
    Any other exception (ValueError, AttributeError, RuntimeError, …) is
    recorded as a CRASH (uncaught exception is the contract violation).
    """
    try:
        result = fn()
    except TypeError:
        if not expected:
            mismatches.append({
                "check": label, "expected": "accept",
                "actual": "raised TypeError",
            })
    except Exception as exc:
        crashes.append({
            "check": label,
            "raised": type(exc).__name__,
            "tb": traceback.format_exc(),
        })
    else:
        # No exception.
        if expected:
            mismatches.append({
                "check": label, "expected": "raise TypeError",
                "actual": repr(result)[:200],
            })
        # else: expected accept and got accept — pass silently.


def run(iters: int, seed: int = 0xBAD0) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()
    mismatches: list[dict] = []
    crashes: list[dict] = []

    # ---- Static bad-data matrix ----
    for label, value, should_raise in _BAD_DATA_CASES:
        _check_rejects(
            f"data.{label}",
            lambda v=value: crc(v),
            should_raise, mismatches, crashes,
        )

    # ---- Bytes-like subclasses MUST be accepted ----
    for label, value in _GOOD_BYTES_LIKE:
        _check_rejects(
            f"accept.{label}",
            lambda v=value: crc(v),
            False, mismatches, crashes,
        )

    # ---- Bad init values ----
    for label, value, should_raise in _BAD_INIT_CASES:
        _check_rejects(
            f"init.{label}",
            lambda v=value: crc(b"123456789", init=v),
            should_raise, mismatches, crashes,
        )

    # ---- Bad xorout values ----
    for label, value, should_raise in _BAD_XOROUT_CASES:
        _check_rejects(
            f"xorout.{label}",
            lambda v=value: crc(b"123456789", xorout=v),
            should_raise, mismatches, crashes,
        )

    # ---- Fuzz: random non-bytes-like objects ----
    for i in range(iters):
        # Build an object that is NOT a (bytes, bytearray, memoryview).
        kind = rng.choice(["custom", "frozenset", "complex", "namedtuple",
                           "iter_builtin", "partial"])
        try:
            if kind == "custom":
                obj: Any = type("Foo", (), {"__len__": lambda s: 1})()
            elif kind == "frozenset":
                obj = frozenset({1, 2, 3})
            elif kind == "complex":
                obj = complex(1, 2)
            elif kind == "namedtuple":
                from collections import namedtuple
                NT = namedtuple("NT", ["a", "b"])
                obj = NT(1, 2)
            elif kind == "iter_builtin":
                obj = map(lambda x: x, [1, 2, 3])
            elif kind == "partial":
                from functools import partial
                obj = partial(int, base=10)
            else:
                obj = object()
        except Exception as exc:
            crashes.append({"check": "fuzz_setup", "iter": i,
                            "kind": kind, "raised": type(exc).__name__,
                            "tb": traceback.format_exc()})
            continue

        _check_rejects(
            f"fuzz.{kind}",
            lambda o=obj: crc(o),
            True, mismatches, crashes,
        )

    elapsed = time.perf_counter() - t0
    results = {
        "surface": SURFACE,
        "iters": iters,
        "crashes": len(crashes),
        "oracle_mismatches": len(mismatches),
        "elapsed_seconds": round(elapsed, 4),
        "extras": {
            "static_bad_data_cases": len(_BAD_DATA_CASES),
            "good_bytes_like_cases": len(_GOOD_BYTES_LIKE),
            "bad_init_cases": len(_BAD_INIT_CASES),
            "bad_xorout_cases": len(_BAD_XOROUT_CASES),
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
        description="TypeError guard fuzz harness for crc()")
    parser.add_argument("--iters", type=int, default=100,
                        help="random non-bytes-like fuzz iterations (default 100)")
    parser.add_argument("--seed", type=int, default=0xBAD0)
    args = parser.parse_args(argv)
    return run(args.iters, args.seed)


if __name__ == "__main__":
    raise SystemExit(main())
