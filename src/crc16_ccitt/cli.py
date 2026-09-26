"""Command-line interface for ``crc16-ccitt``.

Provides two subcommands:

* ``compute``  -- compute the CRC of a hex-string argument.
* ``self-test``  -- print all RevEng-canonical vectors and PASS/FAIL markers.

Stdout-only, no file IO, no network, no environment beyond PYTHONPATH.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import crc


# RevEng-canonical test vectors (mirror seed_evidence.json).
_SELF_TEST_VECTORS: tuple[tuple[str, int, str], ...] = (
    ("", 0xFFFF, "empty input"),
    ("00", 0xE1F0, "single 0x00"),
    ("01", 0xF1D1, "single 0x01"),
    ("ff", 0xFF00, "single 0xFF"),
    ("00010203040506070809", 0xC241, "bytes 0x00..0x09"),
    ("313233343536373839", 0x29B1, "ASCII '123456789' (RevEng check)"),
)


def _compute(data_hex: str) -> int:
    """Compute CRC for the bytes represented by *data_hex*.

    Accepts a contiguous hex string with optional space separators.
    Raises :class:`ValueError` for malformed hex.
    """
    cleaned = data_hex.replace(" ", "").replace(",", "")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"hex string must have even length, got {len(cleaned)}")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex input {data_hex!r}: {exc}") from exc
    return crc(data)


def main_compute(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``crc16-ccitt-pure-compute`` script."""
    parser = argparse.ArgumentParser(
        prog="crc16-ccitt-pure-compute",
        description="Compute CRC-16/CCITT-FALSE of a hex-string input.",
    )
    parser.add_argument(
        "--data",
        required=True,
        help="Hex string representing the bytes to checksum "
             "(e.g. '313233343536373839' for ASCII '123456789').",
    )
    args = parser.parse_args(argv)
    try:
        value = _compute(args.data)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"0x{value:04x}")
    return 0


def main_self_test(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``crc16-ccitt-pure-self-test`` script."""
    parser = argparse.ArgumentParser(
        prog="crc16-ccitt-pure-self-test",
        description="Run the RevEng-canonical CRC-16/CCITT-FALSE self-test.",
    )
    parser.parse_args(argv)

    failed = 0
    for data_hex, expected, comment in _SELF_TEST_VECTORS:
        actual = _compute(data_hex) if data_hex else crc(b"")
        ok = actual == expected
        marker = "PASS" if ok else "FAIL"
        print(
            f"[{marker}] input={data_hex!r:24} "
            f"expected=0x{expected:04x} "
            f"actual=0x{actual:04x} "
            f"-- {comment}"
        )
        if not ok:
            failed += 1

    if failed:
        print(f"\n{failed} vector(s) FAILED", file=sys.stderr)
        return 1
    print(f"\nAll {len(_SELF_TEST_VECTORS)} RevEng vectors PASS")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Top-level dispatcher invoked by ``python -m crc16_ccitt``.

    Runs the self-test if no arguments are supplied (mirrors the convention
    used by Python's ``http.server`` and ``zipfile`` modules).
    """
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return main_self_test([])
    if argv[0] == "compute":
        return main_compute(argv[1:])
    if argv[0] == "self-test":
        return main_self_test(argv[1:])
    if argv[0] in ("-h", "--help"):
        print("usage: crc16-ccitt-pure [-h | compute | self-test]", flush=True)
        return 0
    print(f"unknown subcommand: {argv[0]!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover - exercised via __main__.py
    raise SystemExit(main())
