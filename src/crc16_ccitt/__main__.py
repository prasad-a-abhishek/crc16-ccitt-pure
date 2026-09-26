"""Allow ``python -m crc16_ccitt`` to run the self-test."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
