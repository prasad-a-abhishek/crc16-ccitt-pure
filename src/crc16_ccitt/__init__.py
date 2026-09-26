"""crc16-ccitt -- pure-Python reference implementation of CRC-16/CCITT-FALSE.

Implements the CRC-16/CCITT-FALSE variant (a.k.a. the ITU-T X.25 HDLC FCS,
poly=0x1021, init=0xFFFF, no input/output reflection, no final XOR).
Conforms to ITU-T Recommendation X.25 (1996) §2.2.3.4 and the RevEng CRC
catalogue "CRC-16/CCITT-FALSE" entry (check value 0x29B1).

Public API
----------
- :func:`crc`     -- compute the CRC of a bytes-like object.
- :data:`__version__` -- the package version string ("0.1.0").

The function is a pure, total, side-effect-free mapping from bytes-like
input to a 16-bit unsigned int.  It never raises :class:`ValueError` or
:class:`AttributeError` -- non-bytes-like arguments raise :class:`TypeError`
with a message naming the offending type.
"""

from __future__ import annotations

__version__ = "0.1.0"

# Verbatim from RevEng catalogue, row "CRC-16/CCITT-FALSE".
_POLY: int = 0x1021
_INIT: int = 0xFFFF
_XOROUT: int = 0x0000


def crc(data, init: int = _INIT, xorout: int = _XOROUT) -> int:
    """Return the CRC-16/CCITT-FALSE of *data* as a 16-bit unsigned int.

    Parameters
    ----------
    data : bytes-like (bytes, bytearray, or memoryview)
        Input message.  ``None``, ``str``, ``int``, ``list``, and other
        non-bytes-like objects raise :class:`TypeError` -- they NEVER
        produce a silent garbage CRC.
    init : int (not bool), default 0xFFFF
        Initial CRC register value.  Exposed for callers who chain CRCs
        across blocks of a larger stream.
    xorout : int (not bool), default 0x0000
        Final XOR applied to the register before returning.  CCITT-FALSE
        uses 0x0000; the related CCITT variant uses 0xFFFF.  Bool values
        are rejected (Python ``bool`` is a subclass of ``int`` but is
        almost certainly a programmer error here).

    Returns
    -------
    int
        The 16-bit unsigned CRC.  Always in ``[0, 0xFFFF]``.

    Notes
    -----
    The implementation is the verbatim RevEng pseudocode transcribed to
    Python.  It is MSB-first (no bit reflection on either input or output).
    That distinguishes this variant from:

    * CRC-16/XMODEM  (same poly/init=0x0000 but xorout=0x0000)
    * CRC-16/CCITT   (same poly/init=0x0001 but xorout=0xFFFF)
    * CRC-16/IBM-SDLC (same poly/init=0xFFFF but refin/refout=true)

    The canonical disambiguator is ``crc(b"123456789") == 0x29B1``.
    """
    # ---- type guards (AC12) ----------------------------------------------
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc() expected bytes-like, got {type(data).__name__}"
        )
    if not isinstance(init, int) or isinstance(init, bool):
        raise TypeError(
            f"crc() 'init' must be int (not bool), got {type(init).__name__}"
        )
    if not isinstance(xorout, int) or isinstance(xorout, bool):
        raise TypeError(
            f"crc() 'xorout' must be int (not bool), got {type(xorout).__name__}"
        )

    # ---- MSB-first CRC-16 register shift (RevEng pseudocode) -------------
    reg: int = init & 0xFFFF
    for byte in data:
        reg ^= byte << 8
        for _ in range(8):
            if reg & 0x8000:
                reg = ((reg << 1) ^ _POLY) & 0xFFFF
            else:
                reg = (reg << 1) & 0xFFFF
    return (reg ^ xorout) & 0xFFFF


__all__ = ["crc", "__version__"]
