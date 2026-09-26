"""Tests for crc16-ccitt (CRC-16/CCITT-FALSE pure-Python reference).

Organized into 9 categories totaling >100 pytest items, with 1:1
coverage of the 12 LOCKED acceptance criteria in SPEC.md §3.
"""

from __future__ import annotations

import hashlib
import random

import pytest

from crc16_ccitt import crc, __version__


# ---------------------------------------------------------------------------
# Optional oracle: skip the differential-vs-crcmod category if crcmod is not
# installed.  We install crcmod as an *optional* test dep so production
# `pip install crc16-ccitt` succeeds without it (AC11).
# ---------------------------------------------------------------------------
try:
    import crcmod as _crcmod
    _crcmod_oracle: object = _crcmod.mkCrcFun(
        poly=0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000
    )
    _HAS_CRCMOD = True
except Exception:  # pragma: no cover - guarded by skipif
    _crcmod_oracle = None
    _HAS_CRCMOD = False


def _oracle(data: bytes) -> int:
    """Module-scoped crcmod oracle; raises if crcmod missing."""
    assert _crcmod_oracle is not None
    return _crcmod_oracle(data)  # type: ignore[union-attr]

needs_crcmod = pytest.mark.skipif(
    not _HAS_CRCMOD, reason="crcmod not installed (optional test dep)"
)


# ---------------------------------------------------------------------------
# 1. RevEng-canonical vectors  (AC1, AC2, AC3, AC4 + 2 extras)  -- 6 items
# ---------------------------------------------------------------------------
class TestRevEngCanonical:
    """The 6 RevEng-canonical test vectors from seed_evidence.json."""

    def test_empty_input_returns_init(self):
        # AC2 -- with no bytes consumed, CRC equals init.
        assert crc(b"") == 0xFFFF

    def test_single_byte_0x00(self):
        # AC3
        assert crc(bytes([0x00])) == 0xE1F0

    def test_single_byte_0x01(self):
        # extra
        assert crc(bytes([0x01])) == 0xF1D1

    def test_single_byte_0xff(self):
        # AC4
        assert crc(bytes([0xFF])) == 0xFF00

    def test_bytes_0_to_9(self):
        # extra
        assert crc(bytes(range(10))) == 0xC241

    def test_ascii_123456789_reveng_check(self):
        # AC1 -- the disambiguator check value.
        assert crc(b"123456789") == 0x29B1

    def test_ascii_123456789_hex_form(self):
        # AC1 duplicate check using the hex form shown in SPEC §8.
        assert hex(crc(b"123456789")) == "0x29b1"

    def test_ascii_123456789_decimal_form(self):
        # AC1 duplicate check using the decimal form shown in SPEC §8.
        assert crc(b"123456789") == 10673


# ---------------------------------------------------------------------------
# 2. Byte-range sweep  (all 256 single-byte inputs)  -- 30 items parametrised
# ---------------------------------------------------------------------------
# Tabulated from the same reference implementation; spot-checked against
# crcmod.  Includes the 4 AC2/3/4 anchors plus 26 additional sampled bytes.
_BYTE_TABLE = {
    0x00: 0xE1F0, 0x01: 0xF1D1, 0x02: 0xC1B2, 0x03: 0xD193,
    0x04: 0xA174, 0x05: 0xB155, 0x06: 0x8136, 0x07: 0x9117,
    0x08: 0x60F8, 0x09: 0x70D9, 0x0A: 0x40BA, 0x0B: 0x509B,
    0x0C: 0x207C, 0x0D: 0x305D, 0x0E: 0x003E, 0x0F: 0x101F,
    0x10: 0xF3C1, 0x11: 0xE3E0, 0x12: 0xD383, 0x13: 0xC3A2,
    0x14: 0xB345, 0x15: 0xA364, 0x16: 0x9307, 0x17: 0x8326,
    0x18: 0x72C9, 0x19: 0x62E8, 0x1A: 0x528B, 0x1B: 0x42AA,
    0x1C: 0x324D, 0x1D: 0x226C, 0x1E: 0x120F, 0x1F: 0x022E,
    0x20: 0xC592, 0x21: 0xD5B3, 0x22: 0xE5D0, 0x23: 0xF5F1,
    0x24: 0x8516, 0x25: 0x9537, 0x26: 0xA554, 0x27: 0xB575,
    0x28: 0x449A, 0x29: 0x54BB, 0x2A: 0x64D8, 0x2B: 0x74F9,
    0x2C: 0x041E, 0x2D: 0x143F, 0x2E: 0x245C, 0x2F: 0x347D,
    0x30: 0xD7A3, 0x31: 0xC782, 0x32: 0xF7E1, 0x33: 0xE7C0,
    0x34: 0x9727, 0x35: 0x8706, 0x36: 0xB765, 0x37: 0xA744,
    0x38: 0x56AB, 0x39: 0x468A, 0x3A: 0x76E9, 0x3B: 0x66C8,
    0x3C: 0x162F, 0x3D: 0x060E, 0x3E: 0x366D, 0x3F: 0x264C,
    0x40: 0xA934, 0x41: 0xB915, 0x42: 0x8976, 0x43: 0x9957,
    0x44: 0xE9B0, 0x45: 0xF991, 0x46: 0xC9F2, 0x47: 0xD9D3,
    0x48: 0x283C, 0x49: 0x381D, 0x4A: 0x087E, 0x4B: 0x185F,
    0x4C: 0x68B8, 0x4D: 0x7899, 0x4E: 0x48FA, 0x4F: 0x58DB,
    0x50: 0xBB05, 0x51: 0xAB24, 0x52: 0x9B47, 0x53: 0x8B66,
    0x54: 0xFB81, 0x55: 0xEBA0, 0x56: 0xDBC3, 0x57: 0xCBE2,
    0x58: 0x3A0D, 0x59: 0x2A2C, 0x5A: 0x1A4F, 0x5B: 0x0A6E,
    0x5C: 0x7A89, 0x5D: 0x6AA8, 0x5E: 0x5ACB, 0x5F: 0x4AEA,
    0x60: 0x8D56, 0x61: 0x9D77, 0x62: 0xAD14, 0x63: 0xBD35,
    0x64: 0xCDD2, 0x65: 0xDDF3, 0x66: 0xED90, 0x67: 0xFDB1,
    0x68: 0x0C5E, 0x69: 0x1C7F, 0x6A: 0x2C1C, 0x6B: 0x3C3D,
    0x6C: 0x4CDA, 0x6D: 0x5CFB, 0x6E: 0x6C98, 0x6F: 0x7CB9,
    0x70: 0x9F67, 0x71: 0x8F46, 0x72: 0xBF25, 0x73: 0xAF04,
    0x74: 0xDFE3, 0x75: 0xCFC2, 0x76: 0xFFA1, 0x77: 0xEF80,
    0x78: 0x1E6F, 0x79: 0x0E4E, 0x7A: 0x3E2D, 0x7B: 0x2E0C,
    0x7C: 0x5EEB, 0x7D: 0x4ECA, 0x7E: 0x7EA9, 0x7F: 0x6E88,
    0x80: 0x7078, 0x81: 0x6059, 0x82: 0x503A, 0x83: 0x401B,
    0x84: 0x30FC, 0x85: 0x20DD, 0x86: 0x10BE, 0x87: 0x009F,
    0x88: 0xF170, 0x89: 0xE151, 0x8A: 0xD132, 0x8B: 0xC113,
    0x8C: 0xB1F4, 0x8D: 0xA1D5, 0x8E: 0x91B6, 0x8F: 0x8197,
    0x90: 0x6249, 0x91: 0x7268, 0x92: 0x420B, 0x93: 0x522A,
    0x94: 0x22CD, 0x95: 0x32EC, 0x96: 0x028F, 0x97: 0x12AE,
    0x98: 0xE341, 0x99: 0xF360, 0x9A: 0xC303, 0x9B: 0xD322,
    0x9C: 0xA3C5, 0x9D: 0xB3E4, 0x9E: 0x8387, 0x9F: 0x93A6,
    0xA0: 0x541A, 0xA1: 0x443B, 0xA2: 0x7458, 0xA3: 0x6479,
    0xA4: 0x149E, 0xA5: 0x04BF, 0xA6: 0x34DC, 0xA7: 0x24FD,
    0xA8: 0xD512, 0xA9: 0xC533, 0xAA: 0xF550, 0xAB: 0xE571,
    0xAC: 0x9596, 0xAD: 0x85B7, 0xAE: 0xB5D4, 0xAF: 0xA5F5,
    0xB0: 0x462B, 0xB1: 0x560A, 0xB2: 0x6669, 0xB3: 0x7648,
    0xB4: 0x06AF, 0xB5: 0x168E, 0xB6: 0x26ED, 0xB7: 0x36CC,
    0xB8: 0xC723, 0xB9: 0xD702, 0xBA: 0xE761, 0xBB: 0xF740,
    0xBC: 0x87A7, 0xBD: 0x9786, 0xBE: 0xA7E5, 0xBF: 0xB7C4,
    0xC0: 0x38BC, 0xC1: 0x289D, 0xC2: 0x18FE, 0xC3: 0x08DF,
    0xC4: 0x7838, 0xC5: 0x6819, 0xC6: 0x587A, 0xC7: 0x485B,
    0xC8: 0xB9B4, 0xC9: 0xA995, 0xCA: 0x99F6, 0xCB: 0x89D7,
    0xCC: 0xF930, 0xCD: 0xE911, 0xCE: 0xD972, 0xCF: 0xC953,
    0xD0: 0x2A8D, 0xD1: 0x3AAC, 0xD2: 0x0ACF, 0xD3: 0x1AEE,
    0xD4: 0x6A09, 0xD5: 0x7A28, 0xD6: 0x4A4B, 0xD7: 0x5A6A,
    0xD8: 0xAB85, 0xD9: 0xBBA4, 0xDA: 0x8BC7, 0xDB: 0x9BE6,
    0xDC: 0xEB01, 0xDD: 0xFB20, 0xDE: 0xCB43, 0xDF: 0xDB62,
    0xE0: 0x1CDE, 0xE1: 0x0CFF, 0xE2: 0x3C9C, 0xE3: 0x2CBD,
    0xE4: 0x5C5A, 0xE5: 0x4C7B, 0xE6: 0x7C18, 0xE7: 0x6C39,
    0xE8: 0x9DD6, 0xE9: 0x8DF7, 0xEA: 0xBD94, 0xEB: 0xADB5,
    0xEC: 0xDD52, 0xED: 0xCD73, 0xEE: 0xFD10, 0xEF: 0xED31,
    0xF0: 0x0EEF, 0xF1: 0x1ECE, 0xF2: 0x2EAD, 0xF3: 0x3E8C,
    0xF4: 0x4E6B, 0xF5: 0x5E4A, 0xF6: 0x6E29, 0xF7: 0x7E08,
    0xF8: 0x8FE7, 0xF9: 0x9FC6, 0xFA: 0xAFA5, 0xFB: 0xBF84,
    0xFC: 0xCF63, 0xFD: 0xDF42, 0xFE: 0xEF21, 0xFF: 0xFF00,
}


@pytest.mark.parametrize("byte_value, expected", sorted(_BYTE_TABLE.items()))
def test_single_byte_byte_range_sweep(byte_value: int, expected: int):
    """All 256 single-byte inputs produce the tabulated CRC.

    Tabulated from the same reference implementation; verified against
    crcmod for the boundary bytes (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF).
    """
    assert crc(bytes([byte_value])) == expected


# ---------------------------------------------------------------------------
# 3. Length sweep  (3 fill patterns x 11 lengths + 1 empty)  -- 34 items
# ---------------------------------------------------------------------------
_LENGTH_SWEEP_DATA = [
    # (length, fill_byte, expected_crc, label)
    (0,    0x00, 0xFFFF, "empty is init"),
    (1,    0x00, 0xE1F0, "single 0x00"),
    (2,    0x00, 0x1D0F, "two 0x00"),
    (4,    0x00, 0x84C0, "four 0x00"),
    (8,    0x00, 0x313E, "eight 0x00"),
    (16,   0x00, 0x6A0A, "16 0x00"),
    (32,   0x00, 0xF14C, "32 0x00"),
    (64,   0x00, 0xD6DA, "64 0x00"),
    (128,  0x00, 0xF00A, "128 0x00"),
    (256,  0x00, 0x41E8, "256 0x00"),
    (512,  0x00, 0x1634, "512 0x00"),
    (1024, 0x00, 0xB76F, "1024 0x00"),
    (1,    0xFF, 0xFF00, "single 0xFF"),
    (2,    0xFF, 0x0000, "two 0xFF"),
    (4,    0xFF, 0x1D0F, "four 0xFF"),
    (8,    0xFF, 0x97DF, "eight 0xFF"),
    (16,   0xFF, 0x6A4B, "16 0xFF"),
    (32,   0xFF, 0x75F8, "32 0xFF"),
    (64,   0xFF, 0xF154, "64 0xFF"),
    (128,  0xFF, 0x1DA3, "128 0xFF"),
    (256,  0xFF, 0x5B2F, "256 0xFF"),
    (512,  0xFF, 0x6995, "512 0xFF"),
    (1024, 0xFF, 0x77EB, "1024 0xFF"),
    (1,    0xA5, 0x04BF, "single 0xA5"),
    (2,    0xA5, 0x1ACB, "two 0xA5"),
    (4,    0xA5, 0x835B, "four 0xA5"),
    (8,    0xA5, 0xEF40, "eight 0xA5"),
    (16,   0xA5, 0xAA69, "16 0xA5"),
    (32,   0xA5, 0xE14E, "32 0xA5"),
    (64,   0xA5, 0x0E6E, "64 0xA5"),
    (128,  0xA5, 0xB8E2, "128 0xA5"),
    (256,  0xA5, 0xA33A, "256 0xA5"),
    (512,  0xA5, 0x548A, "512 0xA5"),
    (1024, 0xA5, 0xCB4C, "1024 0xA5"),
]


@pytest.mark.parametrize(
    "length, fill, expected, label",
    _LENGTH_SWEEP_DATA,
    ids=[f"len{l:04d}-fill{fill:02x}-{label}" for (l, fill, _, label) in _LENGTH_SWEEP_DATA],
)
def test_length_sweep(length: int, fill: int, expected: int, label: str):
    """Length sweep across 3 deterministic fill patterns."""
    assert crc(bytes([fill]) * length) == expected


# ---------------------------------------------------------------------------
# 4. Differential vs crcmod  (AC11)  -- 25 random inputs
# ---------------------------------------------------------------------------
@needs_crcmod
def test_differential_vs_crcmod_25_random():
    """AC11 -- 25 random byte strings must match crcmod byte-exact."""
    rng = random.Random(0xC216)  # fixed seed -> reproducible
    for i in range(25):
        length = rng.randint(1, 1024)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        ours = crc(data)
        theirs = _oracle(data)
        assert ours == theirs, (
            f"differential mismatch on sample {i} (len={length}): "
            f"ours=0x{ours:04x} crcmod=0x{theirs:04x}"
        )


@needs_crcmod
def test_differential_vs_crcmod_reveng_canonical():
    """AC11 -- the 6 RevEng-canonical vectors must all match crcmod."""
    vectors = [
        (b"", 0xFFFF),
        (bytes([0x00]), 0xE1F0),
        (bytes([0x01]), 0xF1D1),
        (bytes([0xFF]), 0xFF00),
        (bytes(range(10)), 0xC241),
        (b"123456789", 0x29B1),
    ]
    for data, expected in vectors:
        assert crc(data) == _oracle(data) == expected


# ---------------------------------------------------------------------------
# 5. Type-error safety  (AC12)  -- 14 items
# ---------------------------------------------------------------------------
class TestTypeErrors:
    """AC12 -- non-bytes-like inputs MUST raise TypeError, never garbage CRCs."""

    @pytest.mark.parametrize("bad_input", [None, "string", 42, 3.14, [], {}, set()])
    def test_invalid_data_type_raises(self, bad_input):
        with pytest.raises(TypeError):
            crc(bad_input)

    def test_none_raises_typeerror(self):
        with pytest.raises(TypeError, match="bytes-like"):
            crc(None)

    def test_str_raises_typeerror(self):
        with pytest.raises(TypeError, match="bytes-like"):
            crc("hello")

    def test_int_raises_typeerror(self):
        with pytest.raises(TypeError, match="bytes-like"):
            crc(123)

    def test_list_raises_typeerror(self):
        with pytest.raises(TypeError, match="bytes-like"):
            crc([1, 2, 3])

    def test_bool_init_rejected(self):
        with pytest.raises(TypeError):
            crc(b"x", init=True)

    def test_none_init_rejected(self):
        with pytest.raises(TypeError):
            crc(b"x", init=None)

    def test_str_init_rejected(self):
        with pytest.raises(TypeError):
            crc(b"x", init="0xFFFF")

    def test_float_init_rejected(self):
        with pytest.raises(TypeError):
            crc(b"x", init=0xFFFF + 0.5)

    def test_bool_xorout_rejected(self):
        with pytest.raises(TypeError):
            crc(b"x", xorout=True)

    def test_none_xorout_rejected(self):
        with pytest.raises(TypeError):
            crc(b"x", xorout=None)

    def test_str_xorout_rejected(self):
        with pytest.raises(TypeError):
            crc(b"x", xorout="0")

    def test_bytes_like_inputs_are_accepted(self):
        # bytes, bytearray, memoryview ARE bytes-like.
        assert crc(b"x") == crc(bytearray(b"x")) == crc(memoryview(b"x"))


# ---------------------------------------------------------------------------
# 6. init / xorout parameter matrix  (AC6, AC10)  -- 8 items
# ---------------------------------------------------------------------------
class TestInitXorout:
    """AC6 -- changing init changes output deterministically.

    AC10 -- xorout=0x0000 leaves the register unchanged at the end.
    """

    def test_default_init_0xffff(self):
        # AC2 baseline
        assert crc(b"") == 0xFFFF

    def test_init_0x0000_empty(self):
        # With init=0 the empty input returns 0 xor xorout.
        assert crc(b"", init=0x0000) == 0x0000

    def test_init_0xffff_xorout_0xffff_flips_all_bits(self):
        # xorout=0xFFFF flips all 16 bits of the register.
        # For crc(b"") = 0xFFFF, xorout=0xFFFF should give 0x0000.
        assert crc(b"", init=0xFFFF, xorout=0xFFFF) == 0x0000

    def test_xorout_does_not_change_byte_count(self):
        # xorout affects only the final XOR, not how many bytes are consumed.
        a = crc(b"123456789", xorout=0x0000)
        b = crc(b"123456789", xorout=0xFFFF)
        assert a != b
        assert (a ^ b) == 0xFFFF  # only the 16-bit XOR differs

    def test_init_changes_output_deterministically(self):
        # AC6 -- same data, two different inits -> two different outputs.
        a = crc(b"123456789", init=0xFFFF)
        b = crc(b"123456789", init=0x0000)
        assert a != b

    def test_init_xorout_chain_equivalence(self):
        # crc(data, init=I, xorout=X) == crc(data, init=I) ^ X  (when X in 0..0xFFFF)
        # This is a property test: any (init, xorout) pair should satisfy it.
        for init, xorout in [(0xFFFF, 0x0000), (0x0000, 0xFFFF),
                             (0xDEAD, 0xBEEF), (0x1234, 0x5678)]:
            lhs = crc(b"some data", init=init, xorout=xorout)
            rhs = crc(b"some data", init=init) ^ xorout
            assert (lhs & 0xFFFF) == (rhs & 0xFFFF)

    def test_xorout_clamps_to_16_bits(self):
        # xorout larger than 0xFFFF should still produce a 16-bit result
        # (our implementation masks with & 0xFFFF at the end).
        v = crc(b"x", xorout=0x10000)
        assert 0 <= v <= 0xFFFF

    def test_init_clamps_to_16_bits(self):
        # init larger than 0xFFFF still produces a 16-bit register value
        # (the & 0xFFFF is applied at the start of the register shift).
        a = crc(b"x", init=0x1FFFF)  # truncated to 0xFFFF
        b = crc(b"x", init=0xFFFF)
        assert a == b


# ---------------------------------------------------------------------------
# 7. Register width  (AC5)  -- 8 items
# ---------------------------------------------------------------------------
class TestRegisterWidth:
    """AC5 -- crc() always returns an int in [0, 0xFFFF]."""

    @pytest.mark.parametrize("seed", [0, 1, 42, 0xBEEF, 0xCAFE, 0xDEAD, 0xFEED, 12345])
    def test_result_in_uint16_range(self, seed: int):
        rng = random.Random(seed)
        data = bytes(rng.randint(0, 255) for _ in range(64))
        result = crc(data)
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF
        assert result == (result & 0xFFFF)


# ---------------------------------------------------------------------------
# 8. Determinism  (AC7)  -- 5 items
# ---------------------------------------------------------------------------
class TestDeterminism:
    """AC7 -- crc() is pure and deterministic."""

    @pytest.mark.parametrize("seed", [0, 1, 42, 0xBEEF, 0xCAFE])
    def test_repeated_calls_equal(self, seed: int):
        rng = random.Random(seed)
        data = bytes(rng.randint(0, 255) for _ in range(64))
        first = crc(data)
        for _ in range(100):
            assert crc(data) == first


# ---------------------------------------------------------------------------
# 9. RefIn / RefOut / XorOut cross-checks  (AC8, AC9, AC10)  -- 4 items
# ---------------------------------------------------------------------------
class TestParameterFlags:
    """AC8 / AC9 / AC10 -- each parameter flag does what RevEng says."""

    def test_refin_false_input_not_reflected(self):
        # AC8 -- bytes are NOT bit-reflected before processing.
        # Verified against crcmod: crc(b"\x00\xFF") == 0x03FF.
        # (The SPEC's prose "0x7E83" was illustrative, not computed;
        # the ground truth is the differential-vs-crcmod check below.)
        assert crc(b"\x00\xFF") == 0x03FF

    @needs_crcmod
    def test_refin_false_matches_crcmod_oracle(self):
        # AC8 (oracle-backed) -- b"\x00\xFF" matches the ccitt-false oracle.
        assert crc(b"\x00\xFF") == _oracle(b"\x00\xFF")

    def test_refout_false_output_not_reflected(self):
        # AC9 -- the high bit of the result is the high bit of the
        # internal register at the end (NOT the low bit).
        # For one byte 0xA5 we expect a CRC whose high bit depends on
        # the MSB-first shift.
        result = crc(b"\xA5")
        # 0x04BF == 0000 0100 1011 1111  -- high bit (bit 15) is 0.
        # Under refout=true the result would be 0xFD20 -- bit 15 = 1.
        assert result == 0x04BF

    def test_xorout_0x0000_no_final_xor(self):
        # AC10 -- xorout=0x0000 means the empty-input CRC equals init.
        # This is a stronger version of AC2.
        assert crc(b"") == 0xFFFF  # init == xorout means no change

    def test_distinct_from_xmodem_variant(self):
        # Sanity: our impl is FALSE (init=0xFFFF), NOT XMODEM (init=0x0000).
        # XMODEM yields 0x31C3 for "123456789"; FALSE yields 0x29B1.
        xmodem = crc(b"123456789", init=0x0000)
        ccitt_false = crc(b"123456789", init=0xFFFF)
        assert ccitt_false == 0x29B1
        assert xmodem == 0x31C3
        assert ccitt_false != xmodem


# ---------------------------------------------------------------------------
# 10. Fuzz inputs  (differential vs crcmod, 10 patterns)  -- 10 items
# ---------------------------------------------------------------------------
def _fuzz_corpus() -> list[bytes]:
    """Deterministic fuzz corpus -- 10 patterns of varying shape."""
    return [
        b"",                                                     # empty
        bytes(range(256)),                                       # 256-byte full sweep
        b"\xff" * 256,                                           # all-0xFF
        bytes(1024),                                             # 1KB of zero
        bytes(1024),                                             # 1KB of zero (re-listed)
        b"The quick brown fox jumps over the lazy dog 0123456789" * 4,  # mixed ASCII
        b"\x00" * 64,                                            # NULL padding
        hashlib.sha256(b"seed-1").digest() * 4,                  # 128B pseudo-random
        hashlib.sha256(b"seed-2").digest() * 4,
        hashlib.sha256(b"seed-3").digest() * 4,
    ]


@needs_crcmod
@pytest.mark.parametrize("data", _fuzz_corpus(), ids=lambda d: f"fuzz-len{len(d)}")
def test_fuzz_inputs_match_crcmod(data: bytes):
    """Differential test -- fuzz inputs must match crcmod byte-exact."""
    assert crc(data) == _oracle(data)


# ---------------------------------------------------------------------------
# 11. Edge conditions  -- 10 items
# ---------------------------------------------------------------------------
class TestEdgeConditions:

    def test_empty_bytes(self):
        assert crc(b"") == 0xFFFF

    def test_single_zero_byte(self):
        assert crc(bytes([0x00])) == 0xE1F0

    def test_single_ff_byte(self):
        assert crc(bytes([0xFF])) == 0xFF00

    def test_64k_zero_block(self):
        # 65536 zero bytes -- one full register-width cycle.
        # Spot-check: must not raise and must return a 16-bit value.
        result = crc(b"\x00" * 65536)
        assert 0 <= result <= 0xFFFF

    def test_64k_ff_block(self):
        result = crc(b"\xff" * 65536)
        assert 0 <= result <= 0xFFFF

    @needs_crcmod
    def test_64k_zero_matches_crcmod(self):
        assert crc(b"\x00" * 65536) == _oracle(b"\x00" * 65536)

    @needs_crcmod
    def test_64k_ff_matches_crcmod(self):
        assert crc(b"\xff" * 65536) == _oracle(b"\xff" * 65536)

    def test_alternating_bits_pattern(self):
        # b"\xAA\x55" * 128
        data = (b"\xAA\x55") * 128
        result = crc(data)
        assert 0 <= result <= 0xFFFF

    def test_bytearray_input_matches_bytes(self):
        # bytes-like equivalence: bytearray and memoryview produce same CRC.
        assert crc(bytearray(b"123456789")) == crc(b"123456789") == 0x29B1

    def test_memoryview_input_matches_bytes(self):
        assert crc(memoryview(b"123456789")) == crc(b"123456789") == 0x29B1


# ---------------------------------------------------------------------------
# 12. Version + module surface  -- 4 items
# ---------------------------------------------------------------------------
class TestVersion:

    def test_version_is_string(self):
        assert isinstance(__version__, str)

    def test_version_is_semver(self):
        parts = __version__.split(".")
        assert len(parts) == 3
        for p in parts:
            assert p.isdigit(), f"non-numeric version component: {p!r}"

    def test_version_is_0_1_0(self):
        assert __version__ == "0.1.0"

    def test_crc_is_callable(self):
        assert callable(crc)
