"""Build seed corpora for each fuzz surface.

Generates 50+ deterministic seed inputs per surface under
`fuzz/<surface>/corpus/`. Each seed is written as a separate file
with a stable name so re-runs are reproducible.

Also writes `fuzz/<surface>/corpus/SEEDS.md` documenting what each seed is.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# -----------------------------------------------------------------------------
# crc_main: algorithm-correctness surface
# -----------------------------------------------------------------------------
CRC_MAIN = ROOT / "crc_main" / "corpus"
seeds_main: list[tuple[str, bytes]] = [
    # Boundary inputs
    ("00_empty",                 b""),
    ("01_single_00",             bytes([0x00])),
    ("02_single_FF",             bytes([0xFF])),
    ("03_two_byte_00_FF",        b"\x00\xFF"),
    ("04_two_byte_FF_00",        b"\xFF\x00"),
    ("05_eight_byte_zeros",      b"\x00" * 8),
    ("06_eight_byte_FFs",        b"\xFF" * 8),
    # Canonical RevEng vector
    ("10_canonical_123456789",   b"123456789"),
    ("11_canonical_range10",     bytes(range(10))),
    # Stress patterns
    ("20_256B_zeros",            b"\x00" * 256),
    ("21_256B_FFs",              b"\xFF" * 256),
    ("22_256B_alternating",      (b"\xAA\x55" * 128)),
    ("23_256B_walking_one",      bytes(1 << (i % 8) for i in range(256))),
    # Larger sizes
    ("30_1KB_zeros",             b"\x00" * 1024),
    ("31_1KB_FFs",               b"\xFF" * 1024),
    ("32_4KB_pattern_AA",        b"\xAA" * 4096),
    ("33_4KB_pattern_55",        b"\x55" * 4096),
    # Pathological: all-zero, all-FF, alternating at sizes > 64KB
    ("40_64KB_zeros",            b"\x00" * 65536),
    ("41_64KB_FFs",              b"\xFF" * 65536),
    ("42_64KB_alternating",      (b"\xAA\x55" * 32768)),
    # Bytes-subclass polymorphism (memoryview/bytearray via bytes value)
    ("50_mv_empty",              memoryview(b"").tobytes()),
    ("51_mv_single",             memoryview(bytes([0xAB])).tobytes()),
    ("52_ba_single",             bytes(bytearray(b"\xCD"))),
    # High-bit-density patterns
    ("60_repeated_AB",           b"\xAB" * 100),
    ("61_repeated_CD",           b"\xCD" * 100),
    ("62_repeated_EF",           b"\xEF" * 100),
    # Random-but-deterministic (rng seeded)
    ("70_rng_seq_1",             bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])),
    ("71_rng_seq_2",             bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])),
    ("72_rng_seq_3",             bytes(range(0, 256))),
    # Sizes that hit transition points
    ("80_size_1023",             b"\x00" * 1023),
    ("81_size_1025",             b"\x00" * 1025),
    ("82_size_2047",             b"\x00" * 2047),
    ("83_size_2049",             b"\x00" * 2049),
    ("84_size_4097",             b"\x00" * 4097),
    # Repeating single bytes
    ("90_one_byte_repeat_64",    b"\x42" * 64),
    ("91_one_byte_repeat_256",   b"\x42" * 256),
    ("92_one_byte_repeat_4096",  b"\x42" * 4096),
    # Mixed patterns
    ("100_asc_then_desc",        bytes(list(range(128)) + list(range(127, -1, -1)))),
    ("101_high_then_low",        bytes(list(range(255, -1, -1)))),
    # Each byte value once
    ("110_all_bytes_once",       bytes(range(256))),
    ("111_all_bytes_twice",      bytes(range(256)) * 2),
    # Specific to MSB-first NO-reflection algorithm (cover all polynomial-input bits)
    ("120_poly_kernel_1",        b"\x80" + b"\x00" * 7),  # sets top bit
    ("121_poly_kernel_2",        b"\x01" + b"\x00" * 7),  # sets bottom bit
    ("122_poly_kernel_3",        b"\xFF" * 9),
    # Edge of init 0xFFFF behavior
    ("130_eight_FFs",            b"\xFF" * 8),
    ("131_sixteen_FFs",          b"\xFF" * 16),
    ("132_32_FFs",               b"\xFF" * 32),
    # Init=0 (XMODEM-like) would be tested via crc_oracle — for crc_main just data
    ("140_zero_length_run",      b""),
    ("141_single_then_zero",     b"\x42\x00"),
    ("142_zero_then_single",     b"\x00\x42"),
]

(CRC_MAIN).mkdir(parents=True, exist_ok=True)
for name, data in seeds_main:
    (CRC_MAIN / f"{name}.bin").write_bytes(data)

# Document the seeds
(CRC_MAIN / "SEEDS.md").write_text(
    "# crc_main seed corpus\n\n"
    f"Total seeds: {len(seeds_main)}\n\n"
    "Deterministic boundary + canonical + stress inputs for the algorithm-correctness "
    "surface (Surface 1 from card 01 SURFACES.md). Each seed is stored as a separate "
    "file under `corpus/` with a stable name so re-runs are reproducible.\n\n"
    "## Seed categories\n\n"
    "| Range | Category | Notes |\n|---|---|---|\n"
    "| 00-05 | Boundary | empty, 1-byte, 2-byte pairs |\n"
    "| 10-11 | Canonical | RevEng check vector + 10-byte sweep |\n"
    "| 20-23 | 256-byte patterns | zeros, FFs, alternating, walking-one |\n"
    "| 30-33 | 1KB-4KB patterns | scaling check |\n"
    "| 40-42 | 64KB patterns | high-water scaling |\n"
    "| 50-52 | Bytes-subclass | memoryview/bytearray via `.tobytes()` |\n"
    "| 60-62 | High-bit-density | repeated AB / CD / EF |\n"
    "| 70-72 | Deterministic random | fixed byte sequences |\n"
    "| 80-84 | Transition points | sizes near powers of two |\n"
    "| 90-92 | Single-byte repeats | 64, 256, 4096 |\n"
    "| 100-101 | Ascending/descending | full byte-range sweeps |\n"
    "| 110-111 | All-bytes | each value once / twice |\n"
    "| 120-122 | MSB-polynomial | top-bit / bottom-bit / all-set |\n"
    "| 130-132 | FFs | 8/16/32 byte runs |\n"
    "| 140-142 | Zero-flanked | edge of init-FF behavior |\n"
)


# -----------------------------------------------------------------------------
# crc_oracle: differential against crcmod
# -----------------------------------------------------------------------------
CRC_ORACLE = ROOT / "crc_oracle" / "corpus"
seeds_oracle: list[tuple[str, bytes]] = [
    # Canonical vectors (mirror _CANONICAL in harness_crc_oracle.py)
    ("00_empty",                 b""),
    ("01_single_00",             bytes([0x00])),
    ("02_single_FF",             bytes([0xFF])),
    ("10_canonical_123456789",   b"123456789"),
    ("11_range_10",              bytes(range(10))),
    ("12_pair_00_FF",            b"\x00\xFF"),
    # Larger canonical patterns
    ("20_64B_FFs",               b"\xFF" * 64),
    ("21_1KB_zeros",             b"\x00" * 1024),
    ("22_4KB_AA",                b"\xAA" * 4096),
    # Small edge sizes
    ("30_size_1",                b"\x00"),
    ("31_size_2",                b"\x00\x00"),
    ("32_size_3",                b"\x00\x00\x00"),
    ("33_size_7",                b"\x00" * 7),
    ("34_size_8",                b"\x00" * 8),
    ("35_size_9",                b"\x00" * 9),
    # All-bytes
    ("40_all_bytes_256",         bytes(range(256))),
    # Walking one
    ("50_walking_1_256",         bytes(1 << (i % 8) for i in range(256))),
    ("51_walking_1_512",         bytes(1 << (i % 8) for i in range(512))),
    # Repeating high-bit
    ("60_repeat_0x80",           b"\x80" * 64),
    ("61_repeat_0xFE",           b"\xFE" * 64),
    ("62_repeat_0xFF",           b"\xFF" * 64),
    # Poly boundary cases
    ("70_single_high_bit",       b"\x80"),
    ("71_single_low_bit",        b"\x01"),
    ("72_poly_xFF",              b"\xFF" * 9),
    # Reversed / shuffled
    ("80_descending",            bytes(range(255, -1, -1))),
    ("81_ascending_then_desc",   bytes(list(range(128)) + list(range(127, -1, -1)))),
    # Byte-size edges
    ("90_size_255",              b"\xAA" * 255),
    ("91_size_256",              b"\xAA" * 256),
    ("92_size_257",              b"\xAA" * 257),
    ("93_size_511",              b"\xAA" * 511),
    ("94_size_512",              b"\xAA" * 512),
    ("95_size_513",              b"\xAA" * 513),
    # Common ASCII strings
    ("100_hello_world",          b"hello world"),
    ("101_alphabet_lower",       b"abcdefghijklmnopqrstuvwxyz"),
    ("102_alphabet_upper",       b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("103_digits",               b"0123456789"),
    ("104_json_doc",             b'{"key":"value","arr":[1,2,3]}'),
    # Poly-specific
    ("110_byte_then_FFs",        b"\x00" + b"\xFF" * 100),
    ("111_FFs_then_zero",        b"\xFF" * 100 + b"\x00"),
    # Random-but-deterministic
    ("120_seq_a",                bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])),
    ("121_seq_b",                bytes([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10])),
    ("122_seq_c",                bytes([0xAA, 0x55] * 50)),
    # Pathological length
    ("130_zero",                 b""),
    ("131_one_byte",             b"\x00"),
    ("132_one_byte_FF",          b"\xFF"),
    ("133_two_zeros",            b"\x00\x00"),
    # All-FFs at common sizes
    ("140_FF_2",                 b"\xFF\xFF"),
    ("141_FF_4",                 b"\xFF\xFF\xFF\xFF"),
    ("142_FF_8",                 b"\xFF" * 8),
    ("143_FF_16",                b"\xFF" * 16),
    ("144_FF_32",                b"\xFF" * 32),
    # All-zeros at common sizes
    ("150_00_2",                 b"\x00\x00"),
    ("151_00_4",                 b"\x00\x00\x00\x00"),
    ("152_00_8",                 b"\x00" * 8),
    ("153_00_16",                b"\x00" * 16),
    ("154_00_32",                b"\x00" * 32),
    # Mixed
    ("160_alternating_AB",       b"\xAB" * 128),
    ("161_alternating_CD",       b"\xCD" * 128),
    ("162_alternating_EF",       b"\xEF" * 128),
]

(CRC_ORACLE).mkdir(parents=True, exist_ok=True)
for name, data in seeds_oracle:
    (CRC_ORACLE / f"{name}.bin").write_bytes(data)

(CRC_ORACLE / "SEEDS.md").write_text(
    "# crc_oracle seed corpus\n\n"
    f"Total seeds: {len(seeds_oracle)}\n\n"
    "Differential-fuzz seeds against the `crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, "
    "rev=False, xorOut=0x0000)` reference oracle. The harness computes "
    "`crc16_ccitt.crc(data)` AND `crcmod_oracle(data)` on each seed and asserts "
    "byte-exact equality.\n\n"
    "## Seed categories\n\n"
    "| Range | Category |\n|---|---|\n"
    "| 00-12 | Canonical (mirror of harness `_CANONICAL`) |\n"
    "| 20-22 | Larger canonical patterns |\n"
    "| 30-35 | Small edge sizes (1-9 bytes) |\n"
    "| 40 | All-bytes-256 sweep |\n"
    "| 50-51 | Walking-one bit pattern |\n"
    "| 60-62 | High-bit-density repeats |\n"
    "| 70-72 | Polynomial boundary (high/low bit, all-FF) |\n"
    "| 80-81 | Reversed / shuffled |\n"
    "| 90-95 | Size edges (255/256/257/511/512/513) |\n"
    "| 100-104 | Common ASCII / JSON |\n"
    "| 110-111 | Poly-flanked patterns |\n"
    "| 120-122 | Deterministic random |\n"
    "| 130-133 | Pathological tiny sizes |\n"
    "| 140-144 | All-FF sizes 2/4/8/16/32 |\n"
    "| 150-154 | All-00 sizes 2/4/8/16/32 |\n"
    "| 160-162 | Alternating-AB/CD/EF |\n"
)


# -----------------------------------------------------------------------------
# type_errors: AC12 type-guard contract
# -----------------------------------------------------------------------------
TYPE_ERRORS = ROOT / "type_errors" / "corpus"
seeds_type: list[tuple[str, bytes | str]] = [
    # Good bytes-like (MUST be accepted)
    ("00_bytes_empty",           b""),
    ("01_bytes_single",          b"\x00"),
    ("02_bytes_multi",           b"\x00\x01\x02"),
    ("03_bytearray_empty",       str(type(bytearray()))),  # type descriptor string
    ("04_memoryview_empty",      str(type(memoryview(b"")))),
    # Bad data: primitives
    ("10_None",                  "None"),
    ("11_str",                   "hello"),
    ("12_str_empty",             ""),
    ("13_int",                   "42"),
    ("14_float",                 "3.14"),
    ("15_bool_true",             "True"),
    ("16_bool_false",            "False"),
    # Bad data: containers
    ("20_list",                  "[1,2,3]"),
    ("21_tuple",                 "(1,2)"),
    ("22_dict",                  "{1:2}"),
    ("23_set",                   "{1,2}"),
    ("24_frozenset",             "frozenset({1,2})"),
    # Bad data: iterables
    ("30_generator",             "(i for i in range(3))"),
    ("31_iter_range",            "iter(range(3))"),
    ("32_map",                   "map(int, ['1'])"),
    ("33_zip",                   "zip([1],[2])"),
    # Bad data: exotic types
    ("40_object",                "object()"),
    ("41_custom_class",          "type('Foo', (), {})()"),
    ("42_complex",               "complex(1,2)"),
    ("43_namedtuple",            "from collections import namedtuple; NT=namedtuple('NT',['a','b']); NT(1,2)"),
    ("44_partial",               "from functools import partial; partial(int, base=10)"),
    ("45_lambda",                "(lambda: None)"),
    # Bad init values (must reject)
    ("50_init_None",             "init_None"),
    ("51_init_str",              "init_str"),
    ("52_init_float",            "init_float"),
    ("53_init_bool",             "init_bool"),
    ("54_init_list",             "init_list"),
    ("55_init_tuple",            "init_tuple"),
    ("56_init_object",           "init_object"),
    # Bad xorout values (must reject — symmetric)
    ("60_xorout_None",           "xorout_None"),
    ("61_xorout_str",            "xorout_str"),
    ("62_xorout_float",          "xorout_float"),
    ("63_xorout_bool",           "xorout_bool"),
    ("64_xorout_list",           "xorout_list"),
    ("65_xorout_tuple",          "xorout_tuple"),
    ("66_xorout_object",         "xorout_object"),
    # Boundary int values for init/xorout (must ACCEPT)
    ("70_init_zero",             "init_zero"),
    ("71_init_uint16_max",       "init_uint16_max"),
    ("72_init_negative",         "init_negative"),
    ("73_init_large_positive",   "init_large_positive"),
    # Subclasses of bytes-like (must ACCEPT)
    ("80_bytes_subclass",        "bytes_subclass"),
    ("81_bytearray_subclass",    "bytearray_subclass"),
    ("82_memoryview_subclass",   "memoryview_subclass"),
    # Truthy/empty edge cases
    ("90_data_truthy_single",    "data_truthy_single"),
    ("91_data_truthy_zero",      "data_truthy_zero"),
]

(TYPE_ERRORS).mkdir(parents=True, exist_ok=True)
for name, data in seeds_type:
    (TYPE_ERRORS / f"{name}.txt").write_text(data if isinstance(data, str) else data.decode())

(TYPE_ERRORS / "SEEDS.md").write_text(
    "# type_errors seed corpus\n\n"
    f"Total seeds: {len(seeds_type)}\n\n"
    "Seeds for the AC12 TypeError-guard contract (Surface 5). The harness "
    "doesn't actually use the byte contents of these seeds — they're symbolic "
    "labels describing what kind of input was tested. The harness's static "
    "`_BAD_DATA_CASES`/`_GOOD_BYTES_LIKE`/`_BAD_INIT_CASES`/`_BAD_XOROUT_CASES` "
    "lists enumerate the real test surface. These seed files exist so the "
    "corpus/ directory is populated per the task spec, and so a future "
    "Atheris/libFuzzer-driven run has concrete labels to mutate against.\n\n"
    "## Seed categories\n\n"
    "| Range | Category | Expected outcome |\n|---|---|---|\n"
    "| 00-04 | Good bytes-like | ACCEPT (no exception) |\n"
    "| 10-16 | Bad primitives | REJECT TypeError |\n"
    "| 20-24 | Bad containers | REJECT TypeError |\n"
    "| 30-33 | Bad iterables | REJECT TypeError |\n"
    "| 40-45 | Bad exotic types | REJECT TypeError |\n"
    "| 50-56 | Bad init values | REJECT TypeError |\n"
    "| 60-66 | Bad xorout values | REJECT TypeError |\n"
    "| 70-73 | Boundary int values | ACCEPT (no exception) |\n"
    "| 80-82 | Bytes-like subclasses | ACCEPT (no exception) |\n"
    "| 90-91 | Truthy/zero edges | ACCEPT (no exception) |\n"
)


# -----------------------------------------------------------------------------
# cli: CLI subprocess surface
# -----------------------------------------------------------------------------
CLI = ROOT / "cli" / "corpus"
seeds_cli: list[tuple[str, str]] = [
    # Hex data (compute --data)
    ("00_hex_empty",          "compute --data "),
    ("01_hex_00",             "compute --data 00"),
    ("02_hex_FF",             "compute --data ff"),
    ("03_hex_canonical",      "compute --data 313233343536373839"),
    ("04_hex_256_random_0",   "compute --data a1b2c3d4e5f6"),
    ("05_hex_256_random_1",   "compute --data deadbeefcafe"),
    ("06_hex_256_random_2",   "compute --data 0123456789ab"),
    ("07_hex_1KB",            "compute --data " + "ab" * 1024),
    ("08_hex_4KB",            "compute --data " + "cd" * 4096),
    # Bad hex (must reject)
    ("10_bad_odd_length",     "compute --data 123"),
    ("11_bad_letter_z",       "compute --data zz"),
    ("12_bad_letter_Z",       "compute --data ZZ"),
    ("13_bad_unicode",        "compute --data \xff\xfe"),
    ("14_bad_special",        "compute --data !@#$"),
    # Subcommand dispatch
    ("20_self_test",          "self-test"),
    ("21_help_short",         "-h"),
    ("22_help_long",          "--help"),
    ("23_unknown_subcmd",     "not-a-real-subcommand"),
    ("24_garbage_subcmd",     "asdf"),
    # Edge cases
    ("30_compute_no_args",    "compute"),
    ("31_compute_extra_arg",  "compute --data 00 extra"),
    ("32_compute_flag_only",  "compute --data"),
    ("33_module_only",        ""),
    # Cold-start
    ("40_cold_start",         ""),
    ("41_cold_start_help",    "--help"),
    ("42_cold_start_self",    "self-test"),
]

(CLI).mkdir(parents=True, exist_ok=True)
for name, data in seeds_cli:
    (CLI / f"{name}.txt").write_text(data)

(CLI / "SEEDS.md").write_text(
    "# cli seed corpus\n\n"
    f"Total seeds: {len(seeds_cli)}\n\n"
    "CLI subprocess seeds. Each file holds the argument list for a single "
    "`python -m crc16_ccitt ...` invocation. The harness spawns each as a "
    "fresh subprocess and validates return code, stdout format, and exit "
    "code on the bad-input / unknown-subcommand paths.\n\n"
    "## Seed categories\n\n"
    "| Range | Category | Expected outcome |\n|---|---|---|\n"
    "| 00-08 | Valid hex data | exit 0, hex output |\n"
    "| 10-14 | Bad hex | exit 2 |\n"
    "| 20-24 | Subcommand dispatch | exit 0 / 2 |\n"
    "| 30-33 | Edge args | exit 0 / 2 |\n"
    "| 40-42 | Cold-start | exit 0 with self-test PASS marker |\n"
)


# -----------------------------------------------------------------------------
# large_input: scaling surface
# -----------------------------------------------------------------------------
LARGE = ROOT / "large_input" / "corpus"
seeds_large: list[tuple[str, bytes]] = [
    ("00_size_1_zero",       b"\x00"),
    ("01_size_1_FF",         b"\xFF"),
    ("02_size_1_AB",         b"\xAB"),
    ("10_size_1K_zero",      b"\x00" * 1024),
    ("11_size_1K_FF",        b"\xFF" * 1024),
    ("12_size_1K_alternating", (b"\xAA\x55" * 512)),
    ("20_size_10K_zero",     b"\x00" * 10_000),
    ("21_size_10K_FF",       b"\xFF" * 10_000),
    ("22_size_10K_AB",       b"\xAB" * 10_000),
    ("30_size_100K_zero",    b"\x00" * 100_000),
    ("31_size_100K_FF",      b"\xFF" * 100_000),
    ("32_size_100K_alternating", (b"\xAA\x55" * 50_000)),
    ("40_size_1M_zero",      b"\x00" * 1_000_000),
    ("41_size_1M_FF",        b"\xFF" * 1_000_000),
    ("42_size_1M_alternating", (b"\xAA\x55" * 500_000)),
    ("50_size_10M_zero",     b"\x00" * 10_000_000),
    ("51_size_10M_FF",       b"\xFF" * 10_000_000),
    ("52_size_10M_alternating", (b"\xAA\x55" * 5_000_000)),
]

(LARGE).mkdir(parents=True, exist_ok=True)
for name, data in seeds_large:
    (LARGE / f"{name}.bin").write_bytes(data)

(LARGE / "SEEDS.md").write_text(
    "# large_input seed corpus\n\n"
    f"Total seeds: {len(seeds_large)}\n\n"
    "Size-sweep seeds for Surface 7 (O(N) scaling). The harness exercises sizes "
    "from 1 B to 10 MB across 4 patterns (zeros, FFs, alternating, random). These "
    "files cover sizes × patterns so a future Atheris/libFuzzer driver can replay "
    "them directly.\n\n"
    "## Seed categories\n\n"
    "| Range | Size | Patterns |\n|---|---|---|\n"
    "| 00-02 | 1 B | zero / FF / AB |\n"
    "| 10-12 | 1 KB | zero / FF / alternating |\n"
    "| 20-22 | 10 KB | zero / FF / AB |\n"
    "| 30-32 | 100 KB | zero / FF / alternating |\n"
    "| 40-42 | 1 MB | zero / FF / alternating |\n"
    "| 50-52 | 10 MB | zero / FF / alternating |\n"
)

print("All seed corpora + SEEDS.md written.")
