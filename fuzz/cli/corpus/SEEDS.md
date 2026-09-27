# cli seed corpus

Total seeds: 26

CLI subprocess seeds. Each file holds the argument list for a single `python -m crc16_ccitt ...` invocation. The harness spawns each as a fresh subprocess and validates return code, stdout format, and exit code on the bad-input / unknown-subcommand paths.

## Seed categories

| Range | Category | Expected outcome |
|---|---|---|
| 00-08 | Valid hex data | exit 0, hex output |
| 10-14 | Bad hex | exit 2 |
| 20-24 | Subcommand dispatch | exit 0 / 2 |
| 30-33 | Edge args | exit 0 / 2 |
| 40-42 | Cold-start | exit 0 with self-test PASS marker |
