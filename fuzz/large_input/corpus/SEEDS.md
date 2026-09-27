# large_input seed corpus

Total seeds: 18

Size-sweep seeds for Surface 7 (O(N) scaling). The harness exercises sizes from 1 B to 10 MB across 4 patterns (zeros, FFs, alternating, random). These files cover sizes × patterns so a future Atheris/libFuzzer driver can replay them directly.

## Seed categories

| Range | Size | Patterns |
|---|---|---|
| 00-02 | 1 B | zero / FF / AB |
| 10-12 | 1 KB | zero / FF / alternating |
| 20-22 | 10 KB | zero / FF / AB |
| 30-32 | 100 KB | zero / FF / alternating |
| 40-42 | 1 MB | zero / FF / alternating |
| 50-52 | 10 MB | zero / FF / alternating |
