# type_errors seed corpus

Total seeds: 50

Seeds for the AC12 TypeError-guard contract (Surface 5). The harness doesn't actually use the byte contents of these seeds — they're symbolic labels describing what kind of input was tested. The harness's static `_BAD_DATA_CASES`/`_GOOD_BYTES_LIKE`/`_BAD_INIT_CASES`/`_BAD_XOROUT_CASES` lists enumerate the real test surface. These seed files exist so the corpus/ directory is populated per the task spec, and so a future Atheris/libFuzzer-driven run has concrete labels to mutate against.

## Seed categories

| Range | Category | Expected outcome |
|---|---|---|
| 00-04 | Good bytes-like | ACCEPT (no exception) |
| 10-16 | Bad primitives | REJECT TypeError |
| 20-24 | Bad containers | REJECT TypeError |
| 30-33 | Bad iterables | REJECT TypeError |
| 40-45 | Bad exotic types | REJECT TypeError |
| 50-56 | Bad init values | REJECT TypeError |
| 60-66 | Bad xorout values | REJECT TypeError |
| 70-73 | Boundary int values | ACCEPT (no exception) |
| 80-82 | Bytes-like subclasses | ACCEPT (no exception) |
| 90-91 | Truthy/zero edges | ACCEPT (no exception) |
