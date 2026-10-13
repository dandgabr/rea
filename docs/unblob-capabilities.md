# Unblob capability and acceptance ledger

The producer reference is [Unblob 26.6.4](https://github.com/onekey-sec/unblob/tree/1fcc7a0a584a70a96c31f5a276c20944d199a089),
revision `1fcc7a0a584a70a96c31f5a276c20944d199a089`. Runtime version and executable
SHA-256 are observations; matching the version does not prove this source
revision. REA preserves Binwalk inspection and Unblob extraction defaults.

Native options below are audited in [cli.py](https://github.com/onekey-sec/unblob/blob/1fcc7a0a584a70a96c31f5a276c20944d199a089/python/unblob/cli.py).
`FILE` accepts one existing regular file. A directory, password argument, raw
native argv proxy, force overwrite and sandbox bypass are outside this contract.
Use the [firmware guide](firmware-analysis.md) for public CLI/MCP examples.

| Native option                   | REA disposition and contract                                                     | Acceptance oracle                                                                                                                                 |
| ------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `FILE`                          | `path`; immutable nonempty regular snapshot, original basename, optional `range` | Source identity, selected bytes and original offset adjusted once; FIFO admission terminates without a writer; 128 MiB admission boundary         |
| `-e`, `--extract-dir`           | Private staging; caller `output_directory` is fresh publication                  | Existing destination untouched; exclusive regular writes and SHA readback; failed paths never advertised committed                                |
| `-f`, `--force`                 | Excluded: no overwrite authority                                                 | Native argv contains no force flag; existing output retains partial observations and original bytes                                               |
| `-d`, `--depth`                 | `max_depth`, default 3, 1–10; inspection uses 1                                  | Depth-limited task remains unexamined; at 10 a new extraction requires a verified committed child                                                 |
| `-n`, `--randomness-depth`      | `options.randomness_depth`, default 0                                            | Known-chunk skip early return versus whole-file no-chunks randomness; actual 1025-byte final short block, native windows/cardinality/raw means    |
| `-P`, `--plugins-path`          | Explicit trusted file/tree `options.plugins_path`                                | Descriptor-bound manifest SHA/size, pre/post identity, native handler/report hooks, cache-free package import, drift retains partial observations |
| `-S`, `--skip-magic`            | `options.skip_magic.values`; append default, replace explicit                    | Literal single argv token, actual native magic skip, default rules retained on omission                                                           |
| `--skip-extension`              | Nonempty `options.skip_extensions`; repeated CLI replaces defaults               | Original `.rlib` basename applies to ranges; explicit replacement admits recognized gzip                                                          |
| `--clear-skip-magics`           | `options.skip_magic.mode: replace`; CLI flag with repeatable magic               | Actual native replacement plus append/replace producer-shaped argv controls                                                                       |
| `-p`, `--process-num`           | Positive `options.workers`, default 1; CLI `--workers`                           | Actual workers 2 metadata, invalid worker grammar before command launch; no invented worker cap                                                   |
| `--report`                      | REA owns bounded private JSON path; raw report returned inline                   | Strict UTF-8/JSON and 8 MiB budget; valid unordered reports normalized once; malformed data not repaired                                          |
| `--log`                         | Private producer diagnostic path                                                 | No caller log-path proxy; staging/diagnostic ownership and bounded captured output survive failures                                               |
| `-s`, `--skip-extraction`       | Explicit Unblob `inspect_firmware_regions`                                       | No carve/extract publication; native recognized-chunk early return preserved; whole unrecognized input may have randomness                        |
| `--no-sandbox`                  | Excluded: no bypass or fallback request                                          | Flag absent; native Landlock isolation remains unverified even after a successful analysis                                                        |
| `-k`, `--keep-extracted-chunks` | `options.keep_extracted_chunks`, default false                                   | Actual retained gzip carving digest and nested payload digest; whole-file native no-carving behavior preserved                                    |
| `--delete-extracted-files`      | `options.delete_extracted_files` modes none/all/selected                         | Actual intermediate deletion; `DeletedReport` retained without nonexistent artifact; selected handler argv exact                                  |
| `--carve-suffix`                | `options.carve_suffix`, default `_extract`                                       | Actual `.carved` layout; reject empty or separator-containing suffix                                                                              |
| `--extract-suffix`              | `options.extract_suffix`, default `_extract`                                     | Actual `.decoded` layout and child hash; reject separator-containing suffix                                                                       |
| `-v`, `--verbose` (repeatable)  | Presentation/developer control excluded; fixed normal producer verbosity         | Raw diagnostics remain Evidence; no implicit randomness plot generation or public verbosity proxy                                                 |
| `--show-external-dependencies`  | Named `inspect_firmware_provider`; useful exit 1 retained                        | Actual 15 lookup marks; host missing tools reported explicitly; lookup does not prove extractors function                                         |
| `--build-handlers-doc`          | Same inventory operation, private documentation path                             | Actual public DOC entries retained; malformed rows downgrade coverage; not fabricated complete installed handler inventory                        |
| `--version`                     | Every admitted request, no firmware needed for inventory                         | Observed version/selected invocation/digest; unsupported/invalid banner refuses analysis; cancelled fingerprint launches nothing                  |
| `-h`, `--help`                  | REA named command help and MCP contract discovery                                | Actual SDK/Ajv validation and public CLI grammar; schemas retain provider/options correlation                                                     |

## Interpretation and verification scope

[processing.py](https://github.com/onekey-sec/unblob/blob/1fcc7a0a584a70a96c31f5a276c20944d199a089/python/unblob/processing.py)
defines stage order, skip dispositions, multifile consumption, intermediate
deletion and skip-extraction early return. Stat, MD5/SHA-1/SHA-256, magic, native
randomness, custom diagnostics and unordered multifile constituents remain
observations. Chunk IDs are producer-local. Decompressed children have unknown
original byte offsets. Neither signatures nor randomness establish encryption,
compression or valid partitions.

[plugins.py](https://github.com/onekey-sec/unblob/blob/1fcc7a0a584a70a96c31f5a276c20944d199a089/python/unblob/plugins.py)
imports explicit modules/packages and installed entrypoints before sandbox
setup; fingerprints are attribution observations, not isolation. Informational
report hooks are retained without being classified as extractor failures.
Unknown plugin processing is not asserted complete.

[dependencies.py](https://github.com/onekey-sec/unblob/blob/1fcc7a0a584a70a96c31f5a276c20944d199a089/python/unblob/dependencies.py)
uses executable lookup; missing marks and exit 1 remain useful evidence.
Known dependencies observed before a later documentation failure survive in
the typed partial observation. Published files are independently identified;
cleanup failures retain exact scope/workspace ownership for explicit retry.

The recovery design reconciles merged REA support and the open
[PR 1892](https://github.com/morluto/rea/pull/1892), audited at
`4c834053842b5b10f6703767d25e5d6a68880d21`, without importing that patch.
`extraction_gaps` binds failures to actual task/chunk/multifile identity and
retains prepublication facts, including failed publication.

Real native Linux acceptance covers public CLI/MCP identity/dependencies,
selected gzip at nonzero offset, kept carvings and suffixes, basename and magic
skips, whole-file randomness including a final short block, intermediate
deletion, unordered multifile gzip constituents, a synthetic protected ZIP and
caller-selected trusted plugin hooks. Producer-shaped
boundary tests additionally cover encrypted and
unknown chunks, malformed reports, capacity, cancellation and cleanup failure.
These fixtures do not establish all formats, arbitrary protected archives, hardware
acquisition, arbitrary installed plugins or other hosts. Container acceptance
is tracked separately; native success does not attest container support.
