# Firmware analysis

REA accepts **Binwalk 3.1.x** for default region inspection and **Unblob 26.6.x**
for explicit Unblob inspection, provider inventory and extraction. Omitted
provider selection preserves Binwalk inspection and Unblob extraction. The report parsers are verified with Binwalk 3.1.0 and
Unblob 26.6.4. Another build on those lines is accepted, the observed version
is reported, and a limitation records that the parser was not verified against
that build. This first firmware milestone is verified on Linux x64.
No device, root privilege, mount, emulation or execution of extracted programs
is needed. Arbitrary firmware bytes do not pass native executable admission;
select a returned ELF separately for supported Ghidra analysis.

On Linux, Binwalk and Unblob run as REA-owned processes and require a
procps-compatible `ps` on REA's `PATH`; see the shared
[Linux process prerequisite](installation.md#linux-owned-process-prerequisite).

## Caller-supplied tools

Provide existing tools using absolute executable paths, scoped to your shell:

```sh
export REA_BINWALK_COMMAND=/absolute/path/to/binwalk
export REA_UNBLOB_COMMAND=/absolute/path/to/unblob
```

REA does not install these tools, their dependencies or system packages. It
checks the tool's `--version` banner when executing a request. Binwalk must
print `binwalk <version>` and Unblob must print the version alone. Inspection and
extraction have independent prerequisites; one does not require the other.
Both require util-linux `prlimit`, normally `/usr/bin/prlimit`; override its
absolute path with `REA_FIRMWARE_PRLIMIT_COMMAND` if needed.

REA retains at most 8 MiB of combined stdout and stderr per command. Exceeding
that diagnostic budget stops analysis with an explicit truncated-output error;
child process limits do not bound parent-side pipe retention. Completed commands
drain their output streams before recording diagnostics. Failed worker cleanup
retains the worker and workspace for retry before another request or at shutdown.

Unblob needs the external extractor for the selected format on its inherited
`PATH`: for example, `debugfs` for ext2/ext3/ext4. Native sandbox setup and default skip rules stay enabled. Landlock can silently
fall back in the native producer; REA reports isolation as unverified. Reported
sandbox startup failures remain actionable errors;
REA does not retry with `--no-sandbox`. Missing extractors reported in a valid
analysis report retain partial results and dependency names inline.

Upstream sources are preserved unmodified as optional pinned submodules:

```sh
git submodule update --init third_party/binwalk third_party/unblob
```

Normal REA builds and npm packages do not include or build these sources or
engine binaries. See [upstream provenance](https://github.com/morluto/rea/blob/main/third_party/README.md).

## CLI and MCP

```sh
rea inspect-firmware-regions /path/to/firmware.bin
rea inspect-firmware-provider --provider-id unblob
rea inspect-firmware-regions /path/to/firmware.bin --provider-id unblob \
  --offset 64 --length 82 --workers 2 --randomness-depth 1
rea extract-firmware /path/to/firmware.bin /path/to/new-output
rea extract-firmware /path/to/firmware.bin /path/to/selected-output \
  --offset 64 --length 4096 --max-depth 3
```

The corresponding MCP tools accept the same intent:

```json
{
  "name": "inspect_firmware_regions",
  "arguments": { "path": "/path/to/firmware.bin" }
}
```

```json
{
  "name": "extract_firmware",
  "arguments": {
    "path": "/path/to/firmware.bin",
    "output_directory": "/path/to/new-output",
    "range": { "offset": 64, "length": 4096 },
    "max_depth": 3
  }
}
```

Both return Evidence with the original path and SHA-256, raw producer reports,
actual executable path/digest, version and limitations. Binwalk signature UUIDs
and Unblob blob IDs are producer-local identities; compare content hashes and
source ranges across runs. A matching version does not attest an installed
build's source revision, so that field remains unknown.

### Unblob selection and recovery

`inspect_firmware_provider` accepts `{ "provider_id": "unblob" }`, optionally
with `options.plugins_path`. Its Evidence subject is null because no firmware
file is examined. It reports the selected executable and digest, native version,
external executable lookup marks and the native public handler documentation.
Missing dependencies produce a useful partial inventory even when the native
callback exits 1. A PATH lookup does not prove an extractor works. Public DOC
entries omit private handlers and handlers without documentation; installed
entrypoint inventory and source revision remain unknown.

For explicit Unblob inspection, use `provider_id: "unblob"` and optional
`options`: `workers`, `randomness_depth`, `skip_magic`, `skip_extensions` and
`plugins_path`. `skip_magic` is `{ "mode": "append" | "replace", "values": [] }`;
CLI `--clear-skip-magics` chooses replacement and repeatable `--skip-magic`
adds literal prefixes. Repeatable `--skip-extension` replaces native defaults
when supplied. Native argv values stay single tokens, including flag-like text.
An immutable snapshot keeps the original basename, so `.rlib` skipping applies
even when a range is selected. Omitted options retain native skip rules.

Inspection uses native `--skip-extraction`: a recognized chunk returns before
carving, extraction and unknown-chunk randomness. A wholly unrecognized input
can still produce whole-file randomness when `randomness_depth` is positive;
REA defaults it to 0. Measurements preserve Shannon percentages (0–100%),
chi-square probability percentages, their native window and raw byte-weighted
means. The window is `clamp(floor(length / 80), 1024, 1048576)`; both vectors
must cover `ceil(length / window)` blocks, including a final short block.
They establish neither encryption nor compression.

Extraction additionally accepts `keep_extracted_chunks`,
`delete_extracted_files: { "mode": "none" | "all" | "selected", "handlers": [] }`
(`handlers` only for selected mode), `carve_suffix` and `extract_suffix`.
CLI equivalents are `--keep-extracted-chunks`, `--delete-extracted-files`,
repeatable `--delete-handler`, `--carve-suffix` and `--extract-suffix`.
Suffixes must be nonempty filenames without separators. Native fully extracted
intermediate deletion remains `DeletedReport` metadata; REA never publishes an
absent deleted file. Native carvings are kept only when requested, and a
whole-file recognized chunk can skip carving in the producer.

`extraction_gaps` ties named missing dependencies and extraction failures to the
actual task, chunk or multifile stage. Root correspondence is provided only
where bytes match the selected source. Repeated dependency names aggregate only
within the same producing stage; every native report occurrence remains in raw
diagnostics. Unknown chunks, encrypted chunks, unpublished entries and depth
limits have explicit continuation text. Reentering a nested child or restarting
the depth budget at depth 10 requires that exact independently verified,
committed, nonempty regular child within the input limit. A failed publication retains raw reports,
stat/hash/magic/randomness/multifile/deletion and gap observations in the typed
error without describing uncommitted paths as published. REA installs nothing,
chooses no alternate extractor and never automatically retries analysis.

### Trusted plugins

`--plugins-path /absolute/file.py` or a directory explicitly selects trusted
Python code. REA fingerprints every regular file in that selection, rejects
links and special entries, and checks identity before and after producer
commands. Python bytecode cache writes are disabled in the child environment
so importing a package does not mutate the selected source tree. Hashes and
sizes refer to the same admitted descriptor. Rechecks observe attribution;
they cannot prevent changes between checking and import. Native handler,
directory-handler and report hooks can execute before Landlock setup.
Unselected installed entrypoints can also import with unknown inventory.
Fingerprinting does not establish isolation.

Custom reports remain inline raw diagnostics, including caller evidence that
looks like a password. An informational custom report alone does not establish
an extractor failure. An explicit `ERROR` inside a chunk or multifile extraction
report identifies a problem at that producing stage even when its report type
is unfamiliar; REA retains the original report and invents no dependency names.
Uninterpreted plugin processing remains explicitly
unknown. Identity drift fails with retained producer observations and unknown
plugin attribution; cleanup ownership remains available for retry.

See the [Unblob capability ledger](unblob-capabilities.md) for every native CLI
option, source pin, acceptance scope and excluded authority.

### Interpret the results

- Region offsets refer to bytes in the original firmware. `reported_size`
  preserves Binwalk's output; `size_basis=provider_reported_validation_unknown`
  reflects that Binwalk can replace unknown lengths with the next signature or
  EOF before serialization. Neither a signature nor its confidence byte proves
  a valid partition, encryption or runtime behavior.
- Extraction returns regular file paths, independently verified SHA-256 values,
  producer hashes when available, chunks, diagnostics and task derivations.
  Unblob's task report is unordered; REA resolves relationships by paths and
  blob IDs. Logical references use `$input`, `$output`, or `$output/<relative-path>`
  so a real file named `$input` stays distinct from the original input.
  Chunk offsets belong to the task's input file. Only chunks in the
  selected input have a known `root_file_range`, adjusted by the selected offset.
- Decompressed children have unknown original byte ranges and runtime addresses.
  Task lineage does not establish a byte-for-byte mapping through decompression.
- `partial` marks unknown/encrypted chunks, reported extraction problems,
  unpublished links/special files or reached depth limits. `complete` means the
  engine finished its configured extraction without those reported conditions;
  default skip rules and format coverage still apply. It does not establish
  complete firmware reconstruction.
- `extraction_gaps` makes those conditions recoverable: a row identifies an
  unextracted region or a failed task/stage. A chunk retains its identity and
  byte range, plus its original-file range when it belongs to the selected input.
  A multi-file stage retains its reported ID and handler with unknown byte ranges;
  a standalone task failure keeps unavailable stage identity null. Rows retain exact dependency names from
  the producer's missing-dependency reports; an accepted report with no names
  remains a failure with unknown dependencies; no executable identity or specific installation step is inferred. Each row's `continuation_id`
  references one instruction in `extraction_continuations`, so many regions
  share recovery prose without losing any region identity. Instructions use
  already configured capabilities where one exists. Every extraction rerun
  requires a fresh absent `output_directory`, preserving the prior evidence.
  Nested unknown chunks use `inspect_firmware_regions` on the actual published
  child rather than repeating the same extraction with unchanged handlers.
  Inspection requires separately configured Binwalk (`REA_BINWALK_COMMAND`);
  without it, the inspection step is unavailable and the region remains unexamined. A listed gap does not
  mean the target is corrupt or that a retained region is empty; REA installs
  nothing.
- The destination must be absent, absolute, with an existing parent. Publication
  uses exclusive, symlink-resistant writes and durable digest readback. Existing
  destinations are never overwritten. This is not an atomic directory rename:
  a new tree can be visible while files are written. Failed uncommitted output
  is rolled back. Symlinks and special files are recorded without publication;
  empty directories, ownership and executable permission bits are not reproduced.

Select a verified native child for the existing tools:

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "/path/from/extraction/usr/bin/program",
    "provider_id": "ghidra"
  }
}
```

Then use `analyze_function`, `inspect_native_api` or the other native primitives.
Native architecture and executable validation still apply. Generic
[MIPS ELF](ghidra-mips.md) and [RISC-V ELF](ghidra-riscv.md) lanes are separate
documents with their own admission boundaries. This milestone does
not add PPC decompilation, raw flash load profiles, bootloader/device
tree semantics, vulnerability scanning, emulation or hardware runtime capture.

## Resource and lifecycle policy

- Nonempty regular firmware inputs: at most **128 MiB**, copied and hashed into
  a private workspace before analysis. No in-place source modification.
- One outstanding heavy operation per provider instance in total. Concurrent
  admission fails busy; there is no additional waiter. Binwalk uses one thread;
  Unblob `options.workers` / CLI `--workers` accepts a positive integer, defaults
  to 1 and appears as the actual selected `engine.worker_count`. Resource limits
  can prevent large worker selections from completing.
- **120-second** deadline; inherited **1 GiB per-process address-space** limit,
  120 CPU seconds and zero core-dump allowance through `prlimit`.
- JSON reports: at most **8 MiB** and valid UTF-8; malformed encoding and
  oversized reports fail without repairing or truncating producer data.
  Diagnostic output is bounded with exact captured byte counts.
- Default staging budget: **256 MiB** and **10,000 entries**, configurable using
  `max_output_bytes` / `max_output_files` (CLI `--max-output-bytes` /
  `--max-output-files`). Depth defaults to 3, allowed range 1–10.

Staging budgets are polled and rechecked after exit; short-lived overshoot is
possible. The inherited file-size limit bounds each file, not total storage;
address-space limits are per process, not an aggregate memory quota. Worker
count is not CPU affinity for every external extractor. These limits do not
claim cgroup/container containment. Cancellation cleans the owned process group
before removing its workspace; uncertain cleanup retains resources and blocks
further operations in that provider instance.

## Verification

Generate small public, source-derived fixtures into ignored `_reference/`:

```sh
npm run fixtures:firmware
npm run verify:firmware
```

Fixture generation requires existing Python 3 and a host C compiler (`cc`);
override with `REA_FIRMWARE_PYTHON` / `REA_FIRMWARE_CC`. The independent oracle
records gzip offset/length and extracted file hashes. Real verification checks
CLI/MCP, full-file and selected-range extraction, unknown chunks, depth limits,
content parity and unchanged source bytes. No binary fixture is committed.

The optional missing-extractor lane asserts dependency names and the owning
handler in `extraction_gaps`. Those assertions must be run against the pinned
Unblob release to establish real-provider coverage; synthetic producer fixtures
alone do not verify Unblob's report nesting or stage identities. The gap ownership
claims remain unverified against real Unblob until that lane runs.

Additional lanes are explicit, so the base lane stays small:

```sh
# Existing mke2fs and debugfs required; put debugfs on the scoped PATH.
REA_FIRMWARE_VERIFY_EXT4=1 npm run fixtures:firmware
REA_FIRMWARE_VERIFY_EXT4=1 npm run verify:firmware

# Existing Ghidra 12.1.x and its declared JDK required.
REA_FIRMWARE_VERIFY_GHIDRA=1 npm run verify:firmware
```

`REA_FIRMWARE_MKE2FS_COMMAND` selects the optional ext4 fixture producer.
`REA_FIRMWARE_FIXTURE_ROOT` selects generated data storage.
`REA_FIRMWARE_TEST_ENTRYPOINT` can select an isolated installed npm package's
`scripts/rea.mjs` to verify the packaged CLI/MCP workflow. Real coverage here is
generated gzip/USTAR/ext4 with a Linux x64 ELF child; SquashFS, UBIFS, proprietary
firmware, other hosts and architectures remain unverified.
