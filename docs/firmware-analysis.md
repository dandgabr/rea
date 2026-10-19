# Firmware analysis

REA supports **Binwalk 3.1.x** region inspection. Native Unblob inventory, scan
and bounded extraction are exposed when both absolute runtime variables are
configured; this configuration-based availability is not proof of a successful
analysis. Its admission gate requires a protected runtime whose interpreter,
Python import roots and ancestors are not owned or writable by the invoking
user; the disposable caller-owned runtime root does not meet that condition.
The interpreter must use `/usr/bin` or `/usr/local/bin` and the standard
`/usr/{,local/}lib{,64}/pythonX.Y` roots.
Caller-container Unblob remains unavailable.
The implementation checks its systemd boundary before Python imports Unblob and
is designed to apply fixed cgroup, filesystem, network and device controls.
Extraction is designed to stay in a private 64 MiB, 512-inode tmpfs and stream
framed files into `SafeOutputTree` before verified publication. Prior firmware
lanes ran on Linux x64; they do not verify the revised Unblob bootstrap.
Current-head CLI/MCP/systemd acceptance has not been repeated, so successful
Unblob runtime behavior remains unverified. Unblob integration remains a draft
pending maintainer scope ratification in
[#4110](https://github.com/morluto/rea/issues/4110). No device, root privilege, mount, emulation or execution of extracted programs
is needed. Arbitrary firmware bytes do not pass native executable admission;
select a returned ELF separately for supported Ghidra analysis.

On Linux, Binwalk and Unblob run as REA-owned processes and require a
procps-compatible `ps` on REA's `PATH`; see the shared
[Linux process prerequisite](installation.md#linux-owned-process-prerequisite).

## Caller-supplied tools

Provide existing tools using absolute executable paths, scoped to your shell:

```sh
export REA_BINWALK_COMMAND=/absolute/path/to/binwalk
export REA_UNBLOB_COMMAND=/absolute/runtime/root/usr/local/bin/unblob
export REA_UNBLOB_RUNTIME_ROOT=/absolute/runtime/root
```

REA does not install these tools, their dependencies or system packages. It
checks Binwalk's `--version` banner when executing a request. Binwalk must print
`binwalk <version>`. The Unblob executable, interpreter, package and runtime
dependencies must all be available inside `REA_UNBLOB_RUNTIME_ROOT`; the
configured executable must resolve inside that root. REA requires Linux user
systemd, cgroup v2, and `/usr/bin/systemd-run`. The service uses
`PrivatePIDs=yes`; systemd applies this and the other fixed unit properties
before executing a minimal Python interpreter with `-I -S`. The bootstrap then
proves `/proc/self/ns/pid` differs from the host namespace identity passed by
REA and checks effective cgroup and private tmpfs limits before execing Unblob.
An ignored or unsupported PID namespace fails closed. Interpreter ELF loading
precedes in-process checks; static `UnsetEnvironment` entries remove documented
glibc loader controls and Python startup variables before interpreter exec. A
missing bus, cgroup controller, mount control or policy check fails closed.
Caller-provided
container runtimes remain unavailable. Binwalk requires util-linux `prlimit`,
normally `/usr/bin/prlimit`; override its absolute path with
`REA_FIRMWARE_PRLIMIT_COMMAND` if needed.

REA retains at most 8 MiB of combined stdout and stderr per command. Exceeding
that diagnostic budget stops analysis with an explicit truncated-output error;
child process limits do not bound parent-side pipe retention. Completed commands
drain their output streams before recording diagnostics. Failed worker cleanup
retains the worker and workspace for retry before another request or at shutdown.

Unblob inventory and inspection report the selected runtime version and the
lookup status of external extractors such as `debugfs`; a dependency lookup
does not prove an extractor works. The fixture acceptance requires `7z` from
that same service's reported dependency inventory; unrelated absent helpers do
not block gzip/USTAR acceptance, and the host `PATH` is not used as a proxy for
the admitted runtime. Extraction reports verified published file hashes and
retains producer report lineage. The caller's `max_output_bytes` is
limited to 64 MiB and `max_output_files` to 512 filesystem entries (including
directories, symlinks and special entries); exceeding either budget fails
before any output is published. The service tmpfs reserves up to 8 MiB for
upstream helper temporaries, but its hard aggregate size never exceeds 64 MiB.
Its inode ceiling also counts directories and service files, so a deeply nested
extraction can fail below the entry-count ceiling.

Upstream sources are preserved unmodified as optional pinned submodules:

```sh
git submodule update --init third_party/binwalk third_party/unblob
```

Normal REA builds and npm packages do not include or build these sources or
engine binaries. See [upstream provenance](https://github.com/morluto/rea/blob/main/third_party/README.md).

## CLI and MCP

```sh
rea inspect-firmware-regions /path/to/firmware.bin
```

The Unblob CLI and MCP contracts describe the schemas for provider inventory,
scan-only inspection and extraction. The capability inventory exposes Unblob
when both absolute runtime variables are set; each request still validates its
protected runtime and systemd boundary. Current-head real CLI/MCP/systemd
acceptance has not been repeated, so successful runtime behavior remains
unverified. Setting both variables exposes the configured capability but does
not establish that runtime verification passed.
`inspect_firmware_regions` uses native `--skip-extraction`; `extract_firmware`
uses the service-local tmpfs transfer protocol and publishes only verified
files. An explicitly selected caller container returns
`AnalysisCapabilityUnavailableError` before starting a container or falling
back to native execution. Binwalk region inspection remains available by
default.

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

Successful Binwalk calls return Evidence with the original path and SHA-256,
raw producer reports, actual executable path/digest, version and limitations.
Binwalk signature UUIDs and the planned Unblob blob IDs are producer-local
identities; compare content hashes and source ranges across runs. A matching
version does not attest an installed build's source revision, so that field
remains unknown.

### Unblob selection and recovery

`inspect_firmware_provider` accepts `{ "provider_id": "unblob" }` and runs
inside the same systemd profile. Before importing the CLI, the `-I -S`
bootstrap audits startup files and distribution metadata, rejects all installed
`unblob_v1` entrypoints, and disables Pluggy entrypoint discovery. It never
executes `.pth`, `sitecustomize` or `usercustomize`; only the pinned setuptools
`.pth` is admitted by digest and ignored. The unit applies `MemoryMax=1 GiB`, `MemorySwapMax=0`,
`TasksMax=128`, `CPUQuota=100%`, `RuntimeMaxSec=120s`, private network/devices,
read-only system paths, and a 64 MiB/512-inode `/tmp`. Each invocation verifies
the effective namespace, cgroup, tmpfs controls and runtime immutability
in-unit in a minimal Python bootstrap. After admission, it adds audited import
paths and invokes Unblob with `runpy`; Python site initialization remains
disabled. The input snapshot is exposed read-only. Scan
reports use an individually bounded report
file; logs remain on service-local tmpfs. REA does not create or manage a
container runtime.

The host and in-unit Python startup audits each inspect at most 8,192 combined
directory entries and read each `.pth` or `entry_points.txt` file to a maximum
of 1 MiB plus one byte. Exceeding either limit refuses the invocation before
Unblob imports.

The Unblob inspection input uses `provider_id: "unblob"` and optional
`options`: `workers`, `randomness_depth`, `skip_magic`, and `skip_extensions`.
Caller-selected runtime plugins are unsupported. Installed `unblob_v1`
entrypoints are rejected before launch, and Pluggy entrypoint discovery is
disabled in the admitted interpreter. The configured runtime's Unblob source
revision remains unverified, so overall coverage remains partial even when
every observed report row is well-formed.
`skip_magic` is `{ "mode": "append" | "replace", "values": [] }`;
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

The extraction input additionally accepts `keep_extracted_chunks`,
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

### Plugin execution boundary

REA does not expose Unblob's `--plugins-path`; caller-selected runtime plugins
are outside the supported contract. The pinned CLI's dependency and handler
inventory callbacks call `plugin_manager.import_plugins()`, which normally
loads the `unblob_v1` setuptools entrypoint group. REA audits startup files and
distribution metadata before importing the CLI, rejects any installed
`unblob_v1` entrypoint, and disables Pluggy's entrypoint loader. Audited
upstream `.pth` files are admitted by digest but never executed. External helper
descendants remain caller-provided code inside the service boundary.
If user systemd, cgroup v2 or the required tmpfs controls are unavailable, native
execution fails closed. A version banner alone is not admission evidence.

Custom reports remain inline raw diagnostics, including caller evidence that
looks like a password. An informational custom report alone does not establish
an extractor failure. An explicit `ERROR` inside a chunk or multifile extraction
report identifies a problem at that producing stage even when its report type
is unfamiliar; REA retains the original report and invents no dependency names.
Handler inventory remains partial: public documentation omits handlers without
public DOC metadata, and caller runtime source revision is unknown.

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
  a private workspace before analysis. Growth beyond that allowance during
  copying receives the same typed input refusal as an already oversized file.
  Supply a stable copy within the allowance. No in-place source modification.
- One queued heavy operation per provider instance. Binwalk uses one thread;
  Unblob's caller-selected `options.workers` is reported in `engine.worker_count`.
  No automatic parallel extraction engines.
- **120-second** deadline. Binwalk uses per-process `prlimit` address-space,
  CPU and file limits; its staging budgets are polled and can transiently
  overshoot. Unblob runs in an exact transient systemd unit with 1 GiB aggregate
  `MemoryMax`, zero swap, at most 128 tasks, one CPU quota, 120 seconds,
  64 MiB `LimitFSIZE`, private network/devices, and `/tmp` tmpfs limited to
  64 MiB and 512 inodes. The in-unit gate verifies effective cgroup-v2 and
  tmpfs values before starting Python.
- JSON reports: at most **8 MiB** and valid UTF-8; malformed encoding and
  oversized reports fail without repairing or truncating producer data.
  Diagnostic output is bounded with exact captured byte counts.
- Extraction allows **4 KiB–64 MiB** and at most **512 filesystem entries** via
  `max_output_bytes` / `max_output_files` (CLI `--max-output-bytes` /
  `--max-output-files`); the schema rejects larger values. Depth defaults to 3,
  allowed range 1–10. The hard tmpfs inode ceiling includes directories, the
  report and service files, so actual extraction may stop earlier.

Unblob output is first staged inside the service-local tmpfs; the kernel enforces
aggregate storage and inode ceilings before REA consumes the framed stream. The
adapter rejects an aggregate output frame above the caller byte budget before
streaming any file, and enforces the requested entry count while walking the
service tree. `SafeOutputTree` verifies every streamed file's size and digest
before caller publication. Worker count remains a requested Unblob setting, not a CPU affinity
guarantee. Cancellation stops the exact transient unit and verifies cleanup;
uncertain cleanup retains resources and blocks further operations in that
provider instance. Caller-container Unblob is refused because the current
existing-container profile cannot prove an inode ceiling or exact lifecycle
ownership.

## Verification

Generate small public, source-derived fixtures into ignored `_reference/`:

```sh
npm run fixtures:firmware
npm run verify:firmware
```

Fixture generation requires existing Python 3 and a host C compiler (`cc`);
override with `REA_FIRMWARE_PYTHON` / `REA_FIRMWARE_CC`. The independent oracle
records gzip offset/length and extracted file hashes. Public CLI and MCP
Native Unblob is exposed when configured, but runtime support remains unverified
until the current head passes protected CLI, MCP and systemd acceptance. Historical runs
covered pinned Unblob 26.6.4 inspection and extraction through a transient
service, selected ranges, unknown chunks, depth limits, content parity, suffixes
and intermediate deletion; they do not satisfy current-head acceptance. No
binary fixture is committed.

To verify only Unblob against the generated fixture and independent oracle,
without configuring Binwalk, use:

```sh
npm run verify:unblob-firmware
```

This provider-scoped lane requires `REA_UNBLOB_RUNTIME_ROOT` and
`REA_UNBLOB_COMMAND`; it exercises provider inventory, scan and extraction via
the public CLI and MCP, then checks output file paths, sizes and SHA-256 values
against `oracle.json`. The broader `verify:firmware` lane still requires both
providers and additionally checks Binwalk region results. These commands must
run on the exact current head with a protected runtime root, user systemd and
cgroup v2 before native support can be described as verified.

The optional missing-extractor lane asserts dependency names and the owning
handler in `extraction_gaps`. Run it against the pinned Unblob release to
establish real-provider coverage; synthetic producer fixtures alone do not
verify Unblob's report nesting or stage identities.

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
