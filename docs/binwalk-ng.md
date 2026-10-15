# Binwalk-NG analysis and carving

The independent Binwalk-NG provider admits three firmware-analysis workflows on
Linux when the caller supplies a pinned runtime and the host exposes a working
user-systemd cgroup v2 manager: one-pass region scan, entropy analysis and
internal carving. Provider inventory is a separate fourth operation. External
helper extraction remains unavailable before input reads because
signature-selected external helpers and their exact paths are not admitted. REA never installs engines, extractors, libraries or system
packages. The default region provider remains Binwalk 3.1.x. See the
[firmware guide](firmware-analysis.md) for provider selection.

The audited source is [binwalk-ng/binwalk-ng at
368c3815cb97976ae7ba6092f356933169f06dae](https://github.com/binwalk-ng/binwalk-ng/tree/368c3815cb97976ae7ba6092f356933169f06dae).
Its executable is still named `binwalk`; provider selection distinguishes it
from ReFirmLabs Binwalk. A version banner is a compatibility declaration, not
source attestation. REA records executable and selected runtime SHA-256 values
while the installed source revision remains unknown. Caller-built signature or
callback variants are trusted executables whose behavior is not established by
a matching banner or digest alone.

## Runtime requirements

Configure the exact upstream `binwalk-ng` executable, a runtime manifest that
lists each required regular file, bubblewrap, and a systemd user manager with
cgroup v2 memory, swap, task and CPU controllers. `systemd-run` defaults to
`/usr/bin/systemd-run`; `prlimit` defaults to `/usr/bin/prlimit`. REA fails
closed if effective limits cannot be read back in the service. Before any
service process starts, systemd unsets a fixed list of glibc dynamic-loader
controls, including `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` and
`GLIBC_TUNABLES`, even when they were absent from the manager snapshot. It also
unsets manager variables captured for defense in depth. This pre-exec step
protects the dynamically linked `/usr/bin/env` itself from concurrent manager
changes. The unit then starts `/usr/bin/env -i` before the Node gate or
interpreter; it supplies only `PATH=/usr/bin:/bin` and the REA process-run
identity. The gate launches the selected tool under its own minimal child
environment.

```sh
export REA_BINWALK_NG_COMMAND=/absolute/path/to/binwalk
export REA_FIRMWARE_BWRAP_COMMAND=/absolute/path/to/bwrap
export REA_BINWALK_NG_RUNTIME_MANIFEST=/absolute/path/to/ng-runtime.json
# Optional: defaults to /usr/bin/prlimit.
export REA_FIRMWARE_PRLIMIT_COMMAND=/absolute/path/to/prlimit
# Optional: defaults to /usr/bin/systemd-run.
export REA_FIRMWARE_SYSTEMD_RUN_COMMAND=/absolute/path/to/systemd-run
```

The runtime manifest declares **individual regular files**, not directories.
For example, this is the shape of a library declaration; replace the source and
loader destination with paths required by your existing executable:

```json
{
  "profile": "binwalk-ng-4.0.0",
  "mounts": [
    {
      "source": "/absolute/path/to/liblzma.so.5",
      "destination": "/lib64/liblzma.so.5",
      "kind": "library"
    }
  ]
}
```

That one-file example is not a complete runtime. Supply the actual dynamic
loader and each required library. External extractor executables and their
libraries/support files are not admitted by the current provider. `kind` is `library`,
`executable` or `support`. Library destinations are individual files beneath
`/lib`, `/lib64`, `/usr/lib` or `/usr/lib64`; executable destinations are beneath
`/runtime/bin` or single names beneath `/bin` or `/usr/bin`; support destinations
are beneath `/runtime/support`. The engine is mounted separately at
`/runtime/bin/binwalk`. Duplicate destinations, special files and broad directory
mounts are refused. A configured symlink is resolved to a regular file and both
configured and resolved identities are retained. Runtime files cannot also be
exposed through the writable workspace.

Production invocations use separate user/PID/network/IPC/UTS namespaces, no
capabilities, a new session, parent-death handling, selected read-only runtime
files and immutable input, a private writable `/work`, controlled HOME/tmp/cwd
and stdio. The private work root must be tmpfs. A dedicated user-systemd unit
sets `MemoryMax=512 MiB`, `MemorySwapMax=0`, `TasksMax=64`, `CPUQuota=100%`,
`RuntimeMaxSec=120s`, `KillMode=control-group` and `OOMPolicy=kill`. A Node gate
inside that unit verifies effective cgroup v2 controls and the tmpfs mount
before it launches the existing bubblewrap/prlimit policy. Run identity is
placed in the service and native child for owned cleanup. A successful
`bwrap --version` alone does not establish readiness. Identity readback detects
observed drift; it does not prevent every filesystem race.

## Public CLI and MCP contracts

CLI and MCP expose the same named contracts. Inventory, region scan, entropy
and internal carving execute only through the verified native boundary.
Extraction returns `AnalysisCapabilityUnavailableError` before reading the
selected firmware path or starting a tool. Supported commands include:

```sh
rea inspect-firmware-provider --provider binwalk-ng --format json
rea inspect-firmware-regions /path/firmware.bin --provider binwalk-ng \
  --offset 64 --length 4096 --include gzip --workers 2 --no-mmap
rea inspect-firmware-regions /path/firmware.bin --provider binwalk-ng \
  --search-all --exclude tar
rea inspect-firmware-entropy /path/firmware.bin --offset 64 --length 4096
rea inspect-firmware-entropy /path/firmware.bin \
  --output-directory /path/new-plot
```

Repeat `--include` or `--exclude` for multiple exact native signature names.
They are mutually exclusive. Names must be representable as UTF-8: unpaired
UTF-16 surrogates are refused before provider admission, while valid Unicode,
intentional U+FFFD, spaces and flag-like names remain exact values. Commas and
NUL are not native signature-name values. `--workers` is positive, default 1; `--no-mmap`
preserves the native opt-out. Ng-only options on legacy provider requests are
rejected rather than ignored. Binwalk-NG extraction and recursive extraction
are unavailable; `extract-firmware --provider binwalk-ng` returns a named
capability-unavailable error before reading the input. Its CLI help does not
advertise Binwalk-NG scan, carve, or recursion options. The separate
`carve-firmware` command supports bounded internal carving. Every published
output directory must be absent and absolute with an existing parent. Existing
destinations are not overwritten.

The current operation scope is scan, entropy, runtime inventory and internal
carving. External-helper extraction and recursive extraction are unavailable.
The integration has no firmware flash/update,
boot/emulation, JTAG/UART, glitching or hardware-control operation. Native
execution is Linux-only and requires effective cgroup v2 controls plus the
bubblewrap policy. REA caller-provisioned-container execution is not
implemented.

## Request and output semantics

MCP uses the same named contracts. A request selecting Binwalk-NG for
`extract_firmware` returns capability-unavailable before target reads. The
request must not imply that its otherwise shared extraction fields are active:

```json
{
  "name": "extract_firmware",
  "arguments": {
    "provider_id": "binwalk-ng",
    "path": "/path/firmware.bin",
    "output_directory": "/path/new-output",
    "range": { "offset": 64, "length": 4096 },
    "max_depth": 3
  }
}
```

Use `carve_firmware` for the supported internal carve operation; it accepts
scan selection and bounded output budgets without invoking external helpers.

`carve_firmware` publishes internally carved files through a bounded private
tmpfs, framed digest-checked transfer and exclusive `SafeOutputTree`. It accepts
scan options and output budgets. `inspect_firmware_entropy` accepts selection/output
budgets and optional `output_directory`, with no scan options.
`inspect_firmware_provider` accepts only `provider_id: "binwalk-ng"` and
return corpus Evidence with `subject: null`, native format/extractor labels,
reported counts and runtime fingerprints. An extractor label would not
establish its availability. Ambiguous native display rows would remain
raw/unparsed and cause partial inventory coverage; absent color would leave
`requires_search_all` unknown. Inventory would not probe the `entropy-plot`
feature. Invalid UTF-8 output would be retained as raw command evidence with
its retained-byte SHA-256, byte counts and encoding validity; it would not be
normalized into format names. Valid U+FFFD would be preserved. Bounded command
captures would retain these facts on cancellation, output-limit failure and
cleanup uncertainty.

### Interpretation of admitted observations

The JSON report is an array of per-file analyses. Signature/extractor IDs are
provider-local; array ordering is not a lineage authority. Local ranges remain
local. A root-file offset is adjusted once by the caller's selected offset only
when byte correspondence is established. Reported size/confidence and signatures
do not establish partition validity, authenticity, encryption or runtime maps.

Native exit zero can include failed extractions. Native extraction diagnostics
not present in its JSON remain unknown. Empty analyses can represent a read
failure or a skipped/empty file: `examination: "unknown"` and
`coverage: "none_reported"` do not claim successful examination. Signature scan
coverage is distinct from complete firmware reconstruction.

REA inventories actual artifacts independently because native carving files
can be absent from JSON. Current `byte_correspondence: "verified"` requires
comparison against source bytes and final digest/readback; earlier verified
`carving_observation` can survive a later mutation without falsely identifying
the new bytes. Unattributed files, links and special entries remain explicit
with unknown lineage and partial coverage. Decompressed children have unknown
original file ranges and runtime addresses.

Internal carving is supported under the bounded native boundary. External and
recursive extraction remain unavailable; REA does not execute carved files.

Entropy is the native Shannon measurement, **0–8 bits per byte**, with measured
start/end coordinates. Below 2048 bytes native uses one whole-input window;
2048 and 2049 bytes produce one-byte windows. REA does not interpolate or infer
compression/encryption. The entropy build feature is required; native rejection
becomes a named capability-unavailable error with retained stderr.
A private PNG is **always** requested because native entropy creates a plot even
without a caller path. Its bounded header verifies 2048×1024 dimensions and
SHA-256, not a full image decode. The optional output directory controls only
publication; otherwise the verified plot is `unpublished` with a null public
path. Verified private facts survive publication refusal/cancellation when the
producer completed them.

### Enforced limits and cleanup

Each native invocation runs in a transient user-systemd unit with effective
cgroup v2 `memory.max` ≤ 512 MiB, `memory.swap.max=0`, `pids.max` ≤ 64 and
`cpu.max` ≤ 100%. The unit also applies a 120-second runtime, kills the whole
control group and uses an OOM group. The in-unit gate checks these controls and
the private tmpfs before launching the provider. Per-process `prlimit` and
REA's request deadline remain additional limits, not substitutes for cgroups.

Nonempty regular inputs are copied with original basename and SHA readback,
maximum **128 MiB** before native launch. One heavy operation may be outstanding
per provider, including admitted work that has not started; busy admission is
refused. One **120-second** deadline includes runtime preparation, identity
checks, analysis and recursive passes. JSON/combined diagnostics are bounded at
**8 MiB**. Per-process address space is **1 GiB**, CPU time 120 seconds and core
size zero. These are not aggregate process-memory limits.

The shared request schema accepts budgets up to 512 MiB / 100,000 entries.
Binwalk-NG scan and entropy reports are capped at 8 MiB. Internal carving
honors lower caller limits under hard ceilings of 512 MiB for the private
workspace (including the report) and 10,000 files; tmpfs byte and inode quotas
enforce producer-time limits, and the framed transfer independently checks
aggregate bytes, files, entries and hashes before exclusive publication.
Cancellation carries
an REA-generated run token into the service and provider process. Failed
process/descriptor cleanup retains its owner for cleanup-only retry.

## Source capability ledger

Disposition covers every field in the pinned
[CLI parser](https://github.com/binwalk-ng/binwalk-ng/blob/368c3815cb97976ae7ba6092f356933169f06dae/src/cli_parser.rs).
The adapter owns fixed argv and private paths; it exposes no arbitrary argv proxy.

| Native option          | REA disposition                                                             | Verification scope                                             |
| ---------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `FILE`                 | Immutable selected snapshot; original basename; `path`/`range`              | Native CLI/MCP acceptance                                      |
| `--list`, `-L`         | `inspect_firmware_provider`                                                 | Native CLI/MCP acceptance                                      |
| `--quiet`, `-q`        | Adapter-owned presentation for report workflows                             | Native boundary                                                |
| `--verbose`, `-v`      | Presentation-only, not a caller option; structured per-pass facts preserved | Pinned source audit                                            |
| `--extract`, `-e`      | `extract_firmware`; unavailable before target read                          | Admission refusal; external helper identity not admitted       |
| `--carve`, `-c`        | `carve_firmware`; internal carving only                                     | Native CLI/MCP real acceptance; tmpfs + framed output ceilings |
| `--matryoshka`, `-M`   | Not forwarded; recursive extraction unavailable                             | Excluded                                                       |
| `--search-all`, `-a`   | `options.search_all` / `--search-all`                                       | Native CLI/MCP acceptance                                      |
| `--entropy`, `-E`      | Separate `inspect_firmware_entropy`                                         | Native CLI/MCP acceptance                                      |
| `--png`, `-p`          | Private owned path; optional fresh publication                              | Native entropy acceptance                                      |
| `--log`, `-l`          | Private JSON report, no caller path                                         | Native scan/entropy acceptance                                 |
| `--threads`, `-t`      | Positive `options.workers` / `--workers`, default 1                         | Native CLI acceptance                                          |
| `--exclude`, `-x`      | Exact names, repeated CLI options; conflicts with include                   | Strict schema and fixed command boundary                       |
| `--include`, `-y`      | Exact names; conflicts with exclude                                         | Native CLI/MCP selection                                       |
| `--directory`, `-d`    | Provider-owned private workspace                                            | Fixed command boundary                                         |
| `--no-mmap`            | `options.no_mmap` / `--no-mmap`                                             | Native CLI acceptance                                          |
| Generated help/version | Internal compatibility probes; no help/argv proxy                           | Native provider inventory                                      |

Additional protocol sources:
[main](https://github.com/binwalk-ng/binwalk-ng/blob/368c3815cb97976ae7ba6092f356933169f06dae/src/main.rs),
[JSON](https://github.com/binwalk-ng/binwalk-ng/blob/368c3815cb97976ae7ba6092f356933169f06dae/src/json.rs),
[analysis](https://github.com/binwalk-ng/binwalk-ng/blob/368c3815cb97976ae7ba6092f356933169f06dae/src/binwalk_ng.rs),
[magic](https://github.com/binwalk-ng/binwalk-ng/blob/368c3815cb97976ae7ba6092f356933169f06dae/src/magic.rs),
[signatures](https://github.com/binwalk-ng/binwalk-ng/tree/368c3815cb97976ae7ba6092f356933169f06dae/src/signatures),
[extractors](https://github.com/binwalk-ng/binwalk-ng/tree/368c3815cb97976ae7ba6092f356933169f06dae/src/extractors),
[entropy](https://github.com/binwalk-ng/binwalk-ng/blob/368c3815cb97976ae7ba6092f356933169f06dae/src/entropy.rs).
Library custom signatures/internal callbacks have no REA wrapper; use an explicitly
selected trusted executable profile and retain its actual identity.

## Verification and remaining coverage

The dedicated Binwalk-NG availability acceptance test checks static catalog
contracts and extraction refusal before launch:

```sh
npm run test:focused -- tests/acceptance/binwalkNgAvailability.test.ts
```

The real CLI/MCP cases in `tests/acceptance/providers/binwalkNgNative.test.ts`
run when the exact runtime, runtime manifest and bubblewrap path are configured.
They cover inventory, selected scan, entropy, bounded internal carving and
explicit extraction refusal.
This verification also ran the pinned upstream binary directly inside a
disposable Podman container for `--version`, a gzip JSON scan and entropy PNG
generation, with network disabled, a read-only root filesystem, dropped
capabilities, no-new-privileges, a 64-process limit, 512 MiB memory/swap bounds
and a private `/tmp` tmpfs. This is producer CLI evidence only. The public REA
caller-provisioned-container lane remains unsupported: REA has no admitted
container-selection, identity/configuration proof or immutable input/output
mapping for this provider, and does not manage the caller's container lifecycle.

The native Linux x64 acceptance lane covers gzip signature scan, reported
inventory, selected coordinates, entropy windows, internal carving through
CLI/MCP, quota-bounded output transfer, public converted schemas and source
immutability. External-helper extraction and other signature/extractor
families, proprietary images and other hosts/architectures remain unsupported
or unverified.
The optional acceptance case using a build without `entropy-plot` was skipped
because that alternate pinned binary was not built; its refusal behavior remains
unverified.

**Public container execution is not implemented at this native checkpoint.**
Direct producer container smoke tests do not establish public REA container
support. A future typed mode must satisfy the same observed descendant/runtime
policy, immutable image/runtime identity and owned cleanup; no weaker isolation
or host socket/broad directory mount is a supported fallback.

See the [Binwalk-NG verification record](binwalk-ng-verification.md) for exact
validation results and the scoped mutation checks.
