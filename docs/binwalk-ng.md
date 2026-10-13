# binwalk-ng analysis and extraction

Select `binwalk-ng` explicitly to use the **4.0.0** profile. The default region
provider remains Binwalk 3.1.x, and default extraction remains Unblob 26.6.x;
see the [firmware guide](firmware-analysis.md). This integration does not install
engines, extractors, libraries or system packages.

The audited source is [binwalk-ng/binwalk-ng at
368c3815cb97976ae7ba6092f356933169f06dae](https://github.com/binwalk-ng/binwalk-ng/tree/368c3815cb97976ae7ba6092f356933169f06dae).
Its executable is still named `binwalk`; provider selection distinguishes it
from ReFirmLabs Binwalk. A version banner is a compatibility declaration, not
source attestation. Evidence records executable and selected runtime SHA-256
values; installed source revision remains `null`. Caller-built signature or
callback variants are trusted executables whose behavior is not established by
a matching banner or digest alone.

## Supply the native runtime

Linux and an existing working `bubblewrap` plus util-linux `prlimit` are
required. Set absolute paths in the shell launching REA:

```sh
export REA_BINWALK_NG_COMMAND=/absolute/path/to/binwalk
export REA_FIRMWARE_BWRAP_COMMAND=/absolute/path/to/bwrap
export REA_BINWALK_NG_RUNTIME_MANIFEST=/absolute/path/to/ng-runtime.json
# Optional: defaults to /usr/bin/prlimit.
export REA_FIRMWARE_PRLIMIT_COMMAND=/absolute/path/to/prlimit
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
loader and each required library, plus selected extractor executables and their
own libraries/support files for formats needing them. `kind` is `library`,
`executable` or `support`. Library destinations are individual files beneath
`/lib`, `/lib64`, `/usr/lib` or `/usr/lib64`; executable destinations are beneath
`/runtime/bin` or single names beneath `/bin` or `/usr/bin`; support destinations
are beneath `/runtime/support`. The engine is mounted separately at
`/runtime/bin/binwalk`. Duplicate destinations, special files and broad directory
mounts are refused. A configured symlink is resolved to a regular file and both
configured and resolved identities are retained. Runtime files cannot also be
exposed through the writable workspace.

Each operation probes the **same** actual policy used for production invocations:
separate user/PID/network/IPC/UTS namespaces, no capabilities, a new session,
parent-death handling, selected read-only runtime files and immutable input,
an owned writable `/work`, controlled HOME/tmp/cwd/environment and supervised
stdio. Host home, configuration, sockets and arbitrary host paths are absent.
There is no unrestricted fallback if the policy or runtime cannot start.
A successful `bwrap --version` alone does not establish readiness. Identity
readback detects observed drift; it does not prevent every filesystem race.

## Public CLI and MCP

```sh
rea inspect-firmware-provider --provider binwalk-ng --format json
rea inspect-firmware-regions /path/firmware.bin --provider binwalk-ng \
  --offset 64 --length 4096 --include gzip --workers 2 --no-mmap
rea inspect-firmware-regions /path/firmware.bin --provider binwalk-ng \
  --search-all --exclude tar
rea carve-firmware /path/firmware.bin /path/new-carvings
rea extract-firmware /path/firmware.bin /path/new-output \
  --provider binwalk-ng --carve --recursive --max-depth 3
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
rejected rather than ignored. Recursion defaults to true for ng extraction;
`--no-recursive` disables it. Every output directory must be absent and absolute
with an existing parent. Existing destinations are not overwritten.

MCP uses the same named contracts and preserves caller choices:

```json
{
  "name": "extract_firmware",
  "arguments": {
    "provider_id": "binwalk-ng",
    "path": "/path/firmware.bin",
    "output_directory": "/path/new-output",
    "range": { "offset": 64, "length": 4096 },
    "max_depth": 3,
    "options": {
      "include": ["gzip"],
      "workers": 2,
      "no_mmap": true,
      "carve": true,
      "recursive": true
    }
  }
}
```

`carve_firmware` accepts scan options and output budgets. `inspect_firmware_entropy`
accepts selection/output budgets and optional `output_directory`, with no scan
options. `inspect_firmware_provider` accepts only `provider_id: "binwalk-ng"`:
it returns corpus Evidence with `subject: null`, native format/extractor labels,
reported counts and runtime fingerprints. An extractor label does not establish
its availability. Ambiguous native display rows remain raw/unparsed and cause
partial inventory coverage; absent color leaves `requires_search_all` unknown.
Inventory does not probe the `entropy-plot` feature. Invalid UTF-8 output is
retained as raw command evidence with its retained-byte SHA-256, byte counts
and encoding validity; it is not normalized into format names. Valid U+FFFD
is preserved. Bounded command captures retain these facts on cancellation,
output-limit failure and cleanup uncertainty.

## Interpret the observations

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

Recursive extraction uses a bounded queue of separate one-pass invocations,
not native unrestricted `--matryoshka`. It honors native `do_not_recurse`,
deduplicates actual file identities, skips empty/nonregular files and records
depth/budget/unexamined conditions. Extracted code is never executed.
Only regular files are published with private nonexecutable permissions;
links/special entries are metadata. Publication uses exclusive writes and
readback, not an atomic directory rename. Failed uncommitted output is rolled
back; durable publication stays reported even if later cleanup fails.

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

## Limits and cleanup

Nonempty regular inputs are copied with original basename and SHA readback,
maximum **128 MiB** before native launch. One heavy operation may be outstanding
per provider, including admitted work that has not started; busy admission is
refused. One **120-second** deadline includes runtime preparation, identity
checks, analysis and recursive passes. JSON/combined diagnostics are bounded at
**8 MiB**. Per-process address space is **1 GiB**, CPU time 120 seconds and core
size zero. These are not aggregate process-memory limits.

Staging defaults to **256 MiB / 10,000 entries**, configurable through
`max_output_bytes` / `max_output_files` up to 512 MiB / 100,000 entries. Depth
defaults to 3, allowed 1–10. Polled growth budgets can transiently overshoot and
are not filesystem quotas. Cancellation terminates supervised descendants before
workspace deletion. Failed process/descriptor/publication cleanup retains its
actual owner for cleanup-only retry; new heavy work remains refused while
cleanup cannot finish.

## Source capability ledger

Disposition covers every field in the pinned
[CLI parser](https://github.com/binwalk-ng/binwalk-ng/blob/368c3815cb97976ae7ba6092f356933169f06dae/src/cli_parser.rs).
The adapter owns fixed argv and private paths; it exposes no arbitrary argv proxy.

| Native option          | REA disposition                                                             | Verification scope                                            |
| ---------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `FILE`                 | Immutable selected snapshot; original basename; `path`/`range`              | Actual public CLI/MCP gzip and 128 MiB admission              |
| `--list`, `-L`         | `inspect_firmware_provider`; actual native inventory                        | Actual CLI/MCP; ambiguous rows retained partial               |
| `--quiet`, `-q`        | Adapter-owned presentation for report workflows                             | Command boundary; raw diagnostics retained                    |
| `--verbose`, `-v`      | Presentation-only, not a caller option; structured per-pass facts preserved | Pinned display/main source audit                              |
| `--extract`, `-e`      | `extract_firmware`                                                          | Actual CLI/MCP gzip extraction                                |
| `--carve`, `-c`        | `carve_firmware`; extraction `options.carve`                                | Actual CLI/MCP carving and extract+carve                      |
| `--matryoshka`, `-M`   | Bounded REA one-pass queue; not forwarded                                   | Actual recursive gzip; boundary limits/do-not-recurse tests   |
| `--search-all`, `-a`   | `options.search_all` / `--search-all`                                       | Command boundary; native source semantics                     |
| `--entropy`, `-E`      | Separate `inspect_firmware_entropy`                                         | Actual CLI/MCP; 2047/2048/2049 native windows                 |
| `--png`, `-p`          | Always private owned path; optional fresh publication                       | Actual private/published PNG; feature-disabled native refusal |
| `--log`, `-l`          | Always private bounded JSON report, no caller path                          | Parser and producer boundary tests                            |
| `--threads`, `-t`      | Positive `options.workers` / `--workers`, default 1                         | Actual CLI worker_count 2 and strict contract                 |
| `--exclude`, `-x`      | Exact names, repeated CLI options; conflicts with include                   | Strict schema and fixed command boundary                      |
| `--include`, `-y`      | Exact names; conflicts with exclude                                         | Actual CLI/MCP gzip selection                                 |
| `--directory`, `-d`    | Owned per-pass staging; separate caller publication directory               | Actual fresh outputs and ownership failure controls           |
| `--no-mmap`            | `options.no_mmap` / `--no-mmap`                                             | Actual CLI selection and fixed command boundary               |
| Generated help/version | Lifecycle/compatibility probe; no help/argv proxy                           | Actual same-policy version probe                              |

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

With the supplied prerequisites, run the public native lane:

```sh
npm run test:focused -- tests/acceptance/providers/binwalkNgNative.test.ts
```

`REA_FIRMWARE_TEST_ENTRYPOINT` selects an isolated installed npm package's
`scripts/rea.mjs`. Optional `REA_NG_BOUNDARY_FIXTURE_ROOT` selects an independently
prepared manifest with actual 128 MiB and plus-one fixtures;
`REA_BINWALK_NG_TEST_NO_ENTROPY_COMMAND` selects a separately built actual
feature-disabled executable. Missing selected prerequisites skip those cases;
report skips as unverified, not native conformance.

Native Linux x64 gzip, reported inventory, selected coordinates, carving,
bounded extraction, entropy, public converted schemas and source immutability
are the exercised formats. Other signature/extractor families, proprietary
images and other hosts/architectures remain unverified. A fixture pass does not
attest all listed formats or caller-built variants.

**Public container execution is not implemented at this native checkpoint.**
Direct producer container smoke tests do not establish public REA container
support. A future typed mode must satisfy the same observed descendant/runtime
policy, immutable image/runtime identity and owned cleanup; no weaker isolation
or host socket/broad directory mount is a supported fallback.
