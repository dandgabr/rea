# Unblob capability and acceptance ledger

**Status: native Unblob is exposed when both absolute runtime variables are
configured. This configuration-based availability does not prove a successful
analysis. Each request fails closed unless the runtime passes its admission
checks; current-head CLI/MCP/systemd acceptance remains unverified. The gate
only admits protected runtime trees whose interpreter,
Python import roots and ancestors are not owned or writable by the invoking
user. Python interpreters must resolve under `/usr/bin` or `/usr/local/bin`,
with their standard `/usr/{,local/}lib{,64}/pythonX.Y` roots. The disposable
caller-owned runtime root does not satisfy that precondition.
Caller-container execution remains unavailable.**

**Integration gate:** this capability is proposed in a draft PR while the
required maintainer scope decision in [#4110](https://github.com/morluto/rea/issues/4110)
is pending. Draft publication does not authorize merging or enabling the
provider in official REA distributions.
The implementation is designed to run inside a user-systemd transient service.
systemd applies the service boundary before Python starts; a minimal `-I -S`
bootstrap rechecks the protected Python runtime, then audits startup files and
distribution entrypoints before importing Unblob. It never runs
`.pth`, `sitecustomize` or `usercustomize`; it admits only the known setuptools
`.pth` by exact digest and disables its execution. Any other startup hook or
any `unblob_v1` distribution entrypoint is rejected before launch. Pluggy
entrypoint loading is disabled in the admitted interpreter. The caller runtime
source revision remains unverified, so inspection/extraction coverage remains
partial. Extraction is designed to stage on a 64
MiB/512-inode service tmpfs, then transfers bounded hashed frames into a
private `SafeOutputTree` before verified publication.

The CLI and MCP contracts below describe their schemas and intended behavior.
The capability inventory exposes Unblob when both absolute runtime variables
are configured, while runtime admission still validates the protected tree and
systemd boundary for every request. Current-head real CLI/MCP/systemd
acceptance has not been repeated, so successful runtime behavior remains
unverified; configuration alone is not verification.

The producer reference is [Unblob 26.6.4](https://github.com/onekey-sec/unblob/tree/1fcc7a0a584a70a96c31f5a276c20944d199a089),
revision `1fcc7a0a584a70a96c31f5a276c20944d199a089`. Runtime version and executable
SHA-256 are observations; matching the version does not prove this source
revision. Binwalk inspection is available when configured. Unblob's constrained
native profile is exposed when configured on Linux, but its current-head
acceptance and successful runtime behavior remain unverified; it still requires
user systemd, cgroup v2 and a protected runtime installation.

Native options below are audited in [cli.py](https://github.com/onekey-sec/unblob/blob/1fcc7a0a584a70a96c31f5a276c20944d199a089/python/unblob/cli.py).
`FILE` accepts one existing regular file. A directory, password argument, raw
native argv proxy, force overwrite and sandbox bypass are outside this contract.
Use the [firmware guide](firmware-analysis.md) for public CLI/MCP examples.

| Native option                   | REA disposition and contract                                                                  | Acceptance oracle                                                                                                                              |
| ------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `FILE`                          | `path`; immutable nonempty regular snapshot, original basename, optional `range`              | Source identity, selected bytes and original offset adjusted once; FIFO admission terminates without a writer; 128 MiB admission boundary      |
| `-e`, `--extract-dir`           | Native extraction to service-local `/tmp`; output published only to caller `output_directory` | 64 MiB/512-inode tmpfs, framed stream byte/file limits, digest verification, `SafeOutputTree` publication and rollback                         |
| `-f`, `--force`                 | Not caller-controlled; scan uses it only for REA's exclusive report file                      | Only the report bind is forced; source snapshot and caller destinations remain untouched                                                       |
| `-d`, `--depth`                 | `max_depth`, default 3, 1–10; inspection uses 1                                               | Depth-limited task remains unexamined; at 10 a new extraction requires a verified committed child                                              |
| `-n`, `--randomness-depth`      | `options.randomness_depth`, default 0                                                         | Known-chunk skip early return versus whole-file no-chunks randomness; actual 1025-byte final short block, native windows/cardinality/raw means |
| `-P`, `--plugins-path`          | Excluded: runtime custom plugins are outside the supported contract                           | Public CLI/MCP schemas reject `plugins_path`; REA never adds `--plugins-path` to native argv                                                   |
| `-S`, `--skip-magic`            | `options.skip_magic.values`; append default, replace explicit                                 | Literal single argv token, actual native magic skip, default rules retained on omission                                                        |
| `--skip-extension`              | Nonempty `options.skip_extensions`; repeated CLI replaces defaults                            | Original `.rlib` basename applies to ranges; explicit replacement admits recognized gzip                                                       |
| `--clear-skip-magics`           | `options.skip_magic.mode: replace`; CLI flag with repeatable magic                            | Actual native replacement plus append/replace producer-shaped argv controls                                                                    |
| `-p`, `--process-num`           | Positive `options.workers`, default 1; CLI `--workers`                                        | Actual workers 2 metadata, invalid worker grammar before command launch; no invented worker cap                                                |
| `--report`                      | REA owns bounded private JSON path; raw report returned inline                                | Strict UTF-8/JSON and 8 MiB budget; valid unordered reports normalized once; malformed data not repaired                                       |
| `--log`                         | Private producer diagnostic path                                                              | No caller log-path proxy; staging/diagnostic ownership and bounded captured output survive failures                                            |
| `-s`, `--skip-extraction`       | Explicit Unblob `inspect_firmware_regions`                                                    | No carve/extract publication; native recognized-chunk early return preserved; whole unrecognized input may have randomness                     |
| `--no-sandbox`                  | Excluded: no bypass or fallback request                                                       | Flag absent; native Landlock isolation remains unverified even after a successful analysis                                                     |
| `-k`, `--keep-extracted-chunks` | `options.keep_extracted_chunks`, default false                                                | Actual retained gzip carving digest and nested payload digest; whole-file native no-carving behavior preserved                                 |
| `--delete-extracted-files`      | `options.delete_extracted_files` modes none/all/selected                                      | Actual intermediate deletion; `DeletedReport` retained without nonexistent artifact; selected handler argv exact                               |
| `--carve-suffix`                | `options.carve_suffix`, default `_extract`                                                    | Actual `.carved` layout; reject empty or separator-containing suffix                                                                           |
| `--extract-suffix`              | `options.extract_suffix`, default `_extract`                                                  | Actual `.decoded` layout and child hash; reject separator-containing suffix                                                                    |
| `-v`, `--verbose` (repeatable)  | Presentation/developer control excluded; fixed normal producer verbosity                      | Raw diagnostics remain Evidence; no implicit randomness plot generation or public verbosity proxy                                              |
| `--show-external-dependencies`  | Named `inspect_firmware_provider`; useful exit 1 retained                                     | Actual 15 lookup marks; host missing tools reported explicitly; lookup does not prove extractors function                                      |
| `--build-handlers-doc`          | Same inventory operation, private documentation path                                          | Actual public DOC entries retained; malformed rows downgrade coverage; not fabricated complete installed handler inventory                     |
| `--version`                     | Every admitted request, no firmware needed for inventory                                      | Observed version/selected invocation/digest; unsupported/invalid banner refuses analysis; cancelled fingerprint launches nothing               |
| `-h`, `--help`                  | REA named command help and MCP contract discovery                                             | Actual SDK/Ajv validation and public CLI grammar; schemas retain provider/options correlation                                                  |

## Interpretation and verification scope

[processing.py](https://github.com/onekey-sec/unblob/blob/1fcc7a0a584a70a96c31f5a276c20944d199a089/python/unblob/processing.py)
defines stage order, skip dispositions, multifile consumption, intermediate
deletion and skip-extraction early return. Stat, MD5/SHA-1/SHA-256, magic, native
randomness, custom diagnostics and unordered multifile constituents remain
observations. Chunk IDs are producer-local. Decompressed children have unknown
original byte offsets. Neither signatures nor randomness establish encryption,
compression or valid partitions.

[plugins.py](https://github.com/onekey-sec/unblob/blob/1fcc7a0a584a70a96c31f5a276c20944d199a089/python/unblob/plugins.py)
can import explicitly selected modules and installed entrypoints before its
internal sandbox. REA rejects caller-selected `--plugins-path`, rejects any
installed `unblob_v1` entrypoint during preflight, and disables Pluggy's
entrypoint loader before importing the Unblob CLI. Startup files are audited
before that import; the pinned setuptools `.pth` is recognized by digest but
never executed. The configured runtime's Unblob source revision remains
unverified, so successful analysis still reports partial coverage. The
in-service systemd applies the transient service's filesystem, network, PID
namespace, and cgroup policy before executing the configured Python
interpreter. The interpreter is started with isolated/no-site flags; its gate
checks effective resource controls and audits startup metadata before loading
Unblob.

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

Historical native Linux acceptance covered public CLI/MCP identity/dependencies,
selected gzip at nonzero offset, kept carvings and suffixes, basename and magic
skips, whole-file randomness including a final short block, intermediate
deletion, unordered multifile gzip constituents, and a synthetic protected ZIP.
Those runs predate the systemd boundary and do not establish the current
production profile. Producer-shaped
boundary tests additionally cover encrypted and
unknown chunks, malformed reports, capacity, cancellation and cleanup failure.
These fixtures do not establish all formats, arbitrary protected archives, hardware
acquisition, arbitrary installed plugins or other hosts. Caller-container
execution is explicitly refused because REA does not own or validate that
container boundary.

## Native isolation research (2026-10-15)

A host-specific feasibility probe verified that the user systemd manager can
create a transient service with `RootDirectory`, selected read-only binds,
`PrivateNetwork`, `PrivateDevices`, `ProtectHome=tmpfs`, `ProtectSystem=strict`,
`PrivatePIDs=yes`, `MemoryMax`, `TasksMax`, `CPUQuota`, and `RuntimeMaxSec`. The probe observed the
configured cgroup values in cgroup v2, no default network route, no host home or
input visibility beyond an explicitly bound read-only input, and exact byte and
inode quotas for explicit temporary filesystems. This is evidence that useful
primitives exist on that host; it is not an admitted Unblob profile or a portable
host guarantee.

The production adapter owns a unique transient unit with `PrivatePIDs=yes`,
checks the effective PID namespace, file-size `RLIMIT_FSIZE`, cgroup-v2 and private tmpfs controls in a
minimal Python interpreter started with `-I -S`, binds the input snapshot
read-only, and verifies exact-unit cleanup on completion or cancellation.
systemd applies namespace and resource properties before interpreter exec; the
interpreter's ELF loader runs before the in-process readbacks. Static
`UnsetEnvironment` entries remove glibc `LD_*` controls, `GLIBC_TUNABLES`,
`GCONV_PATH`, `LOCPATH`, and Python startup variables before interpreter exec.
After the in-unit admission check, the bootstrap clears inherited manager
environment values and retains only `PATH`, `TMPDIR`, and the REA run ID before
loading installed site packages or executing Unblob. Public CLI and MCP acceptance has
run against Unblob 26.6.4 for
inspection, provider inventory and gzip extraction. Extraction frames cap
aggregate output bytes at the caller's validated budget (maximum 64 MiB) and
frame records at 512; the tmpfs kernel ceiling independently limits aggregate
bytes and inodes. The host verifies frame hashes and writes files into
`SafeOutputTree` before publication. Real acceptance currently covers one gzip
fixture; all formats and options are not thereby established.

### Verification record

The implementer ran public native CLI and MCP acceptance against pinned
Unblob 26.6.4 with a gzip fixture. These runs used `REA_UNBLOB_ACCEPTANCE_ROOT`,
`REA_UNBLOB_ACCEPTANCE_COMMAND`, and `REA_UNBLOB_ACCEPTANCE_INPUT`; their values
are intentionally omitted because they are machine-local paths. The acceptance
covered inspection, inventory, and gzip extraction, including `workers: 3`,
Evidence `worker_count: 3`, and partial coverage due to unverified installed
plugins. It does not establish behavior for other formats. In the later reviewer
environment, these acceptance variables were absent, so the pinned-provider
tests were skipped there; that run is not independent real-provider
confirmation.

The following selected, manually injected non-equivalent mutants were killed
and then reverted. This targeted set is **not** a broad mutation score:

| Mutation                                  | Exact oracle command                                                                                                                                                                                                      | Result                                                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Treat missing runtime root as `/`         | `npm run test:focused -- tests/boundary/firmware/unblobExecution.test.ts`                                                                                                                                                 | Killed; three operations stopped returning the required root-admission error.                         |
| Weaken fixed service `MemoryMax`          | `npm run test:local -- src/firmware/UnblobSystemd.test.ts`                                                                                                                                                                | Killed; admitted-profile assertion failed.                                                            |
| Bypass producer entry-count ceiling       | `npm run test:local -- src/firmware/UnblobSystemdProtocol.test.ts`                                                                                                                                                        | Killed; 513-entry header was accepted.                                                                |
| Bypass aggregate output-byte ceiling      | `npm run test:local -- src/firmware/UnblobSystemdProtocol.test.ts`                                                                                                                                                        | Killed; 12 declared output bytes passed an 8-byte limit.                                              |
| Bypass streamed-file digest verification  | `npm run test:local -- src/firmware/UnblobSystemdProtocol.test.ts`                                                                                                                                                        | Killed; changed payload passed digest verification.                                                   |
| Discard exact unit cleanup result         | `REA_UNBLOB_ACCEPTANCE_ROOT=<pinned-runtime-root> npm run test:focused -- src/firmware/UnblobSystemd.test.ts`                                                                                                             | Killed; success/cancellation cleanup assertions failed.                                               |
| Force Evidence worker count to one        | `REA_UNBLOB_ACCEPTANCE_ROOT=<pinned-runtime-root> REA_UNBLOB_ACCEPTANCE_COMMAND=<pinned-unblob-command> REA_UNBLOB_ACCEPTANCE_INPUT=<gzip-fixture> npm run test:focused -- tests/boundary/cli/firmwareRuntimeCli.test.ts` | Killed; public acceptance expected 3 and observed 1.                                                  |
| Claim complete plugin processing/coverage | `npm run test:local -- src/firmware/FirmwareReports.test.ts`                                                                                                                                                              | Killed; expected `unknown_plugin_processing` and partial coverage, mutant returned complete coverage. |

The protocol suite also exercises 256 malformed framed headers. Additional
mutations, adversarial plugin behavior, and other-format real-provider runs
remain unverified. A host systemd 259 user-manager probe observed a distinct PID
namespace (`pid:[4026531836]` on the host, `pid:[4026534288]` in the probe); an
owned same-UID sentinel was absent in `/proc` and `kill(pid, 0)` returned
`ESRCH`. The repeatable opt-in test is
`REA_RUN_USER_SYSTEMD=1 npm run test:local -- src/firmware/UnblobSystemd.test.ts`;
it compiles a disposable `LD_PRELOAD` canary and also installs a `sitecustomize`
canary, injects both paths through unit environment properties, verifies they
are scrubbed before Python startup, and checks namespace/sentinel isolation.
Pinned-provider acceptance separately exercises the production gate. A
negative-profile probe runs with `PrivatePIDs=no` and verifies exit 125 with
`PrivatePIDs is unavailable or was not applied`, so an ignored namespace
setting fails closed. The same focused command tests that a synthetic late
manager variable is absent from the post-gate child. Assertions compare names
only and do not print environment values. The transient unit bounds stop time to two seconds and
allows systemd to kill only that exact unit's cgroup if graceful termination
does not complete.

### Fixture-scoped external extractor runtime (2026-10-15)

The gzip/USTAR acceptance now gates its required `7z` against the Unblob
dependency inventory returned inside the admitted service. An absent unrelated
extractor does not fail this fixture-specific check, and a host `PATH` lookup is
not accepted as evidence about `RootDirectory` visibility. Malformed,
duplicate, missing, or incomplete inventory rows fail closed. The dedicated
verification driver also rejects extraction Evidence that reports the
fixture-required `7z` missing.

The disposable Podman runtime was built as
`localhost/rea-unblob-runtime:26.6.4` with image digest
`sha256:64b3e700c9c7cbb1fd9d0c060c35437e89d774089eac598438383fcaccbede02`.
It uses the pinned Python 3.12 slim base digest recorded in
`tests/fixtures/firmware/unblob-runtime/Containerfile`, Unblob commit
`1fcc7a0a584a70a96c31f5a276c20944d199a089`, locked Python distributions, and
Debian `7zip` package `25.01+dfsg-1~deb13u2`. The runtime's `/usr/bin/7z` is a
static executable with SHA-256
`60fc00b4e1ed37668972c51f03426973d8006db3c7224075878f6d66196d7c27`; `7z i`
reports 7-Zip 25.01. The runtime installs Unblob into `/usr/local` so the
manually audited and appended Python import paths resolve the pinned package.
The root is a disposable test artifact, not an accepted caller-container
runtime. Its direct Podman run used no network, a read-only root, no added
capabilities, a private read-only input mount and a private read-write output
mount; extracted fixture
files matched oracle paths, sizes and SHA-256 values.

On 2026-10-15, the real public CLI/MCP test suite passed 11/11 tests with the
generated gzip fixture and passed 11/11 again with a downloaded 7.6 MiB
camera-firmware ZIP (input SHA-256
`0db884f68be6dc6eb78203281f1002644948df35d5562a0497ef0c36438507bc`; the
input hash was unchanged after both runs). This confirms extraction for those
inputs only. The systemd boundary checks its effective file-size `RLIMIT_FSIZE` and cgroup-v2 CPU, memory,
swap and process limits, tmpfs bytes/inodes, and hides an unrelated host
readable canary; output staging and framing retain their independent byte and
entry quotas. Four targeted dependency-gate mutants were killed: required
check removed, installed boolean inverted, inventory replaced by the former
ambient host `7z` prerequisite, and incomplete inventory accepted.

The Unblob-only `npm run verify:unblob-firmware` lane passed against the
generated fixture and independent `oracle.json`, without configuring Binwalk.
The combined `npm run verify:firmware` lane remains unverified because no real
Binwalk executable was configured (`REA_BINWALK_COMMAND`); its early
prerequisite gate stopped before invoking either analysis provider. Real
firmware results do not establish support for other formats or Unblob plugins.

### Python startup and plugin admission (2026-10-16)

Before launch, the adapter checks Python runtime and ancestor paths for
same-user ownership or effective write access. It rejects root execution,
mutable paths, unverifiable or escaping symlinks, and scans at most 100,000
runtime nodes. A successful proof is retained for the REA process lifetime;
trusted runtime-owner updates require restarting REA for fresh admission. The
in-unit bootstrap repeats the check against `sys.executable` and the exact
`sysconfig` import roots. Each host and in-unit startup audit scans at most
8,192 combined directory entries across Python library and startup locations,
and reads each `.pth` or `entry_points.txt` file only up to 1 MiB plus one byte
to detect overflow. Exceeding either limit fails closed before Unblob imports.
The adapter audits Python startup locations and
distribution metadata. It rejects `sitecustomize`, `usercustomize`, every `.pth`
except the pinned setuptools hook by SHA-256, and
every installed `unblob_v1` entrypoint. The known setuptools hook is not
executed: Python site initialization remains disabled and the admitted import
paths are added directly. Unblob is invoked using `runpy`; Python `exec` and
`site.main()` are not used. The same audit runs inside the systemd unit before
the Unblob CLI is imported, and Pluggy entrypoint discovery is disabled before
that import to prevent an entrypoint added after preflight from loading. A
caller plugin whose target has a stable or previously known digest is still
rejected by its installed entrypoint metadata.

Focused source tests passed 9/9 applicable tests for systemd startup admission
and invocation policy; six live systemd cases were skipped because this phase
did not run shared runtime acceptance. The generated Python bootstrap was
compiled with `/usr/bin/python3 -I -S` without execution. Public CLI/MCP and
live systemd acceptance against the pinned runtime is still pending, so the
revised native bootstrap is unverified. Caller-container execution remains
refused because the selected container generation, invocation ownership and
effective inode quota are still unproved.

Caller-container execution remains refused. The current rootless Podman/crun
rejects tmpfs `nr_inodes`; a memory-cgroup many-empty-file probe was OOM-killed
around 140,000 files with millions of tmpfs inodes still free, so memory is not
a substitute for the exact file/inode ceiling. In addition, the existing
container selector does not identify an immutable container generation and
per-request mount/staging map. Do not infer support from an upstream-only
Podman run.
