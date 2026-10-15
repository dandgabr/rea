# Unblob capability and acceptance ledger

**Status: constrained native inventory, scan-only inspection and extraction are
available; caller-container execution remains unavailable.** Native Unblob runs
inside a verified user-systemd transient service. systemd applies the service
boundary before Python exec; a minimal `-I -S` bootstrap verifies the effective
PID namespace and resource controls before executing Unblob. Installed
`unblob_v1` entrypoints execute inside that boundary, but REA cannot enumerate
or attest them; task processing is marked unknown and overall
inspection/extraction coverage is always partial. Extraction stages on a 64
MiB/512-inode service tmpfs, then transfers bounded hashed frames into a
private `SafeOutputTree` before verified publication.

The producer reference is [Unblob 26.6.4](https://github.com/onekey-sec/unblob/tree/1fcc7a0a584a70a96c31f5a276c20944d199a089),
revision `1fcc7a0a584a70a96c31f5a276c20944d199a089`. Runtime version and executable
SHA-256 are observations; matching the version does not prove this source
revision. REA supports Binwalk inspection and this constrained native Unblob
profile on Linux with user systemd and cgroup v2.

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
can import explicitly selected modules and installed entrypoints before sandbox
setup. REA rejects caller-selected `--plugins-path`. Installed entrypoints are
contained inside the transient systemd service rather than disabled. Their
identity and influence cannot be established, so all task processing is
reported as `unknown_plugin_processing` and overall scan/extraction coverage
is partial even when parsed report rows are otherwise complete. The in-service
systemd applies the transient service's filesystem, network, PID namespace,
and cgroup policy before executing the configured Python interpreter. The
interpreter is started with isolated/no-site flags; its small gate then checks
the effective PID namespace, cgroup-v2, and tmpfs controls before it execs the
Unblob entrypoint. Thus interpreter ELF loading necessarily precedes the
in-process readbacks, while systemd policy and static loader-variable removal
are applied before interpreter exec. The gate checks effective controls before
entrypoint loading occurs after the outer boundary is active.

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
checks the effective PID namespace, cgroup-v2 and private tmpfs controls in a
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

Caller-container execution remains refused. The current rootless Podman/crun
rejects tmpfs `nr_inodes`; a memory-cgroup many-empty-file probe was OOM-killed
around 140,000 files with millions of tmpfs inodes still free, so memory is not
a substitute for the exact file/inode ceiling. In addition, the existing
container selector does not identify an immutable container generation and
per-request mount/staging map. Do not infer support from an upstream-only
Podman run.
