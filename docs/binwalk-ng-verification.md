# Binwalk-NG verification record

The upstream review on 2026-10-15 used Node 24.18.0 and reviewed
`binwalk-ng/binwalk-ng` commit `368c3815cb97976ae7ba6092f356933169f06dae`.
Verification figures below describe separate, overlapping runs recorded on
2026-10-16; they are not one aggregate test total. Older Podman and upstream
smoke evidence remains separate from REA public-boundary evidence.

## Scope record and current admission

REA design discussion [#4110](https://github.com/morluto/rea/issues/4110)
records owner-directed initial scope for caller-selected external-helper
extraction and bounded recursion subject to helper identity, process ownership
and confinement. Its latest update still requests explicit maintainer
ratification of final scope or narrowing of modes that cannot satisfy the
listed authority/resource boundaries. This record does not treat that request
as resolved. The provider
requires a manifest record for every helper it exposes: exact command name,
absolute regular-file path, expected SHA-256, version arguments and exact first
non-empty version identity line (full command output is retained) and
supported signature capabilities. Configured capabilities are checked against
the native `--list` inventory plus dynamic overrides inferred from the pinned
source compatibility profile (`7z` for malformed XZ and the `sasquatch*`
SquashFS variants). Each manifest helper must declare the exact full set of
native inventory rows and profile-inferred dynamic overrides that dispatch to
that helper; partial inventory or a narrowed subset is rejected before its
version probe. This completeness check is an inference from source review and
runtime inventory, not proof that the selected executable was built from that
source. The selected Binwalk-NG binary and external helper source/build
provenance remain unknown unless independently attested. The sandbox PATH contains only
`/runtime/bin`; an unconfigured command cannot fall back to the host PATH.

The upstream Rust library API for custom signatures, internal callbacks and
programmatic analysis has no REA wrapper and is excluded from the compatibility
matrix. The integration covers the pinned CLI protocol only; it does not claim
parity with the library API.

Extraction and recursive children use the owned user-systemd cgroup, bounded
private tmpfs, framed output transfer and existing output-tree publication
checks. Extracted files are analyzed as static data and are never executed.
Caller-provisioned-container execution remains unsupported.

## Historical direct upstream smoke test (2026-10-15)

Ran the upstream executable with reported version `binwalk-ng 4.0.0` in a
rootless Podman container with
network disabled, read-only root, dropped capabilities, no-new-privileges,
64-task limit, 512 MiB memory/swap bounds, and a private `/tmp` tmpfs. The
container runtime image was `ghcr.io/binwalk-ng/binwalk-ng:main` with local
image digest `sha256:fb2f83d2700a5cd3c97ac19896bac375993a591e3a10916e7f55e096598c7c04`;
its OCI revision label is `05da0ab9753d8403ccbc60437e875b3660a8b504`. The
mounted executable SHA-256 is not linked to a retained source/build receipt;
the repository commit identifies the reviewed source only. Executable
source/build provenance is therefore unknown.

The smoke command used the mounted executable with `--version`, then scan and
extraction arguments against caller-provided fixture paths. No build command
or source-to-binary receipt was retained for the mounted executable; the
commit above is used only for source review and dispatch mapping.

- Mounted executable SHA-256: `9eb70ccfae69af4f176b5f986384896cf1150114727b203ba72e0aaaf6a42cdd` (source/build provenance unknown).
- `--version` returned `binwalk-ng 4.0.0`.
- Scan found a gzip region in the generated fixture and wrote JSON (SHA-256
  `949ce74d0a9e0c06422d9ee43c433a958febff886c5675995e46285db3f5282b`).
- `--extract --matryoshka` produced the expected 15-byte gzip child with SHA-256
  `9a5df3729917cba86db1a823bdedea240ac08fd1cdacb93ac8d987c09b49bb08`.
- A generated 7z archive exercised Binwalk-NG's external `7z` helper; the
  container reported helper version `7-Zip 26.00` and extraction produced the
  expected 45-byte text file with SHA-256
  `96fcc347e4f952bfe1eb8edd0adf3e797653609a403c6baf00bee91e6b48b621`.
  This matched the source payload digest exactly.
- The 7z archive digest was
  `01dec35f406576703b52f77d02063d3bd62310944998752d8f93fe2df4efec77`.
- The gzip fixture input digest remained
  `b787444dce7d2848b0a1f894dd4bbd142637245398e051713ad72d714d01a6a7`.

These tests establish direct upstream CLI behavior for generated gzip and 7z
fixtures, including built-in gzip extraction, one external helper, and gzip
recursion. The REA native CLI/MCP path is exercised separately by its
configured acceptance lane; its results and skips belong to their own dated
run. The image revision does not establish the 7z helper's source/build
provenance, so REA records it as unknown.

## Offline source build for native acceptance (2026-10-16)

The earlier native acceptance executable was not linked to a retained build
receipt. To test the upstream `entropy-plot` feature and make the native
executable's provenance auditable, a separate x86_64 test binary was built from
the pinned source commit in an already available Podman builder image. This is
a local test artifact, not an upstream release binary.

- Source: `https://github.com/binwalk-ng/binwalk-ng`, commit
  `368c3815cb97976ae7ba6092f356933169f06dae`.
- `git archive` SHA-256:
  `9e5acced4630b32aeb12980c5876938e8226164b3de423d22b424fb75e25c5e7`;
  `Cargo.toml` SHA-256:
  `d6254951f8bacdbb9b5a136d74ff64579b2a5eed94cd7045410d79850dd9a007`;
  `Cargo.lock` SHA-256:
  `ac095096a819caf00ab755e8c6615db3b1020e058c56b32146883563fef700cd`.
- Builder image:
  `docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e`;
  `rustc 1.98.1 (48a229cea 2026-09-01)` and
  `cargo 1.98.1 (797e8a9bc 2026-08-05)`.
- Build command: `cargo build --release --locked --offline --features entropy-plot`.
  The source was mounted read-only, the container root was read-only, all
  capabilities were dropped, `no-new-privileges` was enabled, networking was
  disabled, and the local Cargo registry cache was copied into the disposable
  container. No host package was installed. Two builds with the same source,
  lockfile, builder image, and command produced byte-identical output.
- Test executable SHA-256:
  `621b5a42cdd6412730563c35c45d4a2413e8c2cc5eb4d08707c1b97887aed864`;
  `--version` returned `binwalk-ng 4.0.0`, and `--help` exposed `--entropy` and
  `--png`.
- Native runtime manifest SHA-256:
  `6ff9da6871bd912a95f5b3544a46770c1e1acaa8cb98aa8f04478e5f3e0a1bb0`.
  It pins the external helper executable path, full digest, version identity,
  library/support mounts, and the complete source-backed helper signature set.

A second disposable build of the same source and lockfile used
`cargo build --release --locked --offline --no-default-features` in the same
Podman builder boundary. Its executable SHA-256 is
`54f4a060ba27f1a005134d97191f123f15b2eed3a48a16a8c23e0bb39a807ffa`; it
reports `binwalk-ng 4.0.0`. The CLI still lists `--entropy` in help, but a
generated 16-byte zero fixture passed to `--entropy` exits 1 and emits the
upstream `entropy-plot`-unavailable diagnostic. This build exercises REA's
fail-closed capability classification, and the public CLI/MCP acceptance case
passed through both adapters with the upstream diagnostic preserved. The
no-feature executable is a local test artifact and is not represented as an
upstream release binary.

The helper `/usr/bin/7z` was identified by the installed RPM database as
`7zip-26.04-1.fc44.x86_64`, source RPM label
`7zip-26.04-1.fc44.src.rpm`; `rpm -V 7zip` reported no differences, and the
helper SHA-256 is
`a554d6350fc6f2f1795f37692b4dd83395d41dcfc12c0b0156aba089dad08630`. The
source RPM payload and a cryptographic signing receipt were not present locally.
This verifies the installed package identity against the local RPM database,
but does not establish the helper's source/build provenance; that remains an
explicit limitation. The manifest records the exact helper version and digest
so runtime admission is still identity-bound.

## Targeted mutation checks (2026-10-16)

The five security mutants required by the extraction plan were introduced one
at a time, tested, then restored before the next mutation. All five were killed
by their targeted regression test. Commands used Node 24.18.0:

| Mutant                  | Exact behavior change                                            | Regression test                                                         | Mutation result                                                                                                                                                |
| ----------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Missing helper fallback | Add `/usr/bin:/bin` to the sandbox helper `PATH`.                | `BinwalkNgSandbox.test.ts`                                              | Killed: absent-helper and selected-helper PATH assertions failed.                                                                                              |
| Helper digest recheck   | Remove the runtime recheck after helper version verification.    | `BinwalkNgCorrections.test.ts -t 'rechecks the selected helper digest'` | Killed: extraction launch occurred after helper replacement.                                                                                                   |
| Aggregate output budget | Remove the aggregate byte-ceiling check from the frame consumer. | `BinwalkNgTransfer.test.ts -t 'over budget'`                            | Killed: truncated frame error replaced the expected budget refusal.                                                                                            |
| Symlink/special publish | Bypass nonregular-entry handling during publication.             | `BinwalkNgArtifacts.test.ts -t 'records symlink artifacts'`             | Killed: symlink reached regular-file open and the publication expectation failed.                                                                              |
| Descendant cleanup      | Replace systemd cgroup-owned stop with PID-by-PID signaling.     | `BinwalkNgSystemdBoundary.test.ts` plus live `-t 'owns and reaps'`      | Killed: boundary contract rejects PID signaling; live run confirms descendants are gone before `systemd-run --wait` returns and an external sentinel survives. |

The targeted plan score is **5/5**. Separate helper-version identity and
partial-inventory mutants were also killed earlier; they are not substituted
for these five plan-required cases. No general mutation runner is configured
in `package.json`.

## Recorded verification results

The following branch-level counts are historical checkpoints from
2026-10-16. Tests overlap across focused subsets and later reruns; do not sum
their counts. The latest review-specific results are listed after them.

Earlier branch checkpoints on Node 24.18.0:

- Current focused source suites for `BinwalkNgTransfer`, `BinwalkNgSandbox`,
  `BinwalkNgArtifacts` and `BinwalkNgCorrections`: 36 passed. These include
  digest drift, symlink/FIFO publication, malformed frames and the 256-case
  transfer fuzz. The bounded workflow fuzz, 64-case inventory fuzz and
  stable/mutated recursion cases passed in the broader run.
- Malformed transfer-frame fuzz: 256 cases, seed `0x4e473208`; each failed
  closed, left the `SafeOutputTree` unpublished, and left the caller output
  absent.
- With `REA_RUN_USER_SYSTEMD_BOUNDARY_TEST=1`, the final live user-systemd
  boundary run passed all 10 tests. This includes main-exit with a persistent
  descendant, cleanup within the owned cgroup and survival of an external
  sentinel.
- Public native CLI/MCP acceptance with the locally built pinned runtime and a
  digest-pinned `/usr/bin/7z` manifest: 11 passed, 0 skipped. It covers
  inventory, scan, entropy, internal carve, bounded recursive gzip extraction,
  external 7z extraction through both adapters, exact 128 MiB and 128 MiB+1
  input boundaries through CLI/MCP, UTF-8 argument boundaries, and
  feature-disabled entropy refusal through CLI/MCP. Input digests and source
  byte stability were checked. The helper-absent case retains upstream
  `No such file or directory` stderr in `raw_result`, reports partial coverage
  and failed extraction, and publishes an empty directory.
- The acceptance 7z input is generated inside the digest-pinned
  `ghcr.io/binwalk-ng/binwalk-ng@sha256:fb2f83d2700a5cd3c97ac19896bac375993a591e3a10916e7f55e096598c7c04`
  image with `--pull=never`, `--network=none`, read-only root, all capabilities
  dropped, no-new-privileges, 32 tasks, 256 MiB memory/swap, one CPU, and a
  16 MiB output tmpfs. Acceptance never executes the manifest's helper path
  directly on the host. Set `REA_BINWALK_NG_FIXTURE_IMAGE` to that exact image
  reference to enable the optional 7z fixture lane.
- `BinwalkNgProvider`, inventory failure, domain fuzz and transfer suites:
  10 passed, 4 provider live tests skipped.
- After adding captured-stderr fallback classification, focused
  `BinwalkNgProvider.test.ts` and `FirmwareCommand.test.ts` passed 15 tests.
  The provider suite now skips only `real entropy windows preserve native
  Binwalk-NG behavior` and `real scan, carve, extraction, and entropy preserve
  native Binwalk-NG behavior` when the runtime variables are absent; both
  require the shared user-systemd lane. A deterministic test covers missing
  and empty structured stderr diagnostics and confirms the mapped capability
  error omits the private runtime command while retaining the relevant stderr
  diagnostic.
- `tests/acceptance/binwalkNgAvailability.test.ts`: an earlier run reported 5
  passed, including CLI help, runtime fail-closed behavior, and rejecting
  Binwalk-NG-only options for Unblob. A later QA test extended that suite; see
  the latest review results below.
- A local Downloads ZIP was analyzed statically through public CLI and MCP for
  `inspect_firmware_regions` and `inspect_firmware_entropy` only. Its input
  size was 7,628,047 bytes, SHA-256 before and after was
  `53aa58d3498eb43362ac65a8b886ea9d1213f1688abf1c020e0450f301a90005`, and
  each Evidence subject digest matched. No extraction or artifact execution
  was performed; archive contents were not included in the report.
- The final focused Transfer, Corrections and Inventory suites passed 30
  tests. The malformed-frame fuzz rejected 256 frames with seed `0x4e473208`,
  and the bounded workflow fuzz passed with seed `0x4e473208`. Four targeted
  mutants were reintroduced individually and killed: ambient helper PATH,
  helper digest recheck, aggregate transfer-byte budget, and symlink
  publication. The descendant-cleanup mutant had previously been killed by
  the live cgroup ownership test, which passed again in this final run.
- `npm run check:fast`, `npm run docs:check`, `npm run format:check`, and
  `git diff --check` passed.

Latest review-specific verification on Node 24.18.0 and npm 11.16.0:

- After rejecting exact dot-segment helper names and path separators, the
  focused `BinwalkNgSandbox.test.ts` suite passed 10/10. Its new case covers
  `.`, `..`, slash and backslash path components. The checks also assert valid
  helper names remain directly bound beneath `/runtime/bin`.
- The updated `tests/acceptance/binwalkNgAvailability.test.ts` passed 6/6; its
  caller-container schema/catalog refusal coverage runs before provider
  dispatch.
- `npm run docs:check` and `git diff --check` passed. No container or systemd
  service was started for this review.

REA public acceptance exercised its own bubblewrap plus user-systemd boundary.
It does not establish caller-managed-container selection or lifecycle support.
