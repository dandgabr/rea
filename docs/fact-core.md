# FACT Core corpus workflows

FACT REST workflows use a caller-selected existing service. The native export
contract is planned but currently unavailable. These workflows do not require
a local binary analysis session.
REST and native database authority are declared independently: matching config,
UIDs or timestamps does not prove they address the same corpus.

All 11 FACT corpus MCP tools below have a CLI command formed by replacing
underscores with hyphens. The CLI takes one exact JSON object or a path to a JSON file, and
`--json` returns the same inline Evidence. Local artifact, checkout, interpreter,
archive and output paths must be absolute. A malformed document beginning with
JSON container grammar is rejected before file access, even when its text ends
with `.json`. Select an ambiguous real filename with `./` or an absolute path.
JSON files can hold private transport credentials; protect those files yourself.
`connection.authorization` is the exact HTTP header value: visible/obs-text
Latin-1 bytes with interior spaces or tabs are allowed; control bytes, DEL,
characters above U+00FF and leading or
trailing whitespace are rejected before delivery. Query values, findings and
paths retain their ordinary Unicode meaning. Known authentication values and
their supported UTF-8 and actual Latin-1 wire-byte encodings are redacted from
public Evidence; native configuration text retains UTF-8 semantics. REA does
not consult credential stores.

```sh
rea inspect-firmware-corpus '{"connection":{"endpoint":"http://127.0.0.1:5000","profile":"source-54aed90b"}}' --json
rea search-corpus-objects /absolute/path/to/search.json --json
```

```json
{
  "name": "search_corpus_objects",
  "arguments": {
    "connection": {
      "endpoint": "http://127.0.0.1:5000",
      "profile": "source-54aed90b"
    },
    "kind": "firmware",
    "query": { "vendor": "example" },
    "offset": 0,
    "limit": 10,
    "recursive": false,
    "inverted": false
  }
}
```

## REST selection and supported questions

Every REST request requires `connection`: `endpoint` is a literal loopback HTTP(S)
origin (`127.0.0.1` or `[::1]`), with optional port and trailing slash. Paths,
queries, userinfo, redirects and remote hosts are rejected. A service in a
container can expose its REST port on host loopback. REST endpoint selection is
independent of the native runtime selection below.

`profile` is explicitly `source-54aed90b` (upstream commit
`54aed90bacb13c484404018101527c72d0bff6c5`) or `release-4.4.1` (commit
`9ac65997a2b0fdaabd61bca2280fa22c441b1f92`). These are protocol declarations;
status does not attest the installed service version. Optional `authorization`
is the producer's raw Authorization key, without an invented Bearer prefix.
Actual key values and encoded variants are redacted from output; ordinary paths,
usernames and findings remain evidence.

UIDs are exactly `<lowercase SHA256>_<decimal size>`. Virtual paths and parent
membership are corpus identities, never host files or native runtime addresses.
Plugin names come from the selected service's inventory; REA does not impose a
web form's static plugin list or choose all plugins implicitly.

### Source-pinned endpoint authority matrix

The operation classification below follows the route implementation at source
profile `54aed90bacb13c484404018101527c72d0bff6c5`; each route link is pinned to
that revision. Release profile `9ac65997a2b0fdaabd61bca2280fa22c441b1f92` is
also available as a protocol declaration, but release-specific route behavior
has not been verified against a live service. Both profiles describe expected
producer behavior; the selected REST service does not attest its own revision.
See the [FACT boundary verification record](verification/fact-core-boundaries.md)
for verification scope and limits.

| Route family                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Producer effect                                                                                                                                                               | Current REA exposure                                                                                                                 |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| [`/rest/status`, `/rest/statistics`, `/rest/missing`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_status.py) / [`rest_statistics.py`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_statistics.py) / [`rest_missing_analyses.py`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_missing_analyses.py)                                                                                                                                                                                                                                                                                                    | Read/query. `/rest/missing` additionally requires producer delete privilege.                                                                                                  | Exposed as named inspect operations.                                                                                                 |
| [`/rest/firmware`, `/rest/file_object`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_firmware.py) / [`rest_file_object.py`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_file_object.py) and [`/rest/analysis/<uid>/<plugin>` / `/plugins/<plugin>/rest/<uid>`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_analysis.py) (GET)                                                                                                                                                                                                                                                                        | Read/query.                                                                                                                                                                   | Exposed as named inspect/search operations.                                                                                          |
| [`/rest/compare/<uids>`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_compare.py) (GET)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Read/query; HTTP 202 may include completed comparison data.                                                                                                                   | Exposed as `inspect_corpus_comparison`.                                                                                              |
| [`/rest/binary/<uid>`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_binary.py) (GET)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Read/query; may request a producer-repacked archive. REA writes only a fresh selected local output.                                                                           | Exposed as `download_corpus_binary`.                                                                                                 |
| [`/rest/binary_search/<search_id>`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_binary_search.py) (GET)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | State-consuming: first successful read consumes producer results.                                                                                                             | Exposed only as explicit `collect_corpus_yara`; REA retains the first observation and never automatically retries an ambiguous read. |
| [`/rest/firmware`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_firmware.py) (PUT), [`/rest/firmware/<uid>`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_firmware.py) (PUT), [`/rest/analysis/<uid>/<plugin>`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_analysis.py) (PUT), [`/rest/compare`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_compare.py) (PUT), [`/rest/binary_search`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_binary_search.py) (POST) | Upload/enqueue or trigger plugin/scheduler work. Installed plugins can execute code and permit egress; exact deployment isolation is not established by the current contract. | Not exposed. A future decision must prove the selected deployment's plugin, scheduler and network boundary.                          |
| [`/rest/firmware/<uid>`](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_firmware.py) (DELETE)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Destructive corpus mutation.                                                                                                                                                  | Not exposed.                                                                                                                         |
| [Native `import` CLI](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/firmware_import_export.py)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Mutates FACT DB before writing files; upstream has no transaction/recovery contract covering partial import.                                                                  | Not implemented or exposed. Reconsider only after a verified transaction/recovery design.                                            |
| [Native `export` CLI](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/firmware_import_export.py)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Reads selected producer objects and writes archive outputs.                                                                                                                   | `export_corpus_firmware` is retained as a planned contract but the provider refuses every runtime until isolation is enforceable.    |

The endpoint paths and methods are implementation facts, not sufficient
authority classifications: GET of `/rest/binary_search/<search_id>` consumes
state, while a plugin-triggering request may run code after request acceptance.
See [issue #4110](https://github.com/morluto/rea/issues/4110) for the recorded
scope decision.

| MCP tool                         | Additional input and meaning                                                                                                                                                                                                                                                 |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `inspect_firmware_corpus`        | Status and dynamic plugin inventory; no readiness guarantee. Upstream `/rest/status` omits the `unpacker` plugin from this inventory.                                                                                                                                        |
| `search_corpus_objects`          | `kind`: `firmware`/`file`; `query` defaults `{}`, `offset`/`limit` default 0. Limit 0 preserves producer-unbounded meaning. `recursive` requires firmware and nonempty query; `inverted` requires recursive. Returns only the requested page.                                |
| `inspect_corpus_object`          | `kind`, `uid`; `summary` defaults false and is firmware-only. FACT selects the firmware representation from the exact `summary` query but only echoes UID; REA records the query as transport-bound selection and rejects a contradictory summary echo if present.           |
| `inspect_corpus_analysis`        | `uid`, exact dynamic `plugin`.                                                                                                                                                                                                                                               |
| `inspect_corpus_parent_analysis` | `uid`, `plugin`: `file_system_metadata`/`qemu_exec`; preserves native `included_files` parent-context results.                                                                                                                                                               |
| `inspect_corpus_comparison`      | Distinct `uids`; native HTTP 202 can carry a completed comparison.                                                                                                                                                                                                           |
| `collect_corpus_yara`            | `search_id`; GET consumes the producer result. Pinned FACT does not echo the ID on the result response, so REA binds it to the exact non-redirected result URL and rejects a contradictory ID echo if present.                                                               |
| `inspect_corpus_statistics`      | Optional `category`: `architecture`, `crypto_material`, `elf_executable`, `exploit_mitigations`, `file_type`, `firmware_meta`, `general`, `ips_and_uris`, `known_vulnerabilities`, `release_date`, `software_components`, `unpacking`. Raw dictionaries remain native facts. |
| `inspect_corpus_gaps`            | Missing/failed analysis GET requires producer delete privilege despite being non-destructive.                                                                                                                                                                                |
| `download_corpus_binary`         | `uid`, `repacked` (default false), fresh absent `output_path`. Original bytes require actual UID/SHA/size equality. Repacked output is a tar.gz archive with a distinct digest.                                                                                              |
| `export_corpus_firmware`         | Planning inputs only: `interpreter`, `checkout`, `profile`, selected `uids`, and a fresh absent `output_directory`. Every runtime is refused before identity or execution.                                                                                                   |

Binary publication requires POSIX UID, permission-mode and sticky-directory
semantics. REA fails closed where they are unavailable, including Windows.
The selected output parent must be current-user-owned and not group/world
writable; writable ancestors must be sticky. This boundary does not isolate
against concurrent processes running under the same UID, which share the
caller's filesystem authority. Publication is not atomic.

Plugin-triggering operations, corpus deletion, redo and native import are not
public CLI/MCP capabilities. Their input schemas are absent, the shared service
rejects forged names before provider dispatch, and the REST provider also refuses
them before network access. They are not enabled by plugin names or caller assertions.

YARA collection shares the first observation for the same canonical origin,
profile, private authorization context and search ID within one REA process/MCP
session. The first caller owns fetch cancellation. Captured successes and
ambiguous delivered observations stay retained even if a waiter cancels.
Definitive native not-ready/already-fetched errors remain failed observations;
a later explicit collect can attempt again because that response returned no
result. Pre-aborted/provably undelivered attempts also permit a later explicit
attempt. Separate CLI invocations have separate retention; no disk cache or
credential fingerprint is exported.

## Native interchange

`export_corpus_firmware` retains its strict input schema for planning, but its
provider currently returns `AnalysisCapabilityUnavailableError` for every
runtime selection, including omitted runtime, `{ "kind": "native" }`, and
`podman-existing`. The provider refuses before filesystem identity observation,
process launch, container-session construction, or Podman access. No runtime
mode currently performs a FACT export.

The native export remains unavailable until REA can enforce filesystem, network
and device isolation before examining producer identity or launching work. A
caller-selected interpreter, checkout, `prlimit`, container ID or store profile
does not establish that boundary. The runtime fields describe a future request;
they do not imply support. REST read and explicit one-shot collection tools
remain available under their recorded authority.

## Evidence and resource limits

Corpus Evidence has `subject: null`, `authority: external-service`, observed
confidence and provider version null unless actually observed. Results preserve
`not-delivered`, `accepted`, `completed`, `failed` or `unknown`, actual native
responses, partial facts, digests, output receipts and coverage. HTTP success or
process exit alone cannot establish completion. CLI failed/unknown/undelivered
outcomes exit 1 while preserving Evidence; MCP delivers the same facts inline.
Tool annotations distinguish network, filesystem, process and mutation effects.

The REST provider admits one outstanding heavy operation; capacity refuses
immediately. Retained uncertain producer/parser/file cleanup can hold admission
until explicit close/recovery. Cleanup retries never replay producer work.
Operations have a 120-second deadline, 128 MiB input/binary limit,
8 MiB nonbinary JSON/metadata and aggregate diagnostics limits, and separately
account actual base64 expansion and decoded/staging bytes. JSON parsing has
bounded structural admission and a V8 worker heap limit; Buffer/ArrayBuffer
budgets are accounted separately. These are not a global OOM guarantee.
Known-value privacy projection has independent admission before provider delivery:
64 MiB of accounted UTF-16 strings, byte variants and typed-array representations,
and eight million explicit graph/matcher work units per redactor. The compact
scalar table uses eight bytes per scalar; matching uses two Uint32 rows, eight
bytes per input UTF-16 unit plus sentinel. Arithmetic and replacement expansion
are checked before allocation. Literal/percent prechecks may scan ordinary text
without matching matrices, including the 8 MiB plaintext control. These limits
exclude total V8 object heap, native string-scan CPU and synchronous wall-clock
interruption. A tagged refusal never exports unprojected text. Refusal after a
producer response retains sanitized partial effects, digests, publication and
cleanup counts; consuming observations remain cached without refetching.

Caller-selected paths and producer-side limits do not establish filesystem, network, or device isolation. Native export remains unavailable for every runtime until REA can enforce that boundary before inspecting producer identity or starting work.

Responses must declare the pinned `application/json` media type. REA uses a
format-aware media-type parser and the existing fatal UTF-8 JSON parser; it
retains the bounded response digest but reports unknown if the media type is
missing, malformed or different. JSON charset parameters do not override the
JSON UTF-8 decoder.

For repeatable frontend-only CLI/stdio MCP verification, use the explicit
[read harness and readiness matrix](verification/fact-core-boundaries.md#repeatable-frontend-only-acceptance-2026-10-15).
The backend runtime-control-plane proposal remains pending in
[issue #4325](https://github.com/morluto/rea/issues/4325); no runtime socket is
authorized by a REST profile.

Source-derived controlled HTTP tests cover request construction, response
normalization, resource limits, errors and credential redaction. Historical
Podman acceptance used FACT Core source commit
`54aed90bacb13c484404018101527c72d0bff6c5`, mounted read-only over the local
Python runtime image, plus disposable PostgreSQL 18.6 and Valkey 9.1.2 on an
internal-only network. Real upstream statistics, firmware search, missing
analysis, fixture object detail, and `dummy` analysis queries returned HTTP
200 through both REA CLI and production stdio MCP. One FACT test fixture was
seeded directly into the disposable database and private container storage.

In that historical setup the FACT backend was not started: upstream backend initialization requires
`docker.from_env()`, and no Docker/runtime socket was mounted. Consequently
`/rest/status` returned HTTP 500; the separate setup/service logs attributed it
to unavailable plugin inventory. A generic 500 alone does not establish that cause. A
direct binary retrieval probe did not complete within 15 seconds because
file access is routed through backend intercom. Backend-dependent binary
retrieval, one-shot YARA collection, stored comparison results, plugin
triggering, and native export remain unverified. The runtime image's dependency
layer is not source-attested, and the selected REST profile is still a caller
declaration rather than service-side revision proof. Native export remains
unavailable for every runtime until its filesystem, network, device and
aggregate resource boundaries are enforceable.

The frontend-only verification round repeats the five completed reads
through compiled CLI and production stdio MCP, preserves status HTTP 500 and
adds the nonexistent-UID HTTP 400 control. The prior branch gate passed 83 tests and five targeted mutants; the
process-ownership correction now passes **88 tests in 17 files**, 256 deterministic
response cases and **ten targeted mutants**;
these counts supersede the earlier run counts for the current gate, while the
historical receipts remain unchanged. The current mutant set covers HTTP-500
normalization, forbidden method, private-file cleanup, adapter error redaction,
and media-type admission. It is not a global mutation score. See the
[verification ledger](verification/fact-core-boundaries.md#current-branch-checks-and-targeted-mutations)
for exact scope and the separate historical records. Additional mutants omit the canonical manifest hash
admission, fabricate a missing-backend cause for an unrelated HTTP 500, skip
transport close after client close fails, discard the original operation error,
or bypass owned-child recovery.
The harness attempts client close, transport close and private HOME removal
sequentially even when earlier cleanup fails, and independently settles its
original spawned MCP child through the existing process supervisor. Original operation and cleanup
errors remain private; its single final report names failed resources without
printing error messages and never claims verified success after cleanup failure.
A harness-only bridge captures the original `ChildProcess` from pinned MCP SDK
2.3.1 during transport startup. This SDK-internal field coupling has an explicit
version/binding regression. Recovery uses that retained direct-child handle,
with a 250 ms TERM grace and 1 second KILL grace; it never reconstructs ownership
from a PID or signals an unproven process group. A pre-close rejection regression
has a watchdog and verifies runner exit, child death and private HOME removal.
An incomplete stop retains the owner and reports uncertainty without exporting
its raw failure reason or claiming successful cleanup.

The live acceptance harness supports only the unauthenticated disposable lane.
It accepts no private credential input and passes no authentication value to
child-process argv. A process-level regression captures all seven CLI argv
vectors plus the stdio MCP argv. The 256-case synthetic credential/error run
uses the adapter boundary without spawning the CLI. The recorded live repetitions
were unauthenticated; their provider/build and teardown receipts remain valid.
The historical 15-second binary probe above was not repeated in this round.
Backend-dependent binary retrieval, one-shot YARA, comparison, and native
export acceptance remain unverified, pending the exact backend authority gate.

The selected manifest must match the literal canonical file SHA-256
`044ed40a91a0f81d94061c00d959ada2076a3639077e290318725b79a6b80d1c`;
UID, original-byte digest and size are anchored independently of that input.
An arbitrary internally consistent replacement is rejected before process or
HTTP delivery. The harness labels the status observation `generic-http-500`
with cause `unverified`; the actual missing-inventory diagnosis remains in the
separate disposable setup/log receipt. It does not infer backend absence from
an HTTP error or a caller-declared profile.
