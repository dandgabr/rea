# FACT Core corpus workflows

FACT corpus workflows use a caller-selected existing service or the official
native interchange CLI. They do not require a local binary analysis session.
REST and native database authority are declared independently: matching config,
UIDs or timestamps does not prove they address the same corpus.

All 18 MCP tools below have a CLI command formed by replacing underscores with
hyphens. The CLI takes one exact JSON object or a path to a JSON file, and
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
container can expose its REST port on host loopback. Container-native interchange
execution is not yet implemented in this phase.

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

| MCP tool                         | Additional input and meaning                                                                                                                                                                                                                                                 |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `inspect_firmware_corpus`        | Status and dynamic plugin inventory; no readiness guarantee.                                                                                                                                                                                                                 |
| `search_corpus_objects`          | `kind`: `firmware`/`file`; `query` defaults `{}`, `offset`/`limit` default 0. Limit 0 preserves producer-unbounded meaning. `recursive` requires firmware and nonempty query; `inverted` requires recursive. Returns only the requested page.                                |
| `inspect_corpus_object`          | `kind`, `uid`; `summary` defaults false and is firmware-only.                                                                                                                                                                                                                |
| `inspect_corpus_analysis`        | `uid`, exact dynamic `plugin`.                                                                                                                                                                                                                                               |
| `inspect_corpus_parent_analysis` | `uid`, `plugin`: `file_system_metadata`/`qemu_exec`; preserves native `included_files` parent-context results.                                                                                                                                                               |
| `upload_corpus_firmware`         | `path`, `metadata`, exact `plugins` array. Metadata requires `device_name`, `device_part`, `device_class`, `file_name`, `version`, `vendor`; `release_date` defaults `1970-01-01`, `tags` defaults empty. `unpacker` is an automatic dependency, not an analysis selection.  |
| `reanalyze_corpus_firmware`      | `uid`, `plugins`, separate `re_unpack` (default false); select plugins or re_unpack. Native unpacker removal/reappend semantics are preserved.                                                                                                                               |
| `enqueue_corpus_analysis`        | `uid`, `plugin`, `force` (default false). Source profile only; release profile refuses before HTTP for every force choice.                                                                                                                                                   |
| `start_corpus_comparison`        | Distinct `uids` (at least two), `redo` (default false).                                                                                                                                                                                                                      |
| `inspect_corpus_comparison`      | Distinct `uids`; native HTTP 202 can carry a completed comparison.                                                                                                                                                                                                           |
| `start_corpus_yara`              | Raw YARA source text in `rule_file`, optional `uid`; returns a search ID for explicit collection.                                                                                                                                                                            |
| `collect_corpus_yara`            | `search_id`; GET consumes the producer result.                                                                                                                                                                                                                               |
| `inspect_corpus_statistics`      | Optional `category`: `architecture`, `crypto_material`, `elf_executable`, `exploit_mitigations`, `file_type`, `firmware_meta`, `general`, `ips_and_uris`, `known_vulnerabilities`, `release_date`, `software_components`, `unpacking`. Raw dictionaries remain native facts. |
| `inspect_corpus_gaps`            | Missing/failed analysis GET requires producer delete privilege despite being non-destructive.                                                                                                                                                                                |
| `download_corpus_binary`         | `uid`, `repacked` (default false), fresh absent `output_path`. Original bytes require actual UID/SHA/size equality. Repacked ZIP has a distinct digest.                                                                                                                      |
| `delete_corpus_firmware`         | `uid`; retain the actual deleted-files report. Shared child identities can survive.                                                                                                                                                                                          |

Queue acknowledgements mean `accepted`, not analyzed. Trusted installed plugins
can execute code and permit egress. Reanalysis, force and redo can replace
analyses. Caller cancellation stops REA's transport, not an accepted external
job. No automatic polling, retry, fallback, compensating deletion or server-side
cancellation occurs. A lost response or malformed acknowledgement can leave
mutation delivery unknown.

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

`export_corpus_firmware` requires `interpreter`, `checkout`, `profile`, `uids`,
and fresh absent `output_directory`. `import_corpus_firmware` requires the same
selection and ordered `archives`. Optional `binding_declaration` is a caller
assertion, not proof of an HTTP binding. Both accept `max_output_bytes` (default
256 MiB, maximum 512 MiB) and `max_output_files` (default 10,000, maximum 100,000).

```sh
rea export-corpus-firmware /absolute/path/to/export.json --json
rea import-corpus-firmware /absolute/path/to/import.json --json
```

```json
{
  "name": "export_corpus_firmware",
  "arguments": {
    "interpreter": "/opt/fact/venv/bin/python",
    "checkout": "/opt/FACT_core",
    "profile": "source-54aed90b",
    "uids": [
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_3"
    ],
    "output_directory": "/tmp/new-fact-export"
  }
}
```

The checkout must contain the exact profile's `src/firmware_import_export.py`
and required critical source files, with default config at
`src/config/fact-core-config.toml`. REA observes exact critical source,
interpreter and default configuration identities before/after work, including
nonsecret effective PostgreSQL socket/port/database and storage selection.
Installed Python dependencies remain caller-trusted. Identity observations can
detect drift; they cannot prevent every race. Existing local admin DB/storage
prerequisites are caller-provided. REA never initializes a database, installs
roles, rewrites configuration, selects arbitrary argv or uses native `--force`.
Import may create configured storage directories through the official producer.

All selected import archives are snapshotted and preflighted before any native
command: ZIP local/central headers, CRC, duplicate paths, binary UID/hash/size,
metadata occurrences, effective native nodes, graph coverage and expansion
budgets. Repeated metadata UIDs are preserved in source order and the official
last occurrence is effective; every occurrence is validated. Missing effective
binary metadata, unresolved graph edges and cycles are rejected. Malformed
producer exports remain partial observations rather than being repaired.

Imports invoke the official producer once per selected archive in caller order
under one shared deadline. Exact existing-target skips and revision refusals
continue; unknown producer/transport failure stops remaining archives as
`not_started`. Exit 0 does not prove import: retain reported counts and native
outcomes. Native objects are imported before files; a shared UID can cause a
partially written failed archive. REA does not roll back, retry or compensate.
Exports verify bytes independently before publication. A durable publication
survives a later cleanup failure with its verified paths/digests and explicit
cleanup uncertainty.

## Evidence and resource limits

Corpus Evidence has `subject: null`, `authority: external-service`, observed
confidence and provider version null unless actually observed. Results preserve
`not-delivered`, `accepted`, `completed`, `failed` or `unknown`, actual native
responses, partial facts, digests, output receipts and coverage. HTTP success or
process exit alone cannot establish completion. CLI failed/unknown/undelivered
outcomes exit 1 while preserving Evidence; MCP delivers the same facts inline.
Tool annotations distinguish network, filesystem, process and mutation effects.

Each independent provider admits one outstanding heavy operation; capacity
refuses immediately. Retained uncertain producer/parser/file cleanup can hold
admission until explicit close/recovery. Cleanup retries never replay native
mutations. Operations have a 120-second deadline, 128 MiB input/binary limit,
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

Native producer limits require Linux util-linux `prlimit` (default
`/usr/bin/prlimit`, override absolute `REA_FIRMWARE_PRLIMIT_COMMAND`) with 1 GiB
address space, CPU 120 seconds, core dumps disabled and bounded output files.
Default PostgreSQL Unix sockets and local storage are supported; remote native
DB configuration is unavailable. No aggregate container confinement is claimed.

Real verification used source-54aed90b REST inside an owned disposable container
with actual `file_type`, `file_hashes`, `printable_strings` and unpacker, plus
host-native Python interchange against separate owned PostgreSQL/socket/storage.
Optional full-plugin readiness, release-profile live behavior and product
container-native execution remain unverified. Producer fixtures and boundary
fuzz/mutation tests do not establish those claims.
