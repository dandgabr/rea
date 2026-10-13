# FACT Core corpus boundaries

The corpus adapter uses the caller's literal loopback HTTP(S) origin and declared
source profile. It does not discover a running instance, read a credential store,
or attest a service version from `/rest/status`. Corpus UIDs and virtual paths
belong to the external service; an observation has no local executable subject.

The profiles are pinned to [release 4.4.1](https://github.com/fkie-cad/FACT_core/tree/9ac65997a2b0fdaabd61bca2280fa22c441b1f92)
and [source 54aed90b](https://github.com/fkie-cad/FACT_core/tree/54aed90bacb13c484404018101527c72d0bff6c5).
Release 4.4.1 has no single-file analysis PUT. Every enqueue request using that
profile is refused before HTTP, including omitted or false `force`. Source-profile
PUT sends the caller's `force` selection. Neither profile admits arbitrary routes.

HTTP success alone does not establish an object, analysis or acknowledgement.
The adapter checks the selected producer envelope and native fields, including
analysis metadata, object metadata, comparison identity and mutation acknowledgements.
Available native request echoes are bound to the selected UID, plugin, query,
paging, comparison and binary representation. Reanalysis compares effective plugin
selection and `re_unpack`, respecting native unpacker removal/reappend semantics
without imposing plugin ordering. Contradictory echoes remain unknown with partial
producer values and digest; mutations and consuming reads are never retried or
compensated. Upload UID echoes are checked against the owned byte snapshot.
Statistics use the producer's raw category dictionaries rather than a status envelope.
Malformed responses remain unknown with their raw SHA-256 and available partial
producer values. Malformed UTF-8, duplicate members and nonfinite JSON numbers are
rejected without repairing the source representation.

## Consuming YARA collection

Collection identity includes canonical URL origin, declared profile, exact search
ID and private authentication context. Credentials and their private cache digest
are never exported. Equivalent trailing-slash and default-port spellings join the
same consumption while Evidence preserves the first caller's display endpoint.
The first caller owns the fetch and its cancellation signal. Concurrent callers
join its observation; canceling a joining caller does not cancel that shared fetch.
A captured observation survives subsequent delivery cancellation.

Successful collections and ambiguous delivery, socket loss or malformed-response
observations stay cached. A producer status-1 error is a failed observation, never
an absence claim. The exact HTTP-400 [not-ready-or-already-fetched error](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_binary_search.py)
returns no result: a later explicit collect may make another attempt. Proven
not-delivery and admission refusal also permit a later explicit attempt. There is
no automatic retry, polling, compensation or producer job cancellation.

## Transfer and resource ownership

Raw binary is limited to 128 MiB and nonbinary JSON to 8 MiB. Base64 has its own
actual `4 * ceil(rawBytes / 3)` allowance. Upload metadata is measured with JSON
escaping and UTF-8 before serialization; the binary body streams in bounded
chunks. Download and upload error-echo parsing measure encoded characters,
decoded bytes and original wire overhead separately. Unicode escapes and whitespace
consume the nonbinary wire budget. Retained Evidence omits binary representations,
preserving response SHA-256 and verified binary size/digest instead.

Token validation runs in an owned worker using the existing pinned `stream-json`
and `stream-chain` dependencies. Download binary types, duplicate members and
unexpected nested download structures are checked before generic metadata object
assembly. The worker has a 64 MiB old-generation and 8 MiB young-generation V8
heap ceiling. These limits apply to V8 heap, **not** Buffer/ArrayBuffer allocations
or total operating-system memory. Raw response chunks and their final buffer are
separately bounded; the final buffer transfers to the worker without another
large input copy. Decoded chunks and their final buffer each have the raw-byte
ceiling. Upload echoes hash decoded chunks without retaining another full binary.
The normalized metadata graph is redacted once under exclusive ownership and
sealed for immutable reuse through AnalysisExecution and Evidence, avoiding full
payload clones. These controls do not assert a fixed JSON-to-heap expansion factor
or protection against every system-wide memory failure.

The provider reuses `ArtifactAnalysisResources`: one outstanding heavy operation
per provider instance, with tagged capacity refusal for additional operations.
Identical-authority YARA callers join the existing collection before admission.
Cancellation terminates the owned parser worker. Failed termination retains its
owner and an observable cleanup uncertainty for explicit close/retry.

HTTP response readers are owned before header admission. An oversized declared
body is canceled even if it never finishes; streaming overflow also cancels its
reader. Failed cancellation retains the exact reader and lock for explicit close,
with cleanup uncertainty in the observation. Cleanup does not replace useful
admitted bytes or the original response failure and never repeats the request.

Snapshot roots are owned from creation, including failed acquisitions. Input
handles open nonblocking with no symlink following, then their actual descriptors
must identify regular files; a FIFO needs no writer to be rejected. Descriptor
and root cleanup failures retain owners. A failed post-observation cleanup does
not discard the producer observation.

Downloads create fresh outputs exclusively. The publication owner retains device
and inode identity from creation until commit or rollback. A write failure removes
only that uncommitted owned artifact; failed rollback remains owned for close.
The partial observation preserves independently verified response size, SHA-256
and selected UID plus written-byte count and cleanup uncertainty. Publication is
not claimed atomic, and a preexisting caller file is never overwritten or removed.

## Native interchange boundary

The native adapter has independent caller-declared interpreter/checkout/default
configuration authority. It does not infer a binding to the REST endpoint.
It checks twelve critical source files against the selected source/release pin,
observes resolved executable identities while invoking the original selected
venv path, and fingerprints the exact default `src/config/fact-core-config.toml`.
Only PostgreSQL source/effective socket directory, port, database and storage root
leave configuration parsing. Users and passwords are excluded from that
projection; actual password/API-secret values are privately retained only for
output redaction. Ordinary `postgres` role text and socket paths remain evidence.

The pinned producer maps literal localhost/127.0.0.1/::1 to
`/var/run/postgresql`; an explicit absolute Unix socket directory remains exact.
Remote/unresolved database selectors and relative storage roots are rejected.
Existing admin DB/storage privileges are prerequisites. REA never creates roles,
rewrites configuration or supplies `--force`. Python usersite/bytecode and libpq
ambient credential/service fallback are disabled through the owned command
environment; HOME/XDG and PostgreSQL fallback paths belong to private staging.
No ambient environment is persisted. Native storage-directory creation remains
an upstream effect. Configuration, critical source, interpreter and limiter
identity checks detect pre/post drift; they do not prevent races or attest every
installed imported dependency.

Archive preflight uses the locked zip.js reader with CRC32, overlap and explicit
local-header/central-directory identity checks,
actual streamed expansion accounting and the bounded owned JSON parser. It never
extracts archive paths. Duplicate member paths, traversal, links/special members,
encryption, missing/undeclared binaries, mismatched UID/SHA/size and unsafe
hierarchies are rejected before any selected import starts. Native object
metadata can repeat a UID: preserve all ordered occurrences, validate each
against actual binary bytes, and record the final occurrence selected by the
pinned importer's dictionary comprehension. Parent graph validation uses those
effective native objects. Simple native orphans remain explicit; cycles and
unresolved descendants after one-pass orphan pruning are rejected. Failed
preflight retains already verified binary hashes, metadata digest and the raw
producer metadata as partial source evidence.

All selected import archives are preflighted first, then official single-archive
calls run in caller order under one shared 120s deadline/admission. Exact native
import counts, existing-target skips and revision refusals are distinct
observations. Cancellation before the next invocation preserves its
`not_started` state and prior reported effect bounds. A skip/refusal continues;
an ambiguous exception/cancel during an issued invocation stops the
remaining archives as `not_started`. Exit0 never establishes import. DB object
writes precede native file writes and can partially fail or collide with a shared
UID; no retry, rollback or compensating delete is attempted. Reported counts do
not independently verify DB/storage commits. Rich diagnostics are interpreted
only as exact whole acknowledgement rows; wrapped/unrecognized or invalid UTF-8
output remains unknown. Original diagnostics, retained/observed byte counts,
retained-byte digests and UTF-8 validity remain explicit after provider redaction.
The diagnostic-limit error captures rich provenance when first raised; later
capture cannot replace its authoritative text or byte identity.

Exports run official multi-UID selection into private staging, monitor actual
output growth, verify each selected ZIP and publish verified archives only into
a fresh absent caller directory. Uncommitted publication is rolled back by the
owned tree; failed cleanup retains that exact owner for explicit close. Verified
archive facts survive publication or cleanup failure. Actual durable tree
publication establishes matching global and per-archive committed facts before
cleanup retries; later close failure preserves published bytes and records
cleanup uncertainty. Prepared metadata alone cannot establish publication.
Native export uses BytesIO;
the existing producer limiter applies AS1GiB, CPU120s, file size and zero core
before launch. Compressed staging and actual expanded bytes have separate
budgets. Metadata and aggregate retained native diagnostics each have an 8MiB
budget; crossing the aggregate diagnostic bound can transiently hold one more
bounded command capture before rejection. This is not a global OOM prevention
claim. Archive-member digests describe exact bytes; native capture representation
digest describes serialized command observations before redaction, not a raw
protocol stream.

Pinned native producer: [source CLI](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/firmware_import_export.py),
[source configuration](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/config.py),
[source object conversion](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/objects/file.py),
[release CLI](https://github.com/fkie-cad/FACT_core/blob/9ac65997a2b0fdaabd61bca2280fa22c441b1f92/src/firmware_import_export.py).

| Native choice       | Adapter disposition                                                    | Verification                                                                    |
| ------------------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `export UID...`     | Exact official selection; selected namespace has existing DB authority | Real host-native plain export and malformed producer export partial evidence    |
| `-o/--output`       | Private staging, then fresh verified caller output                     | Actual ZIP byte/hash readback; publication cleanup faults                       |
| `import ARCHIVE...` | Preflight all; ordered per-archive official calls with shared deadline | Real host-native import, shared-UID exception, skip and strict revision refusal |
| `-f/--force`        | Excluded; strict producer revision check retained                      | Real zero-exit incompatible-revision refusal                                    |
| `-h/--help`         | Presentation/developer; no raw CLI proxy                               | Root's direct producer help prerequisite check; not an analyst operation        |

## Verification scope

Production-boundary tests use actual loopback HTTP and disposable files, including
real socket disconnection, FIFO admission, exact metadata maxima, malformed
compact download JSON, contradictory native request echoes, unfinished oversized
HTTP bodies, cancellation, capacity and cleanup failures. Native tests include
actual supervised fixture processes, malformed byte digests, CRC-only corruption,
last-occurrence graph semantics, all-input preflight and failed fresh publication.
Fixture boundaries do not establish actual FACT conformance. Bounded seeded
archive/config/acknowledgement properties and ten specific consequential
mutants validate these owning rules; no global fuzz/mutation score is claimed.

A supplied disposable source54aed service and host-native checkout/venv/socket DB
were separately exercised with the compiled adapters. Host-native plain export
was verified/published; original gzip imported with a producer acknowledgement,
then a real shared-UID exception retained partial uncertainty and stopped the
third selection. Explicit later calls confirmed native existing-target skip and
strict revision refusal, both exit0. Another real host export omitted an effective
object for a binary and was rejected; present verified facts remain partial.
These checks concern supplied disposable resources only. Release native runtime,
full plugin inventory and public CLI/MCP/container-native composition remain
unverified until their later integration gates. No existing human corpus,
configuration rewrite, DB-role installation, push or publication is part of this
checkpoint.
