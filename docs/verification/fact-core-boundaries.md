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

## Verification scope

Production-boundary tests use actual loopback HTTP and disposable files, including
real socket disconnection, FIFO admission, exact metadata maxima, malformed
compact download JSON, contradictory native request echoes, unfinished oversized
HTTP bodies, cancellation, capacity and cleanup failures. These fixtures
do not establish real FACT service or native database conformance. Public CLI/MCP
composition and native import/export require their later integration and a supplied
disposable service/database lane. No existing corpus or ambient credential store
is used for these boundary checks.
