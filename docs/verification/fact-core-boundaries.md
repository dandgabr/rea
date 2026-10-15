# FACT Core corpus boundaries

REA uses a caller-selected literal loopback HTTP(S) origin and a declared
protocol profile. It does not discover a running instance, read a credential
store, or attest a service version from `/rest/status`. Corpus UIDs and virtual
paths belong to the external service; corpus Evidence has no local executable
subject.

The profiles describe upstream source at [release 4.4.1](https://github.com/fkie-cad/FACT_core/tree/9ac65997a2b0fdaabd61bca2280fa22c441b1f92)
and [source 54aed90b](https://github.com/fkie-cad/FACT_core/tree/54aed90bacb13c484404018101527c72d0bff6c5).
They are declarations, not proof that the selected service runs either
revision. `enqueue_corpus_analysis` is not part of the public REA contract;
neither profile permits arbitrary routes.

HTTP success alone does not establish an object, analysis, or acknowledgement.
The adapter validates producer envelopes and requires the pinned upstream
request echoes on successful firmware/file-object searches (query and paging,
plus firmware recursion flags), object detail (UID), analysis (UID and plugin),
parent analysis (UID), comparison (normalized selection), and binary download
(UID and `tar` selection). Firmware summary detail is selected by the exact
[`summary` URL query](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_firmware.py#L173-L187): pinned FACT reads it to select the returned representation
but echoes only the UID, so REA binds that boolean to its non-redirected
request and treats any returned contradictory `request.summary` as unknown.
Missing or contradictory required producer echoes keep the observation
unknown. Error responses may contain only partial echoes and are not required
to repeat the full selection. `/rest/statistics` is a raw dictionary, and
successful [YARA result retrieval](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_binary_search.py#L65-L84) also has no request echo in either pinned
revision. REA binds its one-shot result to the exact caller-selected literal
`/rest/binary_search/<search_id>` request path, refuses redirects, and does not
fabricate a producer echo; a present contradictory `request.search_id` keeps
the observation unknown. YARA start is excluded and is not used to create or
attest the caller's search ID. Contradictory or malformed responses remain
unknown with available partial facts and digests. REA does not retry consuming
reads or compensate for ambiguous delivery. Statistics retain the producer's
raw category dictionaries.

The status plugin inventory deliberately mirrors upstream: `/rest/status`
removes `unpacker` from its plugin map. Its absence from the returned inventory
does not establish that the service has no unpacker implementation.

## Consuming YARA collection

Collection identity includes canonical URL origin, declared profile, exact
search ID, and private authentication context. Credentials and their private
cache digest are not exported. Equivalent trailing-slash and default-port
spellings join the same collection while Evidence preserves the first caller's
display endpoint. The first caller owns fetch cancellation; concurrent callers
join its observation, and canceling a joining caller does not cancel the fetch.

Successful, ambiguous, socket-loss, and malformed-response observations stay
cached. A producer status-1 response is a failed observation, never an absence
claim. The exact HTTP-400
[not-ready-or-already-fetched response](https://github.com/fkie-cad/FACT_core/blob/54aed90bacb13c484404018101527c72d0bff6c5/src/web_interface/rest/rest_binary_search.py)
contains no result; a later explicit collect may try again. Proven
not-delivery and admission refusal also permit a later explicit attempt. There
is no automatic retry, polling, compensation, or producer-job cancellation.

## Transfer and resource ownership

Raw binary is limited to 128 MiB and nonbinary JSON to 8 MiB. Base64 has a
separate actual `4 * ceil(rawBytes / 3)` allowance. Download parsing accounts
for wire bytes and decoded bytes separately and omits binary representations
from retained Evidence. JSON escaping and UTF-8 are measured before payload
serialization.

The response parser uses an owned worker with V8 heap limits. These limits
apply to V8 heap, not Buffer/ArrayBuffer allocations or total operating-system
memory. Raw response chunks and their final buffer are separately bounded; the
final buffer transfers to the worker without another large input copy. The
normalized metadata graph is redacted once and sealed for immutable reuse
through AnalysisExecution and Evidence.

The provider admits one outstanding heavy operation per instance. Identical
authority YARA callers join before admission. Cancellation terminates the
owned parser worker; failed termination retains its owner and reports cleanup
uncertainty for explicit close/retry. HTTP readers are owned before header
admission. Oversized declared or streaming bodies are canceled; failed cleanup
retains the exact reader and lock without repeating the request.

Downloads require a fresh output path and publish through an owned file. A
write failure removes only its uncommitted output; failed rollback remains
owned for close. Partial Evidence retains independently verified response
size, digest, selected UID, written-byte count, and cleanup uncertainty.
Publication is not claimed atomic, and a preexisting caller file is never
overwritten or removed.

## Native interchange

Native import is not exposed. `export_corpus_firmware` remains a planned
contract but the native provider refuses every runtime before checking
producer identity or invoking a process, container session, or Podman. No
native import or export support is currently implemented.

## Verification status

The active REST tests use source-derived protocol expectations, controlled
loopback HTTP responses, and disposable files. They exercise adapter behavior,
including request construction, response normalization, malformed and
oversized bodies, cancellation, capacity, cleanup, credential redaction, and
public CLI/MCP contracts. Those fixtures alone do not establish compatibility
with a running FACT service.

A disposable live service was assembled with Podman on an internal-only network:
PostgreSQL 18.6 and Valkey 9.1.2 had no published ports, and the FACT frontend
was bound to host loopback. FACT Core source was checked out at
`54aed90bacb13c484404018101527c72d0bff6c5` and mounted read-only over the local
Python runtime image. The image's dependency layer is not source-attested. The
database schema was initialized from that checkout, and an upstream FACT test
fixture was inserted directly into this disposable database and its private
container storage. No Docker/runtime socket was mounted; the FACT backend was
not started because upstream imports `docker.from_env()` during backend startup
and exits when the socket is absent. No firmware upload or analysis task was
submitted.

The observation can be reproduced without any saved credential: check out the
pinned FACT revision, start PostgreSQL and Valkey on a Podman `--internal`
network, mount the checkout read-only into the pre-existing FACT Python runtime
image, initialize the schema with that checkout's `init_postgres.py`, and
publish only the frontend port on `127.0.0.1`. For the observed run, the network
was `rea-fact-acceptance-54aed`; temporary containers were
`rea-fact-pg-54aed`, `rea-fact-redis-54aed`, and `rea-fact-app-54aed`. The
fixture was upstream's `dummy` firmware test object, UID
`418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787`.
The image dependency layer is local and must be reviewed independently before
using this as a supply-chain-attested deployment test.

With the frontend mapped to local port `34937` in that run and the fixture
present, these safe calls reproduce the five successful REST checks (the CLI
binary must be built from this branch):

```sh
FACT='{"endpoint":"http://127.0.0.1:34937","profile":"source-54aed90b"}'
FACT_UID='418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787'
rea inspect-corpus-statistics "{\"connection\":$FACT}" --json
rea search-corpus-objects "{\"connection\":$FACT,\"kind\":\"firmware\",\"query\":{},\"offset\":0,\"limit\":10}" --json
rea inspect-corpus-gaps "{\"connection\":$FACT}" --json
rea inspect-corpus-object "{\"connection\":$FACT,\"kind\":\"firmware\",\"uid\":\"$FACT_UID\"}" --json
rea inspect-corpus-analysis "{\"connection\":$FACT,\"uid\":\"$FACT_UID\",\"plugin\":\"dummy\"}" --json
```

The production stdio MCP adapter was separately invoked with the equivalent five
named operations and returned the same completed HTTP observations. Cleanup for
that run removed the three named containers and the `rea-fact-acceptance-54aed`
network; the temporary checkout (including its synthetic local-only test
configuration) was deleted. These names are run-specific and can be reused only
after confirming no matching user-owned container/network exists.

The compiled REA CLI was also invoked natively on the host with Node `22.23.1`
(within the declared `^22.19.0` engine range) against an ephemeral loopback HTTP
fixture for `inspect-corpus-statistics`; it exited 0 with completed Evidence and
one request. This supplements the Node `24.18.0` Podman CLI/MCP acceptance. It
does not enable FACT native export, which remains refused for every runtime.

### Admission mutation and fuzz evidence

Scoped mutation checks ran the full `FactRestProvider.test.ts` source suite in
Node `24.18.0` using a disposable Podman container. They contacted no FACT
service and mounted no runtime socket (the container used its normal Podman
network). Each mutant was a one-occurrence temporary source replacement,
restored byte-for-byte in a `finally` block before the next run. The test
command inside each container was:

```sh
npm run test:local -- src/firmware/fact/FactRestProvider.test.ts
```

The three targeted mutations were all killed:

| Boundary               | Temporary mutant                                                                                                                              | Result                                                                                                                                                     |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| REST admission         | Changed `if (excluded.has(operation as string))` to `if (false && excluded.has(operation as string))` in `FactRestProvider.ts`.               | Exit 1: `denies FACT mutation and plugin-triggering REST operations before HTTP` failed because `upload_corpus_firmware` was admitted; 23/24 tests passed. |
| Evidence redaction     | Changed the redactor's `const output = apply(inputText, retainedBytes);` to `const output = inputText;` in `knownSensitiveValueRedaction.ts`. | Exit 1: 3/24 tests failed, including encoded-key redaction and Unicode redaction; 21/24 passed.                                                            |
| Producer normalization | Changed `valid = schema.safeParse(data).success;` to `valid = true;` in `FactProducerResponse.ts`.                                            | Exit 1: 2/24 tests failed, including malformed successful envelopes and missing native analysis metadata; 22/24 passed.                                    |

These mutations establish that the named tests detect these specific regressions;
they are not a full mutation score for the FACT implementation. Source state was
restored and `git diff --check` passed afterward. Property-based coverage in the
same branch exercises generated connection strings against literal-loopback
admission and generated arbitrary response bytes through the bounded JSON worker,
asserting no leaked worker ownership. The authorization boundary suite also runs
128 deterministic invalid-header cases across schema, CLI and MCP. These tests
do not constitute a coverage-guided native fuzzer run against FACT Core itself.

The focused public boundary run also checks that the seven excluded CLI names
(`upload-corpus-firmware`, `reanalyze-corpus-firmware`,
`enqueue-corpus-analysis`, `start-corpus-comparison`, `start-corpus-yara`,
`delete-corpus-firmware`, and `import-corpus-firmware`) return
`COMMAND_NOT_FOUND` without making an HTTP request. This replaces a stale test
that expected the removed `enqueue-corpus-analysis` command to submit a PUT.
The final focused run passed 13 tests in six files; the source provider run
passed 51 tests in six files; `check:fast` passed two tasks; and `docs:check`
passed six tasks plus both README consistency tests. These are branch checks,
not a full `check:pr` run.

Against that service, real HTTP 200 responses were observed for statistics,
firmware search, missing-analysis lookup, fixture object detail, and its
`dummy` analysis result. REA's compiled CLI and production stdio MCP each
returned `state=completed` and `http_status=200` for statistics, firmware
search, missing-analysis lookup, object detail, and analysis lookup. These are
live upstream REST observations; the empty database/search results and the
single seeded fixture limit their breadth. `/rest/status` returned HTTP 500
because it requires the backend's plugin inventory. A direct binary-retrieval
request did not complete within a 15-second probe because the frontend routes
file access through backend intercom. Backend-dependent binary retrieval,
one-shot YARA collection, comparisons with stored results, release-profile
behavior, and native export were not verified against the live deployment.
The caller-selected profile remains a declaration; it is not service-side
revision attestation. Plugin-triggering endpoints were not called, and no
container authority is inferred for other FACT deployments. Native import and
export acceptance are not claimed.
