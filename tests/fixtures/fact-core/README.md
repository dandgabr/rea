# Pinned FACT REST fixture

`manifest.json` pins upstream public `src/test/data/container/test.zip` at
FACT Core commit `54aed90bacb13c484404018101527c72d0bff6c5`. Its SHA-256 and
787-byte length were computed from that Git checkout before seeding the
owned disposable database. The binary itself is not copied here.

`object.json` is the producer-shaped JSON golden observed from the isolated
frontend reading that fixture. Only the volatile timestamp was set to 42.
It tests response admission; it does not attest the dependency image or a
running service revision. The expected dummy analysis is defined by the pinned
upstream `src/test/common_helper.py`, not inferred from an arbitrary service.

The live verifier performs GET only and requires a selected service seeded
with exactly this firmware. It neither seeds nor starts services. Its UID and
metadata-size checks do not establish binary retrieval. Backend-dependent
binary and one-shot YARA acceptance remain unverified.

The manifest file itself is pinned to SHA-256
`044ed40a91a0f81d94061c00d959ada2076a3639077e290318725b79a6b80d1c`.
The verifier also anchors the exact UID, original SHA and 787-byte size as
literals. A byte-identical copied manifest is allowed; changing its content or
serialization requires explicit pin review. Generic status HTTP 500 remains
cause-unverified in the harness; causal service-log receipts are separate.
