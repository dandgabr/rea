# Firmware container transport boundary

The internal container transport accepts a caller-selected, already initialized
rootless Podman store. This boundary currently provides bootstrap admission,
controlled host-client execution and local immutable-image observations. It does
not by itself establish provider readiness or public CLI/MCP container execution.
Container lifecycle, authoritative OCI admission and provider confinement must
also succeed before a producer starts.

The `podman-existing-store-v1` JSON profile selects Podman 5.8.7 semantics:
the selected and resolved executable paths and SHA-256, rootless UID, canonical
runtime and storage roots, native overlay with its complete typed options,
explicit SQLite/static-directory branch, selected configuration provenance,
an operator/probe initialization receipt and an existing per-user helper
association. Before any client launch, a bounded private snapshot of a quiescent SQLite
store must contain exactly one ordinary `DBConfig` schema1 row matching every
selected root and driver. Existing journal, WAL or SHM sidecars are refused;
transaction applicability remains unknown. An initialization assertion records
its authority; it is not
independent database or installed-source attestation. Unknown keys, unsupported
storage helpers/options and incomplete selections are refused before a Podman
command, including version or info. Analysis never initializes, migrates or
repairs a store.

Executable, configuration and directory identities remain stable selections.
Database, indices and lock-file hashes are dated observations: legitimate DB
transactions and atomic index replacement change them. Admission reopens current
regular files without following links, hashes them under the operation's signal,
and rejects a changing individual read. Historical mutable hashes and inodes are
not permanent pins. The external helper's PID, start, UID, namespaces and
runtime pidfile association are observed again; observation grants no signal or
lifecycle authority over that helper.

The SQLite staging budget is 128 MiB per admission, a resource policy rather
than a SQLite format limit. Admission checks the authoritative size before
copying and meters each 64 KiB chunk before writing. Stable source FD and path
generation, absent sidecars and private-copy digest/readback must agree. Reads
and partial writes are awaited on the admitted descriptors, with cancellation
checks around each operation. A stream abort cannot take over their close
authority. Failed output-descriptor cleanup retains its private snapshot root;
retry closes the same descriptor and removes the root without copying again. A
separate supervised Node helper opens only this private copy, uses a 64 MiB
JavaScript heap ceiling, a 2 MiB SQLite page cache, no mmap/extensions, fixed
queries with at most two rows, 64 KiB SQLite value limits and 4 KiB SQL limits.
These settings bound representation; they do not assert a total process-memory
limit. The helper shares CPU/core/deadline/capture supervision but is distinct
from the Go transport and native producer. Its script is shipped in the npm
package, copied privately and digest-checked; failed process/snapshot cleanup
retains that exact owner and observations for retry.

After admission, `info --format=json` is the mandatory first Podman command.
Only a matching rootless/native-overlay metadata response admits later clients.
Each prepared transport owns private HOME, empty `mounts.conf`, empty valid
authentication, hooks directory and fixed storage/container configuration. Its
environment is explicit and excludes ambient credentials, proxy and container
configuration overrides. Every command uses the same exact root/runroot/driver
and complete option selection, validated against the actual invocation before
spawn. The complete supported command is validated independently of its builder;
its operation and positional identity must match the immutable request. Image and
full-container-ID operands follow an explicit `--` delimiter. Image references
use the pinned native name/domain/path/tag grammar with the 255-byte repository
name and 128-byte tag bounds, preserving exact selected text. Unknown subcommands
and extra flags or operands are refused before launch. Already-local `repository@sha256:…` and full `sha256:…` image IDs are
distinct immutable selections; archive loading may preserve an image ID while
leaving `RepoDigests` empty. Image inspection does not fetch absent images.

Host transport and producer limits have separate owners. Podman uses supervised
CPU 120 seconds, core size zero, an operation deadline and bounded diagnostics.
The native producer's 1 GiB address-space and output-file limits do not wrap the
Go host client or restrict legitimate Podman metadata growth. Producers must
apply their own limits inside the admitted container. Shared supervision retains
the authoritative captured byte SHA-256, counts, strict UTF-8 validity and
command identity, including failures.

Client cleanup validates the captured direct PID's start, run token and parent
before PID-only termination. It never sweeps a process group or run token to
claim helpers or containers. Failed descriptor/client cleanup retains the same
owner for retry. Preparation failures retain their typed primary projection,
meaningful filesystem code/path/reason, cancellation and captured or partial facts
when cleanup also fails; retry does not repeat setup. Exact container IDs, prepared OCI/mount observations and
container settlement need their separate lifecycle owner; host-client exit does
not prove container or producer exit. A bootstrap or image-inspection pass is
not provider conformance.
