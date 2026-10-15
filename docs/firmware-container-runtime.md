# Firmware container transport boundary

## Current support status

Production REA does not create, initialize, start, stop, kill, remove, build,
pull, or reconfigure containers. It also does not yet admit or execute inside a
caller-selected existing container. The production lifecycle-command admission
and container acquisition APIs fail closed. Firmware container execution is
therefore unsupported in this revision; the internal Podman store and image
observation work below is not evidence of container confinement or provider
support. Disposable container lifecycle operations in tests are test-fixture
cleanup only.

An existing-container mode remains deferred until REA can select an exact
already-running container and prove its identity, image, mounts, network,
namespace, capabilities, devices, and input immutability without changing its
lifecycle. Rootless status alone is insufficient.

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

**Deferred design, not current behavior:** the internal lifecycle owner is retained before `create` can have effects. It
binds the full container ID, immutable image ID, owner token, creation timestamp
and selected store before acquiring cleanup authority. A missing acknowledgement
can be recovered by exact token discovery followed by full identity inspection;
it never repeats creation, initialization or workload start. Created containers
need not expose an initialized OCI path or image root yet. Initialization admits
those later fields, positive host process generations, raw OCI, mountinfo and
prepared namespace observations before start. Cleanup rechecks the immutable
association, settles only the owned container and requires exact absence plus
recorded process-generation settlement. An exited native overlay may omit its
current merged directory; cleanup retains the original admitted root binding and
permits that omission only with an exited/stopped, nonrunning PID-zero state.
Failed cleanup retains the dependent staging and transport roots for retry.

### Deferred policy and observer details

These are design constraints and internal observations; they do not enable
firmware execution in a container.

The proposed default OCI policy is pinned to Podman 5.8.7 and crun 1.28 on the
measured Linux x86_64 rootless native-overlay host. Fixed read-only image,
network-none, nonroot keep-id, zero capabilities and no-new-privileges remain
mandatory. Staging roles use `/rea-input` read-only, `/rea-work` writable and
optional `/rea-plugins` read-only, with explicit nosuid/nodev and disjoint source
roots. Runtime-generated mounts are compared semantically without assuming an
order for disjoint destinations. Mask multiplicity is preserved, including the
observed stacked powercap mask. Host-generated CPU thermal masks follow the
pinned vendor rule rather than a fixed CPU count. Unsupported runtime or policy
drift is refused. Prepared SELinux execution labels are pending `attr/exec`
observations; current labels and post-FIFO NNP/seccomp state are distinct facts.
No experimental label, proc-unmask, privileged or unconfined policy is implied.

Optional `metadata_observer` selects the fixed `python-preloaded-v1` protocol,
absolute selected/resolved Python paths, executable SHA-256 and Python 3.14.8.
The packaged helper is read and admitted before launch as fixed `-c` bytes. The
interpreter executes through its retained FD. All code, imports, failure handling
and serialization are preloaded in the parent view before single-threaded user
and mount namespace entry through inherited, generation-bound FDs. A post-entry
audit guard refuses code loading, process creation and thread creation. There is
no post-entry exec or helper-path lookup. Credential maps, emptied supplementary
groups, entered namespaces, acquired host PID/run token and interpreter descriptor
identity are checked alongside anchored process-generation brackets.

This observer is metadata-only: O_PATH/no-follow descriptors compare the image
root, four runtime binds and up to three staging roles through helper/prepared
root views. It neither reads firmware nor grants lifecycle authority over the
external per-user helper. Its fixed request is at most 16 KiB, response and each
capture at most 64 KiB, live transient FD count at most 32 and module inventory
at most 128. Complete argv/environment representation is capped at 96 KiB before
spawn. Exact UTF-8 response size is accounted before JSON allocation. Its
supervised process uses a 10-second monotonic operation budget, CPU 5 seconds,
address space 1 GiB, file size 1 MiB and core size zero. These limits are separate
from the Go transport and producer policies. Captures and independently observed
partial facts survive cancellation, refusal and failed close; retry settles the
same process/descriptor owner before releasing dependent resources.

Source and installed default-policy Python sentinels and alternate private-view
metadata controls verify this boundary. They do not establish Binwalk readiness,
inner-bwrap confinement or public firmware container support. Those producer and
public CLI/MCP acceptance lanes require their own tested policy and evidence.
