# Unblob integration runtime

This disposable Podman image is the complete test root for the native Linux
user-systemd acceptance. It pins the Python base image by digest, Unblob by its
audited upstream commit, the 7-Zip package required by the generated gzip/USTAR
fixture, and every Python distribution in `requirements.lock`. Build tools stay
in the intermediate image stage; the exported runtime contains the Python
interpreter, Unblob entrypoint, shared libraries, package data, and `7z`.

Build and inspect the image:

```sh
podman build --pull=never \
  --file tests/fixtures/firmware/unblob-runtime/Containerfile \
  --tag localhost/rea-unblob-runtime:26.6.4 \
  tests/fixtures/firmware/unblob-runtime
podman image inspect localhost/rea-unblob-runtime:26.6.4 \
  --format '{{.Digest}}'
podman run --rm localhost/rea-unblob-runtime:26.6.4 --version
podman run --rm --entrypoint /bin/sh localhost/rea-unblob-runtime:26.6.4 \
  -c 'command -v 7z && 7z i | head -n 3 && ldd /usr/local/bin/python3'
```

`--pull=never` makes the run use the locally available base image. For a fresh
machine, pull the exact base named in `Containerfile` first; do not replace the
digest with a floating tag. Network access is needed only while building the
image to fetch the pinned upstream Git revision and Python distributions.

For direct upstream CLI acceptance, mount the generated fixture read-only and
an empty temporary output directory read-write. Disable networking and remove
all capabilities. Make private copies of the input and output directories first
so Podman's SELinux relabeling cannot alter repository-owned fixtures. A direct
container check can use this pattern from the repository root:

```sh
set -eu
umask 077
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/input" "$work/output"
cp _reference/firmware-integration/generated/firmware.bin "$work/input/firmware.bin"
podman run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --userns=keep-id \
  --tmpfs /tmp:rw,nosuid,size=64m \
  -v "$work/input:/input:ro,Z" -v "$work/output:/output:rw,Z" \
  localhost/rea-unblob-runtime:26.6.4 \
  --extract-dir /output --report /tmp/report.json --log /tmp/unblob.log \
  /input/firmware.bin
```

Compare regular files under `$work/output` with the generated `oracle.json` by
relative path, size and SHA-256. This checks upstream container behavior; it
does not establish REA's native systemd profile. Do not mount a home directory,
engine socket, or other host state.

The native profile is currently unavailable pending current-head CLI/MCP/systemd
acceptance. It also refuses caller-owned runtime roots: the interpreter,
Python import roots, and their ancestors must be owned by another identity and
not effectively writable by the invoking user. A `podman export` extracted into
a caller-owned temporary directory does not meet this gate. Do not run the
native acceptance command below with such a root. A maintainer-approved,
protected runtime installation is needed before that lane can be tested.

The Unblob-only public CLI/MCP acceptance command is
`npm run verify:unblob-firmware`; it does not require a Binwalk executable and
compares extraction files with the generated `oracle.json` when the protected
runtime precondition and current-head acceptance are available. The broader
`npm run verify:firmware` command requires both Unblob and Binwalk.

```sh
set -eu
umask 077
image=localhost/rea-unblob-runtime:26.6.4
container=rea-unblob-runtime-root
runtime_root="$(mktemp -d)"
archive="$(mktemp)"
cleanup() {
  podman rm --force "$container" >/dev/null 2>&1 || true
  rm -f "$archive"
}
trap cleanup EXIT
podman create --name "$container" --entrypoint /bin/sh "$image" -c true >/dev/null
podman export --output "$archive" "$container"
tar --extract --file "$archive" --directory "$runtime_root" --no-same-owner
export REA_UNBLOB_RUNTIME_ROOT="$runtime_root"
export REA_UNBLOB_COMMAND="$runtime_root/usr/local/bin/unblob"
export REA_BINWALK_COMMAND=/absolute/path/to/binwalk
export REA_FIRMWARE_FIXTURE_ROOT="$PWD/_reference/firmware-integration/generated"
npm run verify:firmware
```

The test root remains under the caller's control. Remove it after acceptance.
Never install `7z` or Unblob on the host as part of this workflow. Keep downloaded
firmware read-only; the generated fixture is the deterministic acceptance
oracle.
