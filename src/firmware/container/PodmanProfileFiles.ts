import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import {
  assertArtifactReadActive,
  withArtifactFileHandle,
  withArtifactRegularFile,
} from "../../artifacts/ArtifactFileOperation.js";
import { sameRegularFileState } from "../../filesystem/RegularFile.js";
import { readBoundedFileBytes } from "../../process/BoundedFileBytes.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import type { AnalysisErrorOptions } from "../../domain/analysisErrorBase.js";
import type { PodmanDescriptorIdentity } from "./PodmanStoreProfile.js";

export const podmanProfileUnavailable = (
  reason: string,
  options?: AnalysisErrorOptions,
) =>
  new AnalysisCapabilityUnavailableError(
    "podman",
    "firmware_container_runtime",
    reason,
    {
      ...options,
      userMessage: reason,
    },
  );
export const podmanPermissionMode = (mode: number | bigint) =>
  `0o${(Number(mode) & 0o7777).toString(8).padStart(3, "0")}`;

/** Bounded authoritative regular descriptor, including its source-byte identity before decoding. */
export const observePodmanProfileFile = (
  path: string,
  maximumBytes: number,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
  retainObservation?: (observation: {
    identity: PodmanDescriptorIdentity;
    bytes: Buffer;
  }) => void,
) =>
  withArtifactRegularFile(path, scope, signal, async (handle) => {
    const before = await handle.stat({ bigint: true });
    if ((await realpath(path)) !== path)
      throw podmanProfileUnavailable(
        `Profile descriptor path must be canonical without symlink parents: ${path}`,
      );
    if (before.size > BigInt(maximumBytes))
      throw podmanProfileUnavailable(
        `Selected profile descriptor exceeds its ${maximumBytes}-byte admission budget: ${path}`,
      );
    const bytes = await readBoundedFileBytes(handle, maximumBytes, signal);
    if (
      bytes === undefined ||
      !sameRegularFileState(before, await handle.stat({ bigint: true }))
    )
      throw podmanProfileUnavailable(
        `Selected profile descriptor changed during bounded admission: ${path}`,
      );
    const identity: PodmanDescriptorIdentity = {
      path,
      device: before.dev.toString(),
      inode: before.ino.toString(),
      uid: Number(before.uid),
      gid: Number(before.gid),
      mode: podmanPermissionMode(before.mode),
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    };
    const observation = { identity, bytes };
    retainObservation?.(observation);
    return observation;
  });

/** A directory FD is admitted without allowing a FIFO, symlink or missing-root initialization. */
export const observePodmanProfileDirectory = async (
  path: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
) => {
  assertArtifactReadActive(signal);
  const handle = await open(
    path,
    constants.O_RDONLY |
      constants.O_DIRECTORY |
      constants.O_NOFOLLOW |
      constants.O_NONBLOCK,
  );
  return withArtifactFileHandle(path, handle, scope, signal, async (handle) => {
    const before = await handle.stat({ bigint: true });
    if (!before.isDirectory() || (await realpath(path)) !== path)
      throw podmanProfileUnavailable(
        `Selected existing directory is not a canonical directory identity: ${path}`,
      );
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.uid !== after.uid ||
      before.gid !== after.gid ||
      before.mode !== after.mode
    )
      throw podmanProfileUnavailable(
        `Existing directory changed during admission: ${path}`,
      );
    return {
      path,
      device: before.dev.toString(),
      inode: before.ino.toString(),
      uid: Number(before.uid),
      gid: Number(before.gid),
      mode: podmanPermissionMode(before.mode),
    };
  });
};

/** Hash current runtime metadata or an executable without allocating its whole representation. */
export const identifyPodmanProfileFile = (
  path: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
) =>
  withArtifactRegularFile(path, scope, signal, async (handle) => {
    const before = await handle.stat({ bigint: true });
    if (
      (await realpath(path)) !== path ||
      before.size > BigInt(Number.MAX_SAFE_INTEGER)
    )
      throw podmanProfileUnavailable(
        `Identity descriptor is not a canonical bounded regular file: ${path}`,
      );
    const hash = createHash("sha256");
    let size = 0;
    const buffer = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      signal.throwIfAborted();
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      signal.throwIfAborted();
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      size += bytesRead;
    }
    signal.throwIfAborted();
    if (
      size !== Number(before.size) ||
      !sameRegularFileState(before, await handle.stat({ bigint: true }))
    )
      throw podmanProfileUnavailable(
        `Identity descriptor changed during admission: ${path}`,
      );
    return {
      path,
      device: before.dev.toString(),
      inode: before.ino.toString(),
      uid: Number(before.uid),
      gid: Number(before.gid),
      mode: podmanPermissionMode(before.mode),
      size,
      sha256: hash.digest("hex"),
    };
  });

/** Encoding is validated once at the descriptor owner; intentional U+FFFD remains valid. */
export const decodePodmanProfileText = (bytes: Uint8Array): string => {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch {
    throw podmanProfileUnavailable(
      "Selected profile/configuration contains invalid UTF-8",
    );
  }
};
