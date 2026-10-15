import { constants } from "node:fs";
import { open, realpath, type FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { sameRegularFileState } from "../../filesystem/RegularFile.js";
import { readBoundedFileBytes } from "../../process/BoundedFileBytes.js";
import { firmwareToolUnavailable } from "../FirmwareCommand.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  FirmwareFileCleanupError,
  withFirmwareFiles,
} from "../FirmwareFiles.js";
import type { PodmanDescriptorIdentity } from "./PodmanStoreProfile.js";

export const podmanProfileUnavailable = (reason: string) =>
  firmwareToolUnavailable("podman", "firmware_container_runtime", reason);
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
  withFirmwareFiles(
    [path],
    "firmware_container_runtime",
    signal,
    scope,
    async ([handle]) => {
      if (handle === undefined)
        throw podmanProfileUnavailable("Missing admitted profile descriptor");
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
    },
    "podman",
  );

/** A directory FD is admitted without allowing a FIFO, symlink or missing-root initialization. */
export const observePodmanProfileDirectory = async (
  path: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
) => {
  signal.throwIfAborted();
  const handle: FileHandle = await open(
    path,
    constants.O_RDONLY |
      constants.O_DIRECTORY |
      constants.O_NOFOLLOW |
      constants.O_NONBLOCK,
  );
  const owner = {
    kind: "file-handle" as const,
    resource: path,
    handle: new OwnedFileHandle(handle),
  };
  let primary: unknown;
  try {
    signal.throwIfAborted();
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
  } catch (cause: unknown) {
    primary =
      cause instanceof AnalysisError
        ? cause
        : signal.aborted
          ? new AnalysisCancelledError("firmware_container_runtime", { cause })
          : cause;
    throw primary;
  } finally {
    const released = await scope.release(owner);
    if (released.kind === "failed")
      throw new FirmwareFileCleanupError(
        scope,
        path,
        "firmware_container_runtime",
        released.cause,
        primary,
        "podman",
      );
  }
};

/** Hash current runtime metadata or an executable without allocating its whole representation. */
export const identifyPodmanProfileFile = (
  path: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
) =>
  withFirmwareFiles(
    [path],
    "firmware_container_runtime",
    signal,
    scope,
    async ([handle]) => {
      if (handle === undefined)
        throw podmanProfileUnavailable("Missing admitted identity descriptor");
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
    },
    "podman",
  );

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
