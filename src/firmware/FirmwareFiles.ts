import { AnalysisError } from "../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import type { FileHandle } from "node:fs/promises";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import {
  openRegularFile,
  RegularFileAdmissionFailure,
  sameRegularFileState,
} from "../filesystem/RegularFile.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { createHash } from "node:crypto";
import { constants, createReadStream, createWriteStream } from "node:fs";
import {
  chmod,
  lstat,
  opendir,
  open,
  readlink,
  realpath,
} from "node:fs/promises";
import { isAbsolute, join, relative, sep } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { FirmwareRequest } from "../domain/firmware/firmwareAnalysis.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { readBoundedFileBytes } from "../process/BoundedFileBytes.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";
import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";

/** One regular file or unpublished filesystem entry in a private extraction. */
export interface FirmwareEntry {
  readonly relativePath: string;
  readonly path: string;
  readonly size: number;
  readonly kind: "file" | "symlink" | "special";
  readonly linkTarget: string | null;
}

const throwIfFirmwareInventoryCancelled = (
  signal: AbortSignal | undefined,
  operation: string,
): void => {
  if (signal?.aborted === true) throw new AnalysisCancelledError(operation);
};

/** Retains a standalone caller's descriptor scope when cleanup cannot be confirmed. */
export class FirmwareFileCleanupError extends ProviderCleanupError {
  constructor(
    readonly resourceScope: ArtifactResourceScope,
    paths: string | readonly string[],
    operation: string,
    cause: unknown,
    primary?: unknown,
    providerId = "firmware",
  ) {
    super(
      providerId,
      [
        ...new Set([
          ...(typeof paths === "string" ? [paths] : paths),
          ...(primary instanceof AnalysisError ? primary.cleanupResources : []),
        ]),
      ],
      {
        reason: "Owned firmware descriptor could not be closed",
        ...(primary === undefined
          ? {}
          : {
              primary_error: jsonValueSchema.parse(
                primary instanceof AnalysisError
                  ? projectAnalysisError(primary)
                  : {
                      reason:
                        primary instanceof Error
                          ? primary.message
                          : String(primary),
                    },
              ),
            }),
      },
      {
        operation,
        cause:
          primary === undefined
            ? cause
            : new AggregateError(
                [primary, cause],
                "Firmware file operation failed and descriptor cleanup remains incomplete",
                { cause: primary },
              ),
      },
    );
    if (
      primary instanceof AnalysisError &&
      primary.capturedOutput !== undefined
    )
      this.retainCapturedOutput(primary.capturedOutput);
    if (
      primary instanceof AnalysisError &&
      primary.partialObservation !== undefined
    )
      this.retainPartialObservation(primary.partialObservation);
  }
}

/** Authoritative admission and one cleanup owner rule for one or multiple regular files. */
export const withFirmwareFiles = async <T>(
  paths: readonly string[],
  operation: string,
  signal: AbortSignal | undefined,
  scope: ArtifactResourceScope | undefined,
  use: (handles: readonly FileHandle[]) => Promise<T>,
  providerId = "firmware",
): Promise<T> => {
  const resources = scope ?? new ArtifactResourceScope();
  const owners: {
    kind: "file-handle";
    resource: string;
    handle: OwnedFileHandle;
  }[] = [];
  let primary: unknown;
  try {
    for (const path of paths) {
      try {
        const handle = await openRegularFile(path, {
          symlinks: "reject",
          signal,
        });
        owners.push({
          kind: "file-handle",
          resource: path,
          handle: new OwnedFileHandle(handle),
        });
      } catch (cause: unknown) {
        if (cause instanceof RegularFileAdmissionFailure) {
          owners.push({
            kind: "file-handle",
            resource: path,
            handle: cause.owner,
          });
          throw cause.cause;
        }
        throw cause;
      }
      signal?.throwIfAborted();
    }
    return await use(owners.map((owner) => owner.handle.handle));
  } catch (cause: unknown) {
    primary =
      cause instanceof AnalysisError
        ? cause
        : signal?.aborted
          ? new AnalysisCancelledError(operation, { cause })
          : cause;
    throw cause;
  } finally {
    const failures: { resource: string; cause: unknown }[] = [];
    for (const owner of owners) {
      const attempt = await resources.release(owner);
      if (attempt.kind === "failed")
        failures.push({ resource: owner.resource, cause: attempt.cause });
    }
    if (failures.length > 0)
      throw new FirmwareFileCleanupError(
        resources,
        failures.map((f) => f.resource),
        operation,
        new AggregateError(
          failures.map((f) => f.cause),
          "Firmware descriptors could not be closed",
        ),
        primary,
        providerId,
      );
  }
};

/** One-file consumers share the same acquisition, primary-error and cleanup boundary. */
export const withFirmwareFile = <T>(
  path: string,
  operation: string,
  signal: AbortSignal | undefined,
  scope: ArtifactResourceScope | undefined,
  use: (handle: FileHandle) => Promise<T>,
): Promise<T> =>
  withFirmwareFiles([path], operation, signal, scope, async ([handle]) => {
    if (handle === undefined)
      throw new Error("Missing acquired firmware descriptor");
    return use(handle);
  });

/** Hash a stable regular tool or extracted file without retaining its bytes in memory. */
export const hashFirmwareFile = async (
  path: string,
  signal?: AbortSignal,
  scope?: ArtifactResourceScope,
  operation = "firmware_file_identity",
): Promise<string> =>
  withFirmwareFile(path, operation, signal, scope, async (handle) => {
    const initial = await handle.stat({ bigint: true });
    const hash = createHash("sha256");
    // Aborting a FileHandle stream can close its FD even with autoClose false.
    // Await reads on the admitted handle so its scoped owner alone closes it.
    const buffer = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      signal?.throwIfAborted();
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      signal?.throwIfAborted();
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
    signal?.throwIfAborted();
    if (!sameRegularFileState(initial, await handle.stat({ bigint: true })))
      throw new AnalysisOutputError(
        operation,
        `File changed while being identified: ${path}`,
      );
    return hash.digest("hex");
  });

/** Copy and identify the exact bytes consumed by firmware providers. */
export const snapshotFirmware = async (
  request: FirmwareRequest,
  root: string,
  signal: AbortSignal,
) => {
  const sourcePath = absoluteCallerPath(request.input.path);
  const source = await realpath(sourcePath);
  const handle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW);
  const fullPath = join(root, "firmware.bin");
  const hash = createHash("sha256");
  let size = 0;
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile() ||
      stat.size === 0 ||
      stat.size > FIRMWARE_LIMITS.inputBytes
    )
      throw new AnalysisInputError(request.operation, undefined, [
        {
          path: ["path"],
          reason: "out_of_range",
          message: `Firmware must be a nonempty regular file no larger than ${FIRMWARE_LIMITS.inputBytes} bytes`,
        },
      ]);
    const meter = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        size += chunk.length;
        if (size > FIRMWARE_LIMITS.inputBytes) {
          callback(new Error("Firmware grew beyond the input byte budget"));
          return;
        }
        hash.update(chunk);
        callback(null, chunk);
      },
    });
    await pipeline(
      handle.createReadStream({ autoClose: false }),
      meter,
      createWriteStream(fullPath, { flags: "wx", mode: 0o600 }),
      { signal },
    );
  } finally {
    await handle.close();
  }
  await chmod(fullPath, 0o400);
  const sha256 = hash.digest("hex");
  const selected =
    request.operation === "extract_firmware" ? request.input.range : undefined;
  const offset = selected?.offset ?? 0;
  const length = selected?.length ?? size;
  if (length === 0 || offset > size || length > size - offset)
    throw new AnalysisInputError(request.operation, undefined, [
      {
        path: ["range"],
        reason: "out_of_range",
        message: `Selected range must be within the ${size}-byte firmware file`,
      },
    ]);
  let inputPath = fullPath;
  if (selected !== undefined) {
    inputPath = join(root, "selected.bin");
    await pipeline(
      createReadStream(fullPath, { start: offset, end: offset + length - 1 }),
      createWriteStream(inputPath, { flags: "wx", mode: 0o600 }),
      { signal },
    );
    await chmod(inputPath, 0o400);
  }
  return {
    subject: { path: sourcePath, sha256, format: "file" as const },
    size,
    inputPath,
    selection: {
      offset,
      length,
      sha256:
        selected === undefined
          ? sha256
          : await hashFirmwareFile(inputPath, signal),
    },
  };
};

/** Read a complete bounded report; oversized data is never reported as complete. */
export const readFirmwareReport = async (
  path: string,
  operation: string,
): Promise<unknown> => {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    if (!(await handle.stat()).isFile())
      throw new AnalysisOutputError(operation, "Report is not a regular file");
    const bytes = await readBoundedFileBytes(
      handle,
      FIRMWARE_LIMITS.reportBytes,
    );
    if (bytes === undefined)
      throw new AnalysisOutputError(
        operation,
        `Report exceeded ${FIRMWARE_LIMITS.reportBytes} bytes`,
      );
    try {
      const value: unknown = JSON.parse(
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          bytes,
        ),
      );
      return value;
    } catch (cause: unknown) {
      throw new AnalysisOutputError(
        operation,
        "Tool report is not valid complete JSON",
        { cause },
      );
    }
  } finally {
    await handle.close();
  }
};

/** Inventory private output without following links, enforcing aggregate staging budgets. */
export const inventoryFirmwareOutput = async (
  root: string,
  maxBytes: number,
  maxEntries: number,
  operation: string,
  signal?: AbortSignal,
): Promise<FirmwareEntry[]> => {
  const entries: FirmwareEntry[] = [];
  const pending = [root];
  let bytes = 0;
  let count = 0;
  while (pending.length > 0) {
    throwIfFirmwareInventoryCancelled(signal, operation);
    const directory = pending.pop();
    if (directory === undefined) break;
    const directoryStat = await lstat(directory).catch((cause: unknown) => {
      if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
        return undefined;
      throw cause;
    });
    if (
      directoryStat === undefined ||
      !directoryStat.isDirectory() ||
      directoryStat.isSymbolicLink()
    )
      continue;
    const handle = await opendir(directory).catch((cause: unknown) => {
      if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
        return undefined;
      throw cause;
    });
    if (handle === undefined) continue;
    const names: string[] = [];
    for await (const entry of handle) {
      throwIfFirmwareInventoryCancelled(signal, operation);
      count++;
      if (count > maxEntries)
        throw new AnalysisOutputError(
          operation,
          `Staging entry budget exceeded (${maxEntries})`,
        );
      names.push(entry.name);
    }
    for (const name of names.sort()) {
      const path = join(directory, name);
      const stat = await lstat(path).catch((cause: unknown) => {
        if (
          cause instanceof Error &&
          "code" in cause &&
          cause.code === "ENOENT"
        )
          return undefined;
        throw cause;
      });
      if (stat === undefined) continue;
      if (stat.isDirectory()) {
        pending.push(path);
        continue;
      }
      if (stat.isFile()) bytes += stat.size;
      if (bytes > maxBytes)
        throw new AnalysisOutputError(
          operation,
          `Staging byte budget exceeded (${maxBytes})`,
        );
      entries.push({
        path,
        relativePath: relative(root, path).split(sep).join("/"),
        size: stat.size,
        kind: stat.isSymbolicLink()
          ? "symlink"
          : stat.isFile()
            ? "file"
            : "special",
        linkTarget: stat.isSymbolicLink() ? await readlink(path) : null,
      });
    }
  }
  return entries.sort((a, b) =>
    compareUnicodeCodePoints(a.relativePath, b.relativePath),
  );
};

/** Bind producer paths to the selected input or private extraction tree. */
export const firmwareLogicalPath = (
  path: string,
  inputPath: string,
  outputRoot: string,
): string => {
  if (path === inputPath) return "$input";
  const rel = relative(outputRoot, path);
  if (
    !isAbsolute(path) ||
    rel === ".." ||
    rel.startsWith(`..${sep}`) ||
    isAbsolute(rel)
  )
    throw new AnalysisOutputError(
      "extract_firmware",
      `Provider reported a path outside its owned output: ${path}`,
    );
  return rel === "" ? "$output" : `$output/${rel.split(sep).join("/")}`;
};
