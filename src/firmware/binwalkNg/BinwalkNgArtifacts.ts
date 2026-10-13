import { createHash } from "node:crypto";
import { sameRegularFileState } from "../../filesystem/RegularFile.js";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { basename, join } from "node:path";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../../artifacts/SafeOutputTreeCreationFailure.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { readPngHeaderDimensions } from "../../domain/pngHeader.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import {
  hashFirmwareFile,
  withFirmwareFile,
  type FirmwareEntry,
} from "../FirmwareFiles.js";
import { FIRMWARE_LIMITS } from "../FirmwareRelease.js";

/** Close every acquired descriptor, retaining failed owners instead of losing them. */
const withFiles = async <T>(
  scope: ArtifactResourceScope,
  paths: readonly string[],
  operation: string,
  signal: AbortSignal,
  use: (handles: readonly OwnedFileHandle[]) => Promise<T>,
): Promise<T> => {
  const owners: {
    kind: "file-handle";
    resource: string;
    handle: OwnedFileHandle;
  }[] = [];
  try {
    for (const path of paths) {
      signal.throwIfAborted();
      const handle = new OwnedFileHandle(
        await open(
          path,
          constants.O_RDONLY |
            constants.O_NOFOLLOW |
            constants.O_NONBLOCK |
            constants.O_NOCTTY,
        ),
      );
      owners.push({ kind: "file-handle", resource: path, handle });
      signal.throwIfAborted();
      if (!(await handle.handle.stat()).isFile())
        throw new AnalysisOutputError(operation, `Not a regular file: ${path}`);
    }
    return await use(owners.map((owner) => owner.handle));
  } finally {
    const failed: string[] = [];
    for (const owner of owners)
      if ((await scope.release(owner)).kind === "failed")
        failed.push(owner.resource);
    if (failed.length > 0)
      throw new ProviderCleanupError(
        "binwalk-ng",
        failed,
        { reason: "Owned artifact descriptors could not be closed" },
        { operation },
      );
  }
};

/** A filename is only a candidate: exact source bytes must establish correspondence. */
export interface BinwalkNgCarvingObservation {
  readonly sha256: string;
  readonly local_range: { offset: number; length: number };
  readonly original_file_range: { offset: number; length: number } | null;
}
export const verifyBinwalkNgCarving = async (context: {
  entry: FirmwareEntry;
  inputPath: string;
  inputSize: number;
  rootOffset: number | null;
  scope: ArtifactResourceScope;
  signal: AbortSignal;
  operation: string;
  observe?: (proof: BinwalkNgCarvingObservation) => void;
}) => {
  const prefix = `${basename(context.inputPath)}_`;
  const name = basename(context.entry.path);
  const suffix = name.startsWith(prefix) ? name.slice(prefix.length) : "";
  const matched = /^(0|[1-9][0-9]*)_.+\.raw$/u.exec(suffix);
  const offset = matched === null ? NaN : Number(matched[1]);
  if (
    context.entry.kind !== "file" ||
    context.entry.size === 0 ||
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    context.entry.size > context.inputSize - offset
  )
    return null;
  return withFiles(
    context.scope,
    [context.inputPath, context.entry.path],
    context.operation,
    context.signal,
    async ([source, candidate]) => {
      if (source === undefined || candidate === undefined)
        throw new Error("Missing acquired comparison descriptors");
      const sourceInitial = await source.handle.stat({ bigint: true }),
        candidateInitial = await candidate.handle.stat({ bigint: true });
      if (
        sourceInitial.size !== BigInt(context.inputSize) ||
        candidateInitial.size !== BigInt(context.entry.size)
      )
        return null;
      const hash = createHash("sha256");
      const a = Buffer.alloc(64 * 1024),
        b = Buffer.alloc(64 * 1024);
      let position = 0;
      while (position < context.entry.size) {
        context.signal.throwIfAborted();
        const length = Math.min(a.length, context.entry.size - position);
        const [left, right] = await Promise.all([
          source.handle.read(a, 0, length, offset + position),
          candidate.handle.read(b, 0, length, position),
        ]);
        if (
          left.bytesRead !== length ||
          right.bytesRead !== length ||
          !a.subarray(0, length).equals(b.subarray(0, length))
        )
          return null;
        hash.update(b.subarray(0, length));
        position += length;
      }
      context.signal.throwIfAborted();
      if (
        !sameRegularFileState(
          sourceInitial,
          await source.handle.stat({ bigint: true }),
        ) ||
        !sameRegularFileState(
          candidateInitial,
          await candidate.handle.stat({ bigint: true }),
        )
      )
        return null;
      const proof: BinwalkNgCarvingObservation = {
        sha256: hash.digest("hex"),
        local_range: { offset, length: context.entry.size },
        original_file_range:
          context.rootOffset === null
            ? null
            : {
                offset: context.rootOffset + offset,
                length: context.entry.size,
              },
      };
      context.observe?.(proof);
      return proof;
    },
  );
};

export interface BinwalkNgPngObservation {
  readonly width: number;
  readonly height: number;
  readonly size: number;
  readonly sha256: string;
  readonly validation: "png_header";
  path: string | null;
  publication_state: "unpublished" | "published";
}

/** Verify the native plot's actual bounded header and retain its independent digest. */
export const inspectBinwalkNgPng = async (
  path: string,
  scope: ArtifactResourceScope,
  signal: AbortSignal,
  operation: string,
  observe?: (png: BinwalkNgPngObservation) => void,
): Promise<BinwalkNgPngObservation> => {
  return withFiles(scope, [path], operation, signal, async ([owner]) => {
    if (owner === undefined) throw new Error("Missing acquired PNG descriptor");
    const initial = await owner.handle.stat({ bigint: true });
    const size = Number(initial.size);
    if (size < 24 || size > FIRMWARE_LIMITS.reportBytes)
      throw new AnalysisOutputError(
        operation,
        "Native PNG is absent or exceeds the private plot byte budget",
      );
    const bytes = Buffer.alloc(24);
    const read = await owner.handle.read(bytes, 0, bytes.length, 0);
    if (read.bytesRead !== bytes.length)
      throw new AnalysisOutputError(
        operation,
        "Native PNG header is incomplete",
      );
    const dimensions = readPngHeaderDimensions(bytes);
    if (dimensions?.width !== 2048 || dimensions.height !== 1024)
      throw new AnalysisOutputError(
        operation,
        "Native PNG header does not match the 2048x1024 source profile",
      );
    const hash = createHash("sha256");
    for await (const chunk of owner.handle.createReadStream({
      autoClose: false,
      start: 0,
      signal,
    })) {
      signal.throwIfAborted();
      hash.update(chunk);
    }
    if (
      !sameRegularFileState(initial, await owner.handle.stat({ bigint: true }))
    )
      throw new AnalysisOutputError(
        operation,
        "Private PNG changed during inspection",
      );
    const png: BinwalkNgPngObservation = {
      ...dimensions,
      size,
      sha256: hash.digest("hex"),
      validation: "png_header",
      path: null,
      publication_state: "unpublished",
    };
    observe?.(png);
    return png;
  });
};

/** Fresh, verified regular-file publication; nonregular entries remain metadata. */
export const publishBinwalkNgFiles = async (context: {
  outputDirectory: string;
  entries: readonly FirmwareEntry[];
  signal: AbortSignal;
  operation: string;
  scope?: ArtifactResourceScope;
  expectedIdentities?: ReadonlyMap<string, string> | undefined;
  ownTree(tree: SafeOutputTree): void;
  releaseTree(): void;
}) => {
  let tree: SafeOutputTree | undefined;
  const files: {
    relative_path: string;
    path: string;
    size: number;
    sha256: string;
  }[] = [];
  const unpublished: {
    relative_path: string;
    kind: "symlink" | "special";
    link_target: string | null;
  }[] = [];
  let prepared:
    | {
        output_directory: string;
        files: typeof files;
        unpublished_entries: typeof unpublished;
        published_bytes: number;
      }
    | undefined;
  try {
    tree = await SafeOutputTree.create(context.outputDirectory);
    context.ownTree(tree);
    for (const entry of context.entries) {
      context.signal.throwIfAborted();
      if (entry.kind !== "file") {
        unpublished.push({
          relative_path: entry.relativePath,
          kind: entry.kind,
          link_target: entry.linkTarget,
        });
        continue;
      }
      const sha256 = await hashFirmwareFile(
        entry.path,
        context.signal,
        context.scope,
        context.operation,
      );
      const expected = context.expectedIdentities?.get(entry.relativePath);
      if (expected !== undefined && expected !== sha256)
        throw new AnalysisOutputError(
          context.operation,
          `Artifact changed after independent inspection: ${entry.relativePath}`,
        );
      const outputTree = tree;
      await withFirmwareFile(
        entry.path,
        context.operation,
        context.signal,
        context.scope,
        async (handle) =>
          outputTree.write(
            entry.relativePath,
            handle.createReadStream({
              autoClose: false,
              signal: context.signal,
            }),
            { sha256, bytes: entry.size },
            context.signal,
          ),
      );
      files.push({
        relative_path: entry.relativePath,
        path: join(tree.outputRoot, entry.relativePath),
        size: entry.size,
        sha256,
      });
    }
    context.signal.throwIfAborted();
    prepared = {
      output_directory: tree.outputRoot,
      files,
      unpublished_entries: unpublished,
      published_bytes: files.reduce((sum, file) => sum + file.size, 0),
    };
    await tree.commit();
    context.releaseTree();
    return prepared;
  } catch (cause: unknown) {
    if (cause instanceof SafeOutputTreeCreationFailure) {
      tree = cause.tree;
      context.ownTree(tree);
    }
    try {
      await tree?.rollback();
      context.releaseTree();
    } catch (cleanupCause: unknown) {
      throw new ProviderCleanupError(
        "binwalk-ng",
        [context.outputDirectory],
        {
          reason:
            cleanupCause instanceof Error
              ? cleanupCause.message
              : String(cleanupCause),
          previous_error:
            cause instanceof Error ? cause.message : String(cause),
        },
        {
          operation: context.operation,
          cause: cleanupCause,
          ...(tree?.published === true && prepared !== undefined
            ? {
                partialObservation: {
                  kind: "firmware",
                  result: jsonValueSchema.parse(prepared),
                },
              }
            : {}),
        },
      );
    }
    if (tree?.published === true && prepared !== undefined) return prepared;
    throw cause;
  }
};
