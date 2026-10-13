import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, opendir, realpath } from "node:fs/promises";
import { basename, join, relative, sep } from "node:path";
import type { z } from "zod";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { firmwareTrustedPluginsSchema } from "../domain/firmware/firmwareAnalysis.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { OwnedDirectoryHandle } from "../filesystem/OwnedDirectoryHandle.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { sameRegularFileState } from "../filesystem/RegularFile.js";
import {
  FirmwareFileCleanupError,
  identifyFirmwareFile,
  withFirmwareFile,
} from "./FirmwareFiles.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";

type PluginIdentity = z.infer<typeof firmwareTrustedPluginsSchema>;

/** Copy an admitted trusted selection into its own read-only mount, without importing it. */
export const stageUnblobContainerPlugins = async (
  baseline: PluginIdentity,
  stage: string,
  operation: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
) => {
  signal.throwIfAborted();
  // The invocation workspace owns this fresh subtree, including incomplete copies.
  await mkdir(stage, { mode: 0o700 });
  const files: PluginIdentity["files"] = [];
  const directories: string[] = [];
  const expected = new Map(
    baseline.files.map((file) => [file.relative_path, file]),
  );
  let manifestBytes = 0;
  let copiedBytes = 0;
  const changed = (reason: string): never => {
    throw new AnalysisOutputError(
      operation,
      `Trusted plugin staging identity changed: ${reason}`,
    );
  };
  const copy = async (source: string, name: string) => {
    signal.throwIfAborted();
    const admitted = expected.get(name);
    if (admitted === undefined) changed(`Unfingerprinted file ${name}`);
    const destination = join(stage, name);
    await withFirmwareFile(source, operation, signal, scope, async (input) => {
      const before = await input.stat({ bigint: true });
      if (
        Number(before.size) !== admitted!.size ||
        (await realpath(source)) !== source
      )
        changed(`Source generation or canonical path ${name}`);
      signal.throwIfAborted();
      const output = await open(
        destination,
        constants.O_RDWR |
          constants.O_CREAT |
          constants.O_EXCL |
          constants.O_NOFOLLOW |
          constants.O_NONBLOCK,
        0o400,
      );
      const owner = {
        kind: "file-handle" as const,
        resource: destination,
        handle: new OwnedFileHandle(output),
      };
      let primary: unknown;
      try {
        const buffer = Buffer.allocUnsafe(64 * 1024);
        const hash = createHash("sha256");
        let size = 0;
        for (;;) {
          signal.throwIfAborted();
          const { bytesRead } = await input.read(
            buffer,
            0,
            buffer.length,
            null,
          );
          signal.throwIfAborted();
          if (bytesRead === 0) break;
          size += bytesRead;
          if (size > admitted!.size)
            changed(`Source grew beyond its admitted extent ${name}`);
          hash.update(buffer.subarray(0, bytesRead));
          let position = 0;
          while (position < bytesRead) {
            signal.throwIfAborted();
            const { bytesWritten } = await output.write(
              buffer,
              position,
              bytesRead - position,
              null,
            );
            signal.throwIfAborted();
            if (bytesWritten === 0)
              throw new AnalysisOutputError(
                operation,
                "Plugin staging write made no progress",
              );
            position += bytesWritten;
          }
        }
        if (
          size !== admitted!.size ||
          hash.digest("hex") !== admitted!.sha256 ||
          !sameRegularFileState(before, await input.stat({ bigint: true }))
        )
          changed(`Source fingerprint or generation ${name}`);
        const readback = await identifyFirmwareFile(
          destination,
          signal,
          scope,
          operation,
        );
        if (
          readback.size !== admitted!.size ||
          readback.sha256 !== admitted!.sha256
        )
          changed(`Private copy readback fingerprint ${name}`);
        files.push({ relative_path: name, ...readback });
        copiedBytes += size;
        if (!Number.isSafeInteger(copiedBytes))
          throw new AnalysisOutputError(
            operation,
            "Plugin copied-byte accounting exceeds the exact integer representation",
          );
      } catch (cause: unknown) {
        primary =
          cause instanceof AnalysisError
            ? cause
            : signal.aborted
              ? new AnalysisCancelledError(operation, { cause })
              : cause;
        throw primary;
      } finally {
        const released = await scope.release(owner);
        if (released.kind === "failed")
          throw new FirmwareFileCleanupError(
            scope,
            destination,
            operation,
            released.cause,
            primary,
            "unblob",
          );
      }
    });
  };
  if (baseline.kind === "file")
    await copy(baseline.resolved_path, basename(baseline.resolved_path));
  else {
    const pending = [baseline.resolved_path];
    while (pending.length > 0) {
      signal.throwIfAborted();
      const directory = pending.pop()!;
      const state = await lstat(directory);
      if (!state.isDirectory() || (await realpath(directory)) !== directory)
        changed(`Directory generation or canonical path ${directory}`);
      const handle = await opendir(directory);
      const owner = {
        kind: "directory-handle" as const,
        resource: directory,
        handle: new OwnedDirectoryHandle(handle),
      };
      let primary: unknown;
      try {
        for (;;) {
          signal.throwIfAborted();
          const item = await handle.read();
          signal.throwIfAborted();
          if (item === null) break;
          const source = join(directory, item.name);
          const name = relative(baseline.resolved_path, source)
            .split(sep)
            .join("/");
          manifestBytes += Buffer.byteLength(JSON.stringify(name), "utf8") + 1;
          if (manifestBytes > FIRMWARE_LIMITS.reportBytes)
            throw new AnalysisOutputError(
              operation,
              "Plugin staging entry manifest exceeds the report budget",
            );
          const state = await lstat(source);
          if (state.isDirectory()) {
            await mkdir(join(stage, name), { mode: 0o700 });
            directories.push(name);
            pending.push(source);
          } else if (state.isFile()) await copy(source, name);
          else
            throw new AnalysisOutputError(
              operation,
              "Trusted plugin tree contains a link or special file during staging",
            );
        }
      } catch (cause: unknown) {
        primary =
          cause instanceof AnalysisError
            ? cause
            : signal.aborted
              ? new AnalysisCancelledError(operation, { cause })
              : cause;
        throw primary;
      } finally {
        const released = await scope.release(owner);
        if (released.kind === "failed")
          throw new FirmwareFileCleanupError(
            scope,
            directory,
            operation,
            released.cause,
            primary,
            "unblob",
          );
      }
    }
  }
  if (files.length !== baseline.files.length)
    changed("Fingerprint files were removed during staging");
  files.sort((a, b) =>
    a.relative_path < b.relative_path
      ? -1
      : a.relative_path > b.relative_path
        ? 1
        : 0,
  );
  directories.sort();
  // Host directories stay removable by the workspace owner. The admitted
  // container bind is read-only; this subtree is never beneath its RW work mount.
  signal.throwIfAborted();
  return {
    host_path: stage,
    kind: baseline.kind === "file" ? ("file" as const) : ("directory" as const),
    basename:
      baseline.kind === "file" ? basename(baseline.resolved_path) : null,
    namespace_path:
      baseline.kind === "file"
        ? `/rea-plugins/${basename(baseline.resolved_path)}`
        : "/rea-plugins",
    source_path: baseline.selected_path,
    source_identity_sha256: baseline.identity_sha256,
    files,
    directories,
    copied_bytes: copiedBytes,
    files_sha256: createHash("sha256")
      .update(JSON.stringify(files))
      .digest("hex"),
  };
};
