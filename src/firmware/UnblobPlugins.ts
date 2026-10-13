import { createHash } from "node:crypto";
import { lstat, opendir, realpath } from "node:fs/promises";
import { basename, join, relative, sep } from "node:path";
import type { z } from "zod";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { OwnedDirectoryHandle } from "../filesystem/OwnedDirectoryHandle.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import { firmwareTrustedPluginsSchema } from "../domain/firmware/firmwareAnalysis.js";
import {
  FirmwareFileCleanupError,
  identifyFirmwareFile,
} from "./FirmwareFiles.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";

type PluginIdentity = z.infer<typeof firmwareTrustedPluginsSchema>;
/** Identify caller-selected trusted code/data without importing it or attesting isolation. */
export const fingerprintUnblobPlugins = async (
  selected: string,
  operation: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
): Promise<PluginIdentity> => {
  signal.throwIfAborted();
  const resolved = await realpath(selected);
  const root = await lstat(resolved);
  if (!root.isDirectory() && !root.isFile())
    throw new AnalysisOutputError(
      operation,
      "Trusted plugin path is not a regular file or directory",
    );
  const files: PluginIdentity["files"] = [];
  // Retained manifest expansion is bounded by the existing report budget, not file sizes.
  let manifestBytes = 0;
  const add = async (path: string) => {
    signal.throwIfAborted();
    const state = await lstat(path);
    if (!state.isFile())
      throw new AnalysisOutputError(
        operation,
        `Trusted plugin tree contains a link or special file: ${path}`,
      );
    const relative_path = root.isFile()
      ? basename(resolved)
      : relative(resolved, path).split(sep).join("/");
    const row = {
      relative_path,
      ...(await identifyFirmwareFile(path, signal, scope, operation)),
    };
    manifestBytes += Buffer.byteLength(JSON.stringify(row), "utf8") + 1;
    if (manifestBytes > FIRMWARE_LIMITS.reportBytes)
      throw new AnalysisOutputError(
        operation,
        "Trusted plugin fingerprint manifest exceeded the report budget",
      );
    files.push(row);
  };
  if (root.isFile()) await add(resolved);
  else {
    const pending = [resolved];
    while (pending.length > 0) {
      signal.throwIfAborted();
      const directory = pending.pop();
      if (directory === undefined) break;
      const state = await lstat(directory);
      if (!state.isDirectory() || state.isSymbolicLink())
        throw new AnalysisOutputError(
          operation,
          "Trusted plugin directory identity changed during fingerprinting",
        );
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
          if (item === null) break;
          const path = join(directory, item.name);
          const state = await lstat(path);
          if (state.isDirectory()) {
            manifestBytes +=
              Buffer.byteLength(
                JSON.stringify(relative(resolved, path)),
                "utf8",
              ) + 1;
            if (manifestBytes > FIRMWARE_LIMITS.reportBytes)
              throw new AnalysisOutputError(
                operation,
                "Trusted plugin directory manifest exceeded the report budget",
              );
            pending.push(path);
          } else await add(path);
        }
      } catch (cause: unknown) {
        primary = cause;
        throw cause;
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
  files.sort((a, b) =>
    a.relative_path < b.relative_path
      ? -1
      : a.relative_path > b.relative_path
        ? 1
        : 0,
  );
  const identity = {
    selected_path: selected,
    resolved_path: resolved,
    kind: root.isFile() ? ("file" as const) : ("tree" as const),
    files,
  };
  return {
    ...identity,
    identity_sha256: createHash("sha256")
      .update(JSON.stringify(identity))
      .digest("hex"),
    // A baseline is one measurement, not a completed execution attribution.
    recheck: "unverified",
    attribution: "unknown",
  };
};

/** Rechecks are attribution observations; they cannot prevent a native import race. */
export const recheckUnblobPlugins = async (
  identity: PluginIdentity,
  operation: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
): Promise<PluginIdentity> => {
  try {
    const checked = await fingerprintUnblobPlugins(
      identity.selected_path,
      operation,
      signal,
      scope,
    );
    return checked.identity_sha256 === identity.identity_sha256
      ? identity.recheck === "changed"
        ? identity
        : {
            ...identity,
            recheck: "unchanged",
            attribution: "pre_and_post_fingerprint",
          }
      : { ...identity, recheck: "changed", attribution: "unknown" };
  } catch (cause: unknown) {
    if (
      signal.aborted ||
      (cause instanceof AnalysisError && cause.cleanupIncomplete)
    )
      throw cause;
    return { ...identity, recheck: "unverified", attribution: "unknown" };
  }
};
