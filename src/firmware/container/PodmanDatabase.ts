import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, open, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import {
  runFirmwareCommand,
  type FirmwareLauncher,
} from "../FirmwareCommand.js";
import { launchPodmanDirectClient } from "./PodmanClientCleanup.js";
import { z } from "zod";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { withArtifactRegularFile } from "../../artifacts/ArtifactFileOperation.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { sameRegularFileState } from "../../filesystem/RegularFile.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import {
  identifyPodmanProfileFile,
  observePodmanProfileFile,
  podmanPermissionMode,
  podmanProfileUnavailable,
} from "./PodmanProfileFiles.js";
import type {
  PodmanDescriptorIdentity,
  PodmanExistingStoreProfile,
} from "./PodmanStoreProfile.js";

/** Private staging resource budget, not a maximum imposed by the SQLite format. */
export const PODMAN_DATABASE_SNAPSHOT_BYTES = 128 * 1024 * 1024;
const configurationSchema = z.strictObject({
  ID: z.strictObject({ integer: z.literal("1") }).transform(() => 1 as const),
  SchemaVersion: z
    .strictObject({ integer: z.literal("1") })
    .transform(() => 1 as const),
  OS: z.literal("linux"),
  StaticDir: z.string(),
  TmpDir: z.string(),
  GraphRoot: z.string(),
  RunRoot: z.string(),
  GraphDriver: z.literal("overlay"),
  VolumeDir: z.string(),
});
const noSidecars = async (path: string, signal: AbortSignal) => {
  for (const suffix of ["-journal", "-wal", "-shm"]) {
    signal.throwIfAborted();
    const present = await lstat(`${path}${suffix}`).catch((cause: unknown) => {
      if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
        return undefined;
      throw cause;
    });
    if (present !== undefined)
      throw podmanProfileUnavailable(
        "This bootstrap profile requires a quiescent SQLite store without journal/WAL/SHM sidecars; transaction applicability is unknown and no migration is authorized",
      );
  }
};

/** Fixed read-only schema1 DBConfig interpretation from an authoritative private snapshot only. */
export const observePodmanDatabase = async (
  selected: PodmanExistingStoreProfile,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
  launcher: FirmwareLauncher = launchPodmanDirectClient,
) => {
  const root = await PrivateRuntimeRoot.create({
    prefix: "rea-podman-db-admission-",
  });
  const pending = new Set<ProviderProcessSupervisor>();
  let snapshotOutput: OwnedFileHandle | undefined;
  let observed:
    | {
        source: PodmanDescriptorIdentity;
        configuration: z.output<typeof configurationSchema>;
        semantics: string;
      }
    | undefined;
  let primary: unknown;
  const owner = {
    kind: "private-runtime-root" as const,
    resource: root.path,
    root: {
      path: root.path,
      close: async () => {
        for (const process of [...pending]) {
          const stopped = await process.stop();
          if (stopped.status !== "incomplete") pending.delete(process);
        }
        if (pending.size > 0)
          throw Error("Snapshot parser cleanup remains pending");
        // A failed output close keeps the exact private snapshot workspace owned.
        await snapshotOutput?.close();
        await root.close();
      },
    },
  };
  try {
    signal.throwIfAborted();
    const path = selected.database.path;
    const snapshot = join(root.path, "db.sql");
    const source = await withArtifactRegularFile(
      path,
      scope,
      signal,
      async (handle) => {
        const before = await handle.stat({ bigint: true });
        if (
          (await realpath(path)) !== path ||
          before.size === 0n ||
          before.size > BigInt(PODMAN_DATABASE_SNAPSHOT_BYTES)
        )
          throw podmanProfileUnavailable(
            `Existing database exceeds the ${PODMAN_DATABASE_SNAPSHOT_BYTES}-byte private staging resource budget or is not a canonical nonempty regular file`,
          );
        await noSidecars(path, signal);
        const hash = createHash("sha256");
        let size = 0;
        const output = await open(
          snapshot,
          constants.O_WRONLY |
            constants.O_CREAT |
            constants.O_EXCL |
            constants.O_NOFOLLOW |
            constants.O_NONBLOCK,
          0o600,
        );
        snapshotOutput = new OwnedFileHandle(output);
        const outputOwner = {
          kind: "file-handle" as const,
          resource: snapshot,
          handle: snapshotOutput,
        };
        let copyFailure: unknown;
        try {
          const buffer = Buffer.allocUnsafe(64 * 1024);
          for (;;) {
            signal.throwIfAborted();
            const { bytesRead } = await handle.read(
              buffer,
              0,
              buffer.length,
              null,
            );
            signal.throwIfAborted();
            if (bytesRead === 0) break;
            if (bytesRead > PODMAN_DATABASE_SNAPSHOT_BYTES - size)
              throw podmanProfileUnavailable(
                "Database grew beyond the bounded private snapshot resource budget",
              );
            let written = 0;
            while (written < bytesRead) {
              signal.throwIfAborted();
              const { bytesWritten } = await output.write(
                buffer,
                written,
                bytesRead - written,
                null,
              );
              signal.throwIfAborted();
              if (bytesWritten === 0)
                throw Error("Private database snapshot write made no progress");
              written += bytesWritten;
            }
            hash.update(buffer.subarray(0, bytesRead));
            size += bytesRead;
          }
        } catch (cause: unknown) {
          copyFailure =
            cause instanceof AnalysisError
              ? cause
              : signal.aborted
                ? new AnalysisCancelledError("firmware_container_runtime", {
                    cause,
                  })
                : cause;
          throw copyFailure;
        } finally {
          const closed = await scope.release(outputOwner);
          if (closed.kind === "failed")
            throw new ProviderCleanupError(
              "podman",
              [snapshot],
              {
                reason: "Private database snapshot cleanup remains pending",
                ...(copyFailure instanceof AnalysisError
                  ? { primary_error: projectAnalysisError(copyFailure) }
                  : {}),
              },
              {
                operation: "firmware_container_runtime",
                cause:
                  copyFailure === undefined
                    ? closed.cause
                    : new AggregateError([copyFailure, closed.cause]),
              },
            );
        }
        await noSidecars(path, signal);
        const current = await lstat(path, { bigint: true });
        if (
          !sameRegularFileState(before, await handle.stat({ bigint: true })) ||
          !sameRegularFileState(before, current) ||
          size !== Number(before.size)
        )
          throw podmanProfileUnavailable(
            "Database generation changed while admitted; initialized compatibility remains unknown",
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
        } satisfies PodmanDescriptorIdentity;
      },
    );
    await chmod(snapshot, 0o400);
    signal.throwIfAborted();
    const helper = await observePodmanProfileFile(
      fileURLToPath(
        new URL(
          "../../../bridge/firmware/podman_db_config.mjs",
          import.meta.url,
        ),
      ),
      1024 * 1024,
      signal,
      scope,
    );
    const helperPath = join(root.path, "podman_db_config.mjs");
    await writeFile(helperPath, helper.bytes, { flag: "wx", mode: 0o400 });
    const stagedHelper = await identifyPodmanProfileFile(
      helperPath,
      signal,
      scope,
    );
    if (stagedHelper.sha256 !== helper.identity.sha256)
      throw podmanProfileUnavailable(
        "Private database parser differs from the shipped helper",
      );
    const snapshotIdentity = await identifyPodmanProfileFile(
      snapshot,
      signal,
      scope,
    );
    if (
      snapshotIdentity.sha256 !== source.sha256 ||
      snapshotIdentity.size !== source.size
    )
      throw podmanProfileUnavailable(
        "Private database snapshot differs from the acquired source",
      );
    const result = await runFirmwareCommand({
      engine: "podman",
      operation: "firmware_container_runtime",
      command: process.execPath,
      limiter: "/usr/bin/prlimit",
      args: [
        "--max-old-space-size=64",
        helperPath,
        snapshot,
        source.sha256,
        String(source.size),
      ],
      cwd: root.path,
      environment: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      signal,
      launcher,
      limitProfile: "container-transport",
      retainCleanup: (owner) => pending.add(owner),
    });
    let config: z.output<typeof configurationSchema>;
    try {
      if (result.stdout.invalidUtf8 === true)
        throw Error("Snapshot parser output is not valid UTF-8");
      const parsed = z
        .strictObject({
          snapshot_sha256: z.literal(source.sha256),
          tables: z
            .array(
              z.strictObject({
                type: z.literal("table"),
                sql: z
                  .string()
                  .regex(
                    /^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`]?DBConfig\b/iu,
                  ),
              }),
            )
            .length(1),
          configuration: z.array(configurationSchema).length(1),
        })
        .parse(JSON.parse(result.stdout.text));
      config = parsed.configuration[0]!;
      const after = await identifyPodmanProfileFile(snapshot, signal, scope);
      if (
        after.sha256 !== source.sha256 ||
        after.size !== source.size ||
        after.inode !== snapshotIdentity.inode ||
        after.device !== snapshotIdentity.device
      )
        throw Error("Consumed snapshot identity changed");
    } catch (cause: unknown) {
      if (cause instanceof AnalysisError) throw cause;
      throw podmanProfileUnavailable(
        `Initialized DBConfig interpretation is unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
      ).retainCapturedOutput(result.captured_output);
    }
    if (
      config.StaticDir !== selected.static_dir ||
      config.TmpDir !== selected.tmp_dir ||
      config.GraphRoot !== selected.graph_root ||
      config.RunRoot !== selected.run_root ||
      config.VolumeDir !== selected.volume_path
    )
      throw podmanProfileUnavailable(
        "Existing DBConfig roots differ from the complete selected SQLite profile",
      );
    signal.throwIfAborted();
    observed = {
      source,
      configuration: config,
      semantics:
        "observed quiescent SQLite schema1 DBConfig; installed source attestation remains unknown" as const,
    };
    return observed;
  } catch (cause: unknown) {
    if (cause instanceof ProviderAdapterError && !cause.cleanupIncomplete) {
      primary = podmanProfileUnavailable(
        `Initialized database helper failed; database compatibility remains unknown: ${cause.message}`,
      );
      if (cause.capturedOutput !== undefined)
        (primary as AnalysisError).retainCapturedOutput(cause.capturedOutput);
    } else
      primary =
        cause instanceof AnalysisError
          ? cause
          : signal.aborted
            ? new AnalysisCancelledError("firmware_container_runtime", {
                cause,
              })
            : podmanProfileUnavailable(
                `Initialized database compatibility is unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
              );
    throw primary;
  } finally {
    const released = await scope.release(owner);
    if (released.kind === "failed") {
      const failure = new ProviderCleanupError(
        "podman",
        [root.path],
        {
          reason:
            "Private read-only database admission cleanup remains pending",
          observed_database: observed ?? null,
          ...(primary instanceof AnalysisError
            ? { primary_error: projectAnalysisError(primary) }
            : {}),
        },
        {
          operation: "firmware_container_runtime",
          cause: new AggregateError([primary, released.cause]),
        },
      );
      if (
        primary instanceof AnalysisError &&
        primary.capturedOutput !== undefined
      )
        failure.retainCapturedOutput(primary.capturedOutput);
      throw failure;
    }
  }
};
