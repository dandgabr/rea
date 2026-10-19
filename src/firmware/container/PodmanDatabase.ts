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
import {
  assertArtifactReadActive,
  ArtifactFileCleanupFailure,
  withArtifactFileHandle,
  withArtifactRegularFile,
} from "../../artifacts/ArtifactFileOperation.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  AnalysisCleanupLeaseGroup,
  type AnalysisCleanupLease,
} from "../../artifacts/AnalysisCleanupLease.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import { firmwareFailure } from "../FirmwareFailures.js";
import {
  AnalysisError,
  type AnalysisCapturedOutput,
} from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { sameRegularFileState } from "../../filesystem/RegularFile.js";
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
    assertArtifactReadActive(signal);
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
  let snapshotOutput: AnalysisCleanupLease | undefined;
  let observed:
    | {
        source: PodmanDescriptorIdentity;
        configuration: z.output<typeof configurationSchema>;
        semantics: string;
      }
    | undefined;
  let primary: AnalysisError | undefined;
  let capturedOutput: AnalysisCapturedOutput | undefined;
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
        await snapshotOutput?.release();
        await root.close();
      },
    },
  };
  try {
    assertArtifactReadActive(signal);
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
        try {
          await withArtifactFileHandle(
            snapshot,
            output,
            scope,
            signal,
            async () => {
              const buffer = Buffer.allocUnsafe(64 * 1024);
              for (;;) {
                assertArtifactReadActive(signal);
                const { bytesRead } = await handle.read(
                  buffer,
                  0,
                  buffer.length,
                  null,
                );
                assertArtifactReadActive(signal);
                if (bytesRead === 0) break;
                if (bytesRead > PODMAN_DATABASE_SNAPSHOT_BYTES - size)
                  throw podmanProfileUnavailable(
                    "Database grew beyond the bounded private snapshot resource budget",
                  );
                let written = 0;
                while (written < bytesRead) {
                  assertArtifactReadActive(signal);
                  const { bytesWritten } = await output.write(
                    buffer,
                    written,
                    bytesRead - written,
                    null,
                  );
                  assertArtifactReadActive(signal);
                  if (bytesWritten === 0)
                    throw Error(
                      "Private database snapshot write made no progress",
                    );
                  written += bytesWritten;
                }
                hash.update(buffer.subarray(0, bytesRead));
                size += bytesRead;
              }
            },
          );
        } catch (cause: unknown) {
          if (cause instanceof ArtifactFileCleanupFailure)
            snapshotOutput = cause.cleanupLease;
          throw cause;
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
    assertArtifactReadActive(signal);
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
    capturedOutput = result.captured_output;
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
      if (
        cause instanceof AnalysisError ||
        cause instanceof ArtifactReaderFailure
      )
        throw cause;
      throw podmanProfileUnavailable(
        `Initialized DBConfig interpretation is unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
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
    assertArtifactReadActive(signal);
    const databaseObservation = {
      source,
      configuration: config,
      semantics:
        "observed quiescent SQLite schema1 DBConfig; installed source attestation remains unknown" as const,
    };
    observed = databaseObservation;
    return databaseObservation;
  } catch (cause: unknown) {
    if (cause instanceof ArtifactReaderFailure) {
      primary = firmwareFailure(cause, "podman", "firmware_container_runtime");
    } else if (
      cause instanceof ProviderAdapterError &&
      !cause.cleanupIncomplete
    ) {
      primary = podmanProfileUnavailable(
        `Initialized database helper failed; database compatibility remains unknown: ${cause.message}`,
        {
          cause,
          diagnostics: cause.diagnostics,
          capturedOutput: cause.capturedOutput,
          partialObservation: cause.partialObservation,
        },
      );
    } else
      primary =
        cause instanceof AnalysisError
          ? cause
          : signal.aborted && cause === signal.reason
            ? new AnalysisCancelledError("firmware_container_runtime", {
                cause,
              })
            : podmanProfileUnavailable(
                `Initialized database compatibility is unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
                { cause },
              );
    throw primary;
  } finally {
    // This workspace owns the parser's entire retained cleanup set. Descriptor
    // failures keep their independent leases and must not be resolved here.
    const retainedParserFailure =
      primary instanceof ProviderCleanupError && pending.size > 0
        ? primary
        : undefined;
    const released = await scope.release(owner);
    if (retainedParserFailure !== undefined) {
      if (released.kind === "failed")
        new AnalysisCleanupLeaseGroup(retainedParserFailure, [released.lease]);
      else retainedParserFailure.resolveCleanup();
    }
    // Completion cancellation is observed after final cleanup. A prior failure
    // remains primary even when the caller cancels while its owner is closing.
    const completionFailure =
      primary ??
      (signal.aborted
        ? new AnalysisCancelledError("firmware_container_runtime", {
            cause: signal.reason,
          })
        : undefined);
    if (capturedOutput !== undefined)
      completionFailure?.retainCapturedOutput(capturedOutput);
    if (released.kind === "failed") {
      const cleanup = new ProviderCleanupError(
        "podman",
        [root.path],
        {
          reason:
            "Private read-only database admission cleanup remains pending",
          observed_database: observed ?? null,
        },
        { operation: "firmware_container_runtime", cause: released.cause },
      );
      new AnalysisCleanupLeaseGroup(cleanup, [released.lease]);
      if (capturedOutput !== undefined)
        cleanup.retainCapturedOutput(capturedOutput);
      throw completionFailure === undefined
        ? cleanup
        : analysisErrorWithCleanupFailure(
            completionFailure,
            cleanup,
            "firmware_container_runtime",
          ).bindCleanupDependencies([completionFailure, cleanup]);
    }
    if (primary === undefined && completionFailure !== undefined)
      throw completionFailure;
  }
};
