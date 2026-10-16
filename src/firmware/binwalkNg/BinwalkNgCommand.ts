import {
  AnalysisCancelledError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { systemProcessOwnershipHost } from "../../process/ProcessOwnershipObservation.js";
import { cleanupOwnedProcessGroup } from "../../process/ProcessOwnership.js";
import {
  spawnOwnedProviderProcess,
  type ProviderProcessSupervisor,
} from "../../process/ProviderProcess.js";
import {
  firmwareToolUnavailable,
  runFirmwareCommand,
  type FirmwareLauncher,
} from "../FirmwareCommand.js";
import { FIRMWARE_LIMITS } from "../FirmwareRelease.js";
import { consumeBinwalkNgTransfer } from "./BinwalkNgTransfer.js";
import type { BinwalkNgAggregateBudget } from "./BinwalkNgAggregateBudget.js";
import type { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import type { Readable } from "node:stream";
import type { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";
import {
  binwalkNgCgroupGateArguments,
  binwalkNgSystemdRunArguments,
  readBinwalkNgSystemdEnvironmentNames,
} from "./BinwalkNgSystemdBoundary.js";

/** One owned run under the selected namespace/mount/environment policy. */
export interface BinwalkNgCommandContext {
  readonly sandbox: Awaited<ReturnType<typeof prepareBinwalkNgSandbox>>;
  readonly operation: string;
  readonly signal: AbortSignal;
  readonly maxOutputBytes: number;
  readonly maxOutputFiles: number;
  readonly launcher?: FirmwareLauncher;
  readonly executable?: string;
  readonly reportPath?: string;
  readonly pngPath?: string;
  readonly workspaceQuota?: {
    readonly bytes: number;
    readonly inodes: number;
  };
  readonly transfer?: {
    readonly tree: SafeOutputTree;
    readonly paths: readonly string[];
    readonly maxBytes: number;
    readonly maxFiles: number;
    readonly maxEntries: number;
    readonly aggregateBudget?: BinwalkNgAggregateBudget;
  };
  retainCleanup(supervisor: ProviderProcessSupervisor): void;
}

/** Native descendants inherit only the controlled environment and the owned run token. */
export const runBinwalkNgCommand = async (
  context: BinwalkNgCommandContext,
  args: readonly string[],
) => {
  const { sandbox } = context;
  const executable = context.executable ?? "/runtime/bin/binwalk";
  if (!/^\/runtime\/bin\/[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(executable))
    throw firmwareToolUnavailable(
      "binwalk-ng",
      context.operation,
      "A child executable must resolve to one exact admitted runtime helper path",
    );
  return runFirmwareCommand({
    engine: "binwalk-ng",
    operation: context.operation,
    command: sandbox.bubblewrap.path,
    limiter: sandbox.limiter.path,
    args: [...sandbox.policy_arguments, "--", executable, ...args],
    cwd: sandbox.work_root,
    environment: {},
    signal: context.signal,
    boundedOutputFiles: [
      ...(context.reportPath === undefined
        ? []
        : [
            { path: context.reportPath, maxBytes: FIRMWARE_LIMITS.reportBytes },
          ]),
      ...(context.pngPath === undefined
        ? []
        : [{ path: context.pngPath, maxBytes: FIRMWARE_LIMITS.reportBytes }]),
    ],
    ...(context.transfer === undefined
      ? {}
      : {
          protocolStdout: (stdout: Readable) =>
            consumeBinwalkNgTransfer(stdout, context.transfer!.tree, {
              maxBytes: context.transfer!.maxBytes,
              maxFiles: context.transfer!.maxFiles,
              maxEntries: context.transfer!.maxEntries,
              ...(context.transfer!.aggregateBudget === undefined
                ? {}
                : { aggregateBudget: context.transfer!.aggregateBudget }),
              signal: context.signal,
            }).then(() => undefined),
        }),
    retainCleanup: context.retainCleanup,
    launcher: async (options) => {
      const boundary = options.arguments.lastIndexOf("--");
      if (boundary < 0) throw new Error("Missing native command boundary");
      const captureBaseline =
        await systemProcessOwnershipHost.captureBaseline?.(options.signal);
      if (captureBaseline === undefined)
        throw firmwareToolUnavailable(
          "binwalk-ng",
          context.operation,
          "Owned descendant supervision requires a prelaunch process identity baseline",
        );
      const providerArguments = [
        ...options.arguments.slice(0, boundary),
        "--setenv",
        "REA_PROCESS_RUN_ID",
        options.runId,
        ...options.arguments.slice(boundary),
      ];
      const uid = process.getuid?.();
      const gid = process.getgid?.();
      if (
        uid === undefined ||
        (context.workspaceQuota !== undefined && gid === undefined)
      )
        throw firmwareToolUnavailable(
          "binwalk-ng",
          context.operation,
          "A verified Linux user systemd manager is required for aggregate resource limits",
        );
      const runtimeDirectory = `/run/user/${uid}`;
      const serviceEnvironment = {
        PATH: "/usr/bin:/bin",
        XDG_RUNTIME_DIR: runtimeDirectory,
        DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`,
      };
      const inheritedEnvironmentNames =
        context.launcher === undefined
          ? (
              await readBinwalkNgSystemdEnvironmentNames(uid, options.signal)
            ).filter((name) => name !== "REA_PROCESS_RUN_ID")
          : [];
      const spawnOptions = {
        ...options,
        command: sandbox.systemdRun.path,
        expectedCommand: null,
        arguments: binwalkNgSystemdRunArguments({
          runId: options.runId,
          cwd: sandbox.work_root,
          command: process.execPath,
          ...(context.workspaceQuota === undefined
            ? {}
            : {
                workspaceQuota: {
                  bytes: context.workspaceQuota.bytes,
                  inodes: context.workspaceQuota.inodes,
                  uid,
                  gid: gid!,
                },
              }),
          inheritedEnvironmentNames,
          commandArguments: binwalkNgCgroupGateArguments({
            workRoot: sandbox.work_root,
            command: options.command,
            commandArguments: providerArguments,
            ...(context.workspaceQuota === undefined
              ? {}
              : {
                  workspaceQuota: {
                    bytes: context.workspaceQuota.bytes,
                    inodes: context.workspaceQuota.inodes,
                  },
                }),
            ...(context.transfer === undefined
              ? {}
              : {
                  transfer: {
                    paths: context.transfer.paths,
                    maxBytes: context.transfer.maxBytes,
                    maxFiles: context.transfer.maxFiles,
                    maxEntries: context.transfer.maxEntries,
                  },
                }),
          }),
        }),
        hostEnvironment: {},
        env: serviceEnvironment,
      };
      const spawned = await (context.launcher ?? spawnOwnedProviderProcess)(
        spawnOptions,
      );
      const ownership = {
        ...spawned.ownership,
        captureBaseline,
        sweepTokenOwnedProcesses: true,
      };
      return {
        ...spawned,
        ownership,
        cleanup:
          context.launcher === undefined || spawned.cleanup === undefined
            ? () => cleanupOwnedProcessGroup(ownership)
            : spawned.cleanup,
      };
    },
  });
};

/** Probe the identical policy, never launch an unrestricted replacement on denial. */
export const probeBinwalkNgSandbox = async (
  context: BinwalkNgCommandContext,
) => {
  try {
    const observed = await runBinwalkNgCommand(context, ["--version"]);
    if (observed.stdout.text.trim() !== "binwalk-ng 4.0.0")
      throw firmwareToolUnavailable(
        "binwalk-ng",
        context.operation,
        `Selected profile requires binwalk-ng 4.0.0; observed ${observed.stdout.text.trim()}`,
      );
    return observed;
  } catch (cause: unknown) {
    if (
      cause instanceof ProviderCleanupError ||
      cause instanceof AnalysisCancelledError ||
      cause instanceof AnalysisTimeoutError
    )
      throw cause;
    throw firmwareToolUnavailable(
      "binwalk-ng",
      context.operation,
      `The exact bubblewrap policy could not launch the selected runtime; no fallback was attempted: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
};

/** Run each configured version probe through the same quota, namespace and ownership boundary. */
export const verifyBinwalkNgHelperVersions = async (
  context: BinwalkNgCommandContext,
) => {
  const observed = [];
  const { transfer: _transfer, ...helperContext } = context;
  for (const helper of context.sandbox.helpers) {
    context.signal.throwIfAborted();
    const result = await runBinwalkNgCommand(
      {
        ...helperContext,
        executable: helper.destination,
        maxOutputBytes: Math.min(context.maxOutputBytes, 8 * 1024 * 1024),
      },
      helper.version_arguments,
    );
    // Version commands may include environment-specific details (locale,
    // loaded plugin paths, CPU/thread counts). Bind to the stable first
    // non-empty identity line while retaining the full execution evidence.
    const actual =
      result.stdout.text
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .find((line) => line.length > 0) ?? "";
    if (
      result.stdout.invalidUtf8 === true ||
      actual !== helper.expected_version
    )
      throw firmwareToolUnavailable(
        "binwalk-ng",
        context.operation,
        `Helper ${helper.name} version identity did not match the selected runtime manifest`,
      );
    observed.push({
      name: helper.name,
      path: helper.source,
      sha256: helper.sha256,
      version: actual,
      execution: result,
    });
  }
  return observed;
};
