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
import type { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";

/** One owned run under the selected namespace/mount/environment policy. */
export interface BinwalkNgCommandContext {
  readonly sandbox: Awaited<ReturnType<typeof prepareBinwalkNgSandbox>>;
  readonly operation: string;
  readonly signal: AbortSignal;
  readonly maxOutputBytes: number;
  readonly maxOutputFiles: number;
  readonly launcher?: FirmwareLauncher;
  readonly reportPath?: string;
  readonly pngPath?: string;
  retainCleanup(supervisor: ProviderProcessSupervisor): void;
}

/** Native descendants inherit only the controlled environment and the owned run token. */
export const runBinwalkNgCommand = async (
  context: BinwalkNgCommandContext,
  args: readonly string[],
) => {
  const { sandbox } = context;
  return runFirmwareCommand({
    engine: "binwalk-ng",
    operation: context.operation,
    command: sandbox.bubblewrap.path,
    limiter: sandbox.limiter.path,
    args: [...sandbox.policy_arguments, "--", "/runtime/bin/binwalk", ...args],
    cwd: sandbox.work_root,
    environment: {},
    signal: context.signal,
    outputBudget: {
      root: sandbox.work_root,
      bytes: context.maxOutputBytes,
      entries: context.maxOutputFiles,
    },
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
      const spawned = await (context.launcher ?? spawnOwnedProviderProcess)({
        ...options,
        arguments: [
          ...options.arguments.slice(0, boundary),
          "--setenv",
          "REA_PROCESS_RUN_ID",
          options.runId,
          ...options.arguments.slice(boundary),
        ],
      });
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
