import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import {
  AnalysisError,
  type AnalysisCapturedOutput,
} from "../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { createHash, randomUUID } from "node:crypto";
import { access, realpath, stat } from "node:fs/promises";
import { constants } from "node:fs";
import type { Readable } from "node:stream";
import { isAbsolute, relative, sep } from "node:path";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisCancelledError,
  AnalysisTimeoutError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  spawnOwnedProviderProcess,
  ProviderProcessSupervisor,
  type OwnedProviderProcessSpawnOptions,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../process/ProcessOwnership.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";
import {
  spawnUnblobSystemdProcess,
  type UnblobSystemdProfile,
} from "./UnblobSystemd.js";
import {
  hashFirmwareFile,
  inventoryFirmwareOutput,
  readFirmwareReport,
} from "./FirmwareFiles.js";

/** Injectable owned launcher for production protocol and lifecycle tests. */
export type FirmwareLauncher = (
  options: OwnedProviderProcessSpawnOptions,
) => Promise<SpawnedOwnedProviderProcess>;

export interface FirmwareCommandResult {
  readonly stdout: {
    readonly text: string;
    readonly bytes: number;
    readonly observedBytes: number;
    readonly invalidUtf8?: true;
  };
  readonly stderr: {
    readonly text: string;
    readonly bytes: number;
    readonly observedBytes: number;
    readonly invalidUtf8?: true;
  };
  readonly exit_code: number | null | undefined;
  readonly signal: string | null;
  readonly captured_output?: AnalysisCapturedOutput;
  readonly transport_capture?: AnalysisCapturedOutput;
  readonly diagnostic_truncated: boolean;
  readonly output_incomplete?: true;
  readonly command: string;
  readonly args: readonly string[];
  readonly resource_limiter?: string;
  readonly stdoutResult?: unknown;
  readonly transport?: Readonly<Record<string, unknown>>;
}

/** Refuse an unmet host or tool requirement, which another target cannot satisfy. */
export const firmwareToolUnavailable = (
  engine: string,
  operation: string,
  reason: string,
): AnalysisCapabilityUnavailableError =>
  new AnalysisCapabilityUnavailableError(engine, operation, reason, {
    userMessage: reason,
  });

/** Resolve explicitly supplied executable paths; never install or search for engines. */
export const resolveFirmwareCommand = async (
  environment: Readonly<Record<string, string | undefined>>,
  engine: "binwalk" | "unblob",
  operation: string,
  signal?: AbortSignal,
  scope?: ArtifactResourceScope,
) => {
  signal?.throwIfAborted();
  const variable =
    engine === "binwalk" ? "REA_BINWALK_COMMAND" : "REA_UNBLOB_COMMAND";
  const configured = environment[variable];
  if (
    process.platform !== "linux" ||
    configured === undefined ||
    !isAbsolute(configured)
  )
    throw firmwareToolUnavailable(
      engine,
      operation,
      `This integration requires Linux and an absolute ${variable} path to the caller-supplied tool`,
    );
  const command = await realpath(configured).catch((cause: unknown) => {
    signal?.throwIfAborted();
    throw firmwareToolUnavailable(
      engine,
      operation,
      `${variable} is unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  });
  signal?.throwIfAborted();
  let sha256: string;
  try {
    await access(command, constants.R_OK | constants.X_OK);
    signal?.throwIfAborted();
    const identity = await stat(command);
    signal?.throwIfAborted();
    if (!identity.isFile())
      throw new TypeError("Configured path is not a regular file");
    sha256 = await hashFirmwareFile(command, signal, scope, operation);
    signal?.throwIfAborted();
  } catch (cause: unknown) {
    if (cause instanceof AnalysisError && cause.cleanupIncomplete) throw cause;
    signal?.throwIfAborted();
    throw firmwareToolUnavailable(
      engine,
      operation,
      `${variable} is not a readable executable regular file: ${command}: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  let rootDirectory: string | undefined;
  if (engine === "unblob") {
    const configuredRoot = environment.REA_UNBLOB_RUNTIME_ROOT;
    if (configuredRoot === undefined || !isAbsolute(configuredRoot))
      throw firmwareToolUnavailable(
        engine,
        operation,
        "Native Unblob requires an absolute REA_UNBLOB_RUNTIME_ROOT containing the caller-supplied interpreter, package, and dependencies",
      );
    rootDirectory = await realpath(configuredRoot).catch((cause: unknown) => {
      signal?.throwIfAborted();
      throw firmwareToolUnavailable(
        engine,
        operation,
        `REA_UNBLOB_RUNTIME_ROOT is unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    });
    const relativeExecutable = relative(rootDirectory, command);
    if (
      relativeExecutable === ".." ||
      relativeExecutable.startsWith(`..${sep}`) ||
      isAbsolute(relativeExecutable)
    )
      throw firmwareToolUnavailable(
        engine,
        operation,
        "REA_UNBLOB_COMMAND must resolve inside REA_UNBLOB_RUNTIME_ROOT",
      );
  }
  const limiter =
    engine === "unblob"
      ? "/usr/bin/systemd-run"
      : (environment.REA_FIRMWARE_PRLIMIT_COMMAND ?? "/usr/bin/prlimit");
  if (!isAbsolute(limiter))
    throw firmwareToolUnavailable(
      engine,
      operation,
      engine === "unblob"
        ? "user systemd systemd-run must be available at /usr/bin/systemd-run"
        : "REA_FIRMWARE_PRLIMIT_COMMAND must be absolute",
    );
  try {
    await access(limiter, constants.X_OK);
    signal?.throwIfAborted();
    const identity = await stat(limiter);
    signal?.throwIfAborted();
    if (!identity.isFile())
      throw new TypeError("Configured path is not a regular file");
  } catch (cause: unknown) {
    signal?.throwIfAborted();
    throw firmwareToolUnavailable(
      engine,
      operation,
      engine === "unblob"
        ? `Native Unblob requires /usr/bin/systemd-run and the user-systemd manager: ${cause instanceof Error ? cause.message : String(cause)}`
        : `Resource limiter is not an executable regular file: ${limiter}: ${cause instanceof Error ? cause.message : String(cause)}; provide util-linux prlimit`,
    );
  }
  return {
    command: configured,
    resolvedCommand: command,
    limiter,
    sha256,
    ...(rootDirectory === undefined ? {} : { rootDirectory }),
  };
};

/** Execute one bounded provider command and verify its owned descendants have stopped. */
export const runFirmwareCommand = async (context: {
  engine: string;
  operation: string;
  command: string;
  limiter: string;
  args: readonly string[];
  cwd: string;
  environment: Readonly<Record<string, string | undefined>>;
  signal: AbortSignal;
  launcher?: FirmwareLauncher;
  outputBudget?: { root: string; bytes: number; entries: number };
  systemdProfile?: UnblobSystemdProfile;
  consumeStdout?: (stream: Readable) => Promise<unknown>;
  acceptReportedExtractionFailure?: boolean;
  retainCleanup(supervisor: ProviderProcessSupervisor): void;
}): Promise<FirmwareCommandResult> => {
  const { engine, operation, signal } = context;
  signal.throwIfAborted();
  const runId = `rea-firmware-${randomUUID()}`;
  const launchOptions: OwnedProviderProcessSpawnOptions = {
    command: context.limiter,
    arguments: [
      `--as=${FIRMWARE_LIMITS.addressSpaceBytes}`,
      `--fsize=${context.outputBudget?.bytes ?? FIRMWARE_LIMITS.reportBytes}`,
      "--core=0",
      "--cpu=120",
      "--",
      context.command,
      ...context.args,
    ],
    expectedCommand: null,
    runId,
    cwd: context.cwd,
    hostEnvironment: context.environment,
    signal,
    env: {
      TMPDIR: context.cwd,
      OMP_NUM_THREADS: "1",
      OPENBLAS_NUM_THREADS: "1",
      RAYON_NUM_THREADS: "1",
      NO_COLOR: "1",
    },
  };
  const spawned =
    engine === "unblob" &&
    context.systemdProfile !== undefined &&
    context.launcher === undefined
      ? await spawnUnblobSystemdProcess(
          context.systemdProfile,
          context.args,
          launchOptions,
        )
      : await (context.launcher ?? spawnOwnedProviderProcess)(launchOptions);
  let diagnosticTruncated = false;
  const supervisor = new ProviderProcessSupervisor(
    {
      ...spawned,
      ownsProcessLifetime: true,
      cleanup:
        spawned.cleanup ?? (() => cleanupOwnedProcessGroup(spawned.ownership)),
    },
    {
      captureStdout: context.consumeStdout === undefined,
      maxDiagnosticBytes: FIRMWARE_LIMITS.diagnosticBytes,
      onDiagnostic: (event) => {
        if (event.type === "output" && event.truncated === true)
          diagnosticTruncated = true;
      },
    },
  );
  const capture = (): AnalysisCapturedOutput => {
    const snapshot = supervisor.snapshot();
    const stderrBytes = Buffer.from(snapshot.stderr.text, "utf8");
    const stderrUtf8Valid = snapshot.stderr.invalidUtf8 !== true;
    return {
      stdout: snapshot.stdout.text,
      stderr: snapshot.stderr.text,
      truncated: snapshot.diagnosticTruncated ?? false,
      stderr_bytes: snapshot.stderr.bytes,
      stderr_observed_bytes: snapshot.stderr.observedBytes,
      exit_code: snapshot.exitCode ?? null,
      signal: snapshot.signal ?? null,
      stderr_utf8_valid: stderrUtf8Valid,
      ...(context.consumeStdout === undefined
        ? {
            stdout_bytes: snapshot.stdout.bytes,
            stdout_observed_bytes: snapshot.stdout.observedBytes,
            stdout_utf8_valid: snapshot.stdout.invalidUtf8 !== true,
            ...(snapshot.stdout.invalidUtf8 !== true &&
            Buffer.byteLength(snapshot.stdout.text, "utf8") ===
              snapshot.stdout.bytes
              ? {
                  stdout_sha256: createHash("sha256")
                    .update(Buffer.from(snapshot.stdout.text, "utf8"))
                    .digest("hex"),
                }
              : {}),
          }
        : {}),
      ...(stderrUtf8Valid && stderrBytes.byteLength === snapshot.stderr.bytes
        ? {
            stderr_sha256: createHash("sha256")
              .update(stderrBytes)
              .digest("hex"),
          }
        : {}),
      ...(context.consumeStdout === undefined
        ? { command: context.command }
        : spawned.invocation === undefined
          ? {}
          : { command: spawned.invocation.command }),
      ...(context.consumeStdout === undefined
        ? { arguments: [...context.args] }
        : spawned.invocation === undefined
          ? {}
          : { arguments: [...spawned.invocation.arguments] }),
      ...(context.consumeStdout === undefined
        ? { resource_limiter: context.limiter }
        : {}),
    };
  };
  let stdoutResult: unknown;
  let stdoutFailure: unknown;
  const stdoutResultPromise =
    context.consumeStdout === undefined
      ? undefined
      : context.consumeStdout(supervisor.launch.process.stdout!).then(
          (value) => {
            stdoutResult = value;
          },
          (cause: unknown) => {
            stdoutFailure = cause;
          },
        );
  const checkDiagnostics = () => {
    const snapshot = supervisor.snapshot();
    if (
      diagnosticTruncated ||
      snapshot.diagnosticTruncated === true ||
      snapshot.outputIncomplete === true
    ) {
      throw new AnalysisOutputError(
        operation,
        snapshot.outputIncomplete === true
          ? "Tool output is incomplete; refusing to interpret a partial report"
          : `Tool diagnostics exceeded the ${FIRMWARE_LIMITS.diagnosticBytes}-byte capture budget`,
        {
          capturedOutput: capture(),
        },
      );
    }
  };
  let failure: unknown;
  try {
    const deadline = performance.now() + FIRMWARE_LIMITS.timeoutMs;
    while (!(await supervisor.waitForOutputClose(100))) {
      if (stdoutFailure !== undefined) throw stdoutFailure;
      checkDiagnostics();
      if (signal.aborted) throw new AnalysisCancelledError(operation);
      if (performance.now() >= deadline)
        throw new AnalysisTimeoutError(operation, FIRMWARE_LIMITS.timeoutMs);
      if (context.outputBudget !== undefined)
        await inventoryFirmwareOutput(
          context.outputBudget.root,
          context.outputBudget.bytes,
          context.outputBudget.entries,
          operation,
          signal,
        );
    }
    await stdoutResultPromise;
    if (stdoutFailure !== undefined) throw stdoutFailure;
    checkDiagnostics();
    if (signal.aborted) throw new AnalysisCancelledError(operation);
  } catch (cause: unknown) {
    failure = cause;
  }
  const stopped = await supervisor.stop();
  await stdoutResultPromise;
  const snapshot = supervisor.snapshot();
  const captured = capture();
  if (failure instanceof AnalysisError) failure.retainCapturedOutput(captured);
  if (stopped.status === "incomplete") {
    context.retainCleanup(supervisor);
    throw new ProviderCleanupError(
      engine,
      [runId, context.cwd],
      {
        reason: stopped.reason,
        leader_pid: spawned.ownership.leaderPid,
        process_group_id: spawned.ownership.processGroupId,
        exit_code: snapshot.exitCode ?? null,
        signal: snapshot.signal ?? null,
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        ...(context.consumeStdout === undefined
          ? { stdout_bytes: snapshot.stdout.bytes }
          : {}),
        stderr_bytes: snapshot.stderr.bytes,
        previous_error: failure instanceof Error ? failure.message : null,
        primary_error:
          failure instanceof AnalysisError
            ? projectAnalysisError(failure)
            : null,
      },
      { operation, cause: failure, capturedOutput: captured },
    );
  }
  if (failure !== undefined) throw failure;
  if (
    snapshot.exitCode !== 0 &&
    !(
      context.acceptReportedExtractionFailure === true &&
      snapshot.exitCode === 1
    )
  )
    throw new ProviderAdapterError(engine, operation, {
      capturedOutput: captured,
      diagnostics: {
        reason:
          "Tool failed; inspect exit status and stderr for format, dependency, sandbox or resource-limit failures",
        exit_code: snapshot.exitCode ?? null,
        signal: snapshot.signal ?? null,
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        ...(context.consumeStdout === undefined
          ? { stdout_bytes: snapshot.stdout.bytes }
          : {}),
        stderr_bytes: snapshot.stderr.bytes,
      },
    });
  return {
    stdout: snapshot.stdout,
    stderr: snapshot.stderr,
    exit_code: snapshot.exitCode,
    signal: snapshot.signal ?? null,
    ...(context.consumeStdout === undefined
      ? { captured_output: captured }
      : { transport_capture: captured }),
    diagnostic_truncated: snapshot.diagnosticTruncated ?? false,
    ...(snapshot.outputIncomplete === true ? { output_incomplete: true } : {}),
    command: context.command,
    args: [...context.args],
    ...(context.consumeStdout === undefined
      ? { resource_limiter: context.limiter }
      : {}),
    ...(context.consumeStdout === undefined ? {} : { stdoutResult }),
  };
};

/** Preserve tool failure diagnostics when an accepted exit 1 has no usable report. */
export const readFirmwareCommandReport = async (context: {
  path: string;
  engine: string;
  operation: string;
  signal?: AbortSignal;
  scope?: ArtifactResourceScope;
  execution: Awaited<ReturnType<typeof runFirmwareCommand>>;
}): Promise<unknown> => {
  try {
    return await readFirmwareReport(
      context.path,
      context.operation,
      context.signal,
      context.scope,
    );
  } catch (cause: unknown) {
    if (cause instanceof AnalysisError && cause.cleanupIncomplete) throw cause;
    context.signal?.throwIfAborted();
    if (context.execution.exit_code === 1)
      throw new ProviderAdapterError(context.engine, context.operation, {
        cause,
        diagnostics: {
          reason:
            "Tool exited 1 without a usable analysis report; inspect stderr for startup, sandbox or dependency failures",
          report_failure:
            cause instanceof Error ? cause.message : String(cause),
          exit_code: 1,
          signal: context.execution.signal,
          stdout: context.execution.stdout.text,
          stderr: context.execution.stderr.text,
          stdout_bytes: context.execution.stdout.bytes,
          stderr_bytes: context.execution.stderr.bytes,
        },
      });
    const diagnostics = `stdout (${context.execution.stdout.bytes} bytes): ${context.execution.stdout.text}; stderr (${context.execution.stderr.bytes} bytes): ${context.execution.stderr.text}`;
    if (cause instanceof AnalysisOutputError)
      throw new AnalysisOutputError(
        context.operation,
        `${cause.reason}; ${diagnostics}`,
        { cause },
      );
    throw new AnalysisOutputError(
      context.operation,
      `Tool did not produce the expected complete report: ${context.path}; ${diagnostics}`,
      { cause },
    );
  }
};
