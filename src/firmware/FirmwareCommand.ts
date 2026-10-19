import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { firmwareFailure } from "./FirmwareFailures.js";
import { randomUUID } from "node:crypto";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { access, lstat, realpath, stat } from "node:fs/promises";
import { constants } from "node:fs";
import { isAbsolute } from "node:path";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisCancelledError,
  AnalysisTimeoutError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  spawnOwnedProviderProcess,
  ProviderProcessSupervisor,
  type OwnedProviderProcessSpawnOptions,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../process/ProcessOwnership.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";
import {
  FirmwareFileAccess,
  inventoryFirmwareOutput,
} from "./FirmwareFiles.js";

/** Injectable owned launcher for production protocol and lifecycle tests. */
export type FirmwareLauncher = (
  options: OwnedProviderProcessSpawnOptions,
) => Promise<SpawnedOwnedProviderProcess>;

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
  files: FirmwareFileAccess,
  signal?: AbortSignal,
) => {
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
    throw firmwareToolUnavailable(
      engine,
      operation,
      `${variable} is unavailable: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  });
  let sha256: string;
  try {
    await access(command, constants.R_OK | constants.X_OK);
    if (!(await stat(command)).isFile())
      throw new TypeError("Configured path is not a regular file");
    sha256 = await files.hash(command, signal);
  } catch (cause: unknown) {
    if (cause instanceof ArtifactReaderFailure) throw cause;
    throw firmwareToolUnavailable(
      engine,
      operation,
      `${variable} is not a readable executable regular file: ${command}: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  const limiter =
    environment.REA_FIRMWARE_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";
  if (!isAbsolute(limiter))
    throw firmwareToolUnavailable(
      engine,
      operation,
      "REA_FIRMWARE_PRLIMIT_COMMAND must be absolute",
    );
  try {
    await access(limiter, constants.X_OK);
    if (!(await stat(limiter)).isFile())
      throw new TypeError("Configured path is not a regular file");
  } catch (cause: unknown) {
    throw firmwareToolUnavailable(
      engine,
      operation,
      `Resource limiter is not an executable regular file: ${limiter}: ${cause instanceof Error ? cause.message : String(cause)}; provide util-linux prlimit`,
    );
  }
  return { command, limiter, sha256 };
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
  boundedOutputFiles?: readonly {
    readonly path: string;
    readonly maxBytes: number;
  }[];
  acceptReportedExtractionFailure?: boolean;
  acceptedExitCodes?: readonly number[];
  limitProfile?: "producer" | "container-transport" | "metadata-observer";
  protocolInput?: Buffer;
  protocolStdout?: (stdout: Readable) => Promise<void>;
  inheritedDescriptors?: readonly number[];
  retainCleanup(supervisor: ProviderProcessSupervisor): void;
}) => {
  const { engine, operation, signal } = context;
  if (signal.aborted)
    throw new AnalysisCancelledError(operation, { cause: signal.reason });
  if (
    context.limitProfile === "container-transport" &&
    context.launcher === undefined
  )
    throw firmwareToolUnavailable(
      engine,
      operation,
      "Container transport requires its explicit direct-client cleanup owner",
    );
  if (
    context.protocolInput !== undefined &&
    context.protocolInput.length > 16 * 1024
  )
    throw firmwareToolUnavailable(
      engine,
      operation,
      "Metadata request exceeds its 16 KiB protocol input budget",
    );
  const protocolInput =
    context.protocolInput === undefined
      ? undefined
      : Buffer.from(context.protocolInput);
  const runId = `rea-firmware-${randomUUID()}`;
  const spawned = await (context.launcher ?? spawnOwnedProviderProcess)({
    command: context.limiter,
    arguments: [
      ...(context.limitProfile === "container-transport"
        ? []
        : [
            `--as=${FIRMWARE_LIMITS.addressSpaceBytes}`,
            `--fsize=${context.limitProfile === "metadata-observer" ? 1_048_576 : (context.outputBudget?.bytes ?? FIRMWARE_LIMITS.reportBytes)}`,
          ]),
      "--core=0",
      context.limitProfile === "metadata-observer" ? "--cpu=5" : "--cpu=120",
      "--",
      context.command,
      ...context.args,
    ],
    expectedCommand: null,
    ...(protocolInput === undefined ? {} : { stdin: "pipe" as const }),
    ...(context.inheritedDescriptors === undefined
      ? {}
      : { inheritedDescriptors: context.inheritedDescriptors }),
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
  });
  let diagnosticTruncated = false;
  const supervisor = new ProviderProcessSupervisor(
    {
      ...spawned,
      ownsProcessLifetime: true,
      cleanup:
        spawned.cleanup ??
        (context.limitProfile === "container-transport"
          ? async () => ({
              cleaned: false as const,
              reason:
                "Container transport launcher returned no direct-client cleanup owner; group signaling is refused",
            })
          : () => cleanupOwnedProcessGroup(spawned.ownership)),
    },
    {
      ...(context.protocolStdout === undefined ? {} : { captureStdout: false }),
      maxDiagnosticBytes:
        context.limitProfile === "metadata-observer"
          ? 65_536
          : FIRMWARE_LIMITS.diagnosticBytes,
      onDiagnostic: (event) => {
        if (event.type === "output" && event.truncated === true)
          diagnosticTruncated = true;
      },
    },
  );
  let protocolObservedBytes = 0;
  const capture = () => {
    const snapshot = supervisor.snapshot();
    return {
      stdout: snapshot.stdout.text,
      stderr: snapshot.stderr.text,
      truncated: snapshot.diagnosticTruncated ?? false,
      ...(context.protocolStdout === undefined
        ? {
            stdout_bytes: snapshot.stdout.bytes,
            stdout_utf8_valid: snapshot.stdout.invalidUtf8 !== true,
            ...(snapshot.stdout.invalidUtf8 === true
              ? {}
              : { stdout_sha256: snapshot.stdout.sha256 }),
          }
        : {}),
      stderr_bytes: snapshot.stderr.bytes,
      stdout_observed_bytes:
        context.protocolStdout === undefined
          ? snapshot.stdout.observedBytes
          : protocolObservedBytes,
      stderr_observed_bytes: snapshot.stderr.observedBytes,
      exit_code: snapshot.exitCode ?? null,
      signal: snapshot.signal ?? null,
      ...(snapshot.stderr.invalidUtf8 === true
        ? {}
        : { stderr_sha256: snapshot.stderr.sha256 }),
      stderr_utf8_valid: snapshot.stderr.invalidUtf8 !== true,
      stdout_capture:
        context.protocolStdout === undefined
          ? ("diagnostic" as const)
          : ("protocol" as const),
      command: context.command,
      arguments: [...context.args],
      resource_limiter: context.limiter,
    };
  };
  const checkDiagnostics = () => {
    const snapshot = supervisor.snapshot();
    if (diagnosticTruncated || snapshot.outputIncomplete === true)
      throw new AnalysisOutputError(
        operation,
        snapshot.outputIncomplete === true
          ? "Tool output closed before complete observation"
          : `Tool diagnostics exceeded the ${FIRMWARE_LIMITS.diagnosticBytes}-byte capture budget`,
        { capturedOutput: { ...capture(), truncated: true } },
      );
  };
  const protocolError = (cause: unknown): AnalysisError => {
    if (cause instanceof ArtifactReaderFailure)
      return firmwareFailure(cause, engine, operation);
    if (cause instanceof AnalysisError) return cause;
    const observed = supervisor.snapshot();
    return new ProviderAdapterError(engine, operation, {
      cause,
      diagnostics: {
        reason: cause instanceof Error ? cause.message : String(cause),
        exit_code: observed.exitCode ?? null,
        signal: observed.signal ?? null,
        stderr: observed.stderr.text,
        stderr_bytes: observed.stderr.bytes,
      },
    });
  };
  let failure: unknown;
  let protocolFailure: unknown;
  const protocolMeter =
    context.protocolStdout === undefined
      ? undefined
      : new Transform({
          transform(chunk: Buffer, _encoding, callback) {
            protocolObservedBytes += chunk.byteLength;
            callback(null, chunk);
          },
        });
  const protocolOutput =
    context.protocolStdout === undefined || protocolMeter === undefined
      ? undefined
      : spawned.process.stdout === null
        ? Promise.reject(new Error("Provider omitted protocol stdout"))
        : Promise.all([
            pipeline(spawned.process.stdout, protocolMeter),
            context.protocolStdout(protocolMeter),
          ])
            .then(() => undefined)
            .catch((cause: unknown) => {
              protocolFailure = cause;
              throw cause;
            });
  void protocolOutput?.catch(() => {});
  try {
    if (protocolInput !== undefined) {
      const stdin = spawned.process.stdin;
      if (stdin === undefined || stdin === null)
        throw new Error("Fixed protocol launcher omitted stdin");
      stdin.on("error", () => {});
      await new Promise<void>((resolve, reject) => {
        const aborted = () => reject(new AnalysisCancelledError(operation));
        signal.addEventListener("abort", aborted, { once: true });
        stdin.write(protocolInput, (error) => {
          signal.removeEventListener("abort", aborted);
          if (error) reject(error);
          else resolve();
        });
        if (signal.aborted) aborted();
      });
      stdin.end();
    }
    const deadline = performance.now() + FIRMWARE_LIMITS.timeoutMs;
    while (!(await supervisor.waitForOutputClose(100))) {
      if (protocolFailure !== undefined) throw protocolError(protocolFailure);
      checkDiagnostics();
      await assertFirmwareOutputBounds(
        context.boundedOutputFiles ?? [],
        operation,
      );
      if (signal.aborted)
        throw new AnalysisCancelledError(operation, { cause: signal.reason });
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
    if (protocolOutput !== undefined) await protocolOutput;
    checkDiagnostics();
    await assertFirmwareOutputBounds(
      context.boundedOutputFiles ?? [],
      operation,
    );
    if (signal.aborted)
      throw new AnalysisCancelledError(operation, { cause: signal.reason });
  } catch (cause: unknown) {
    failure = cause === protocolFailure ? protocolError(cause) : cause;
  }
  const stopped = await supervisor.stop();
  if (protocolMeter !== undefined) {
    spawned.process.stdout?.unpipe(protocolMeter);
    protocolMeter.destroy();
  }
  const snapshot = supervisor.snapshot();
  const capturedOutput = capture();
  if (
    failure === undefined &&
    snapshot.exitCode !== undefined &&
    snapshot.exitCode !== 0 &&
    !(context.acceptedExitCodes ?? []).includes(snapshot.exitCode ?? -1) &&
    !(
      context.acceptReportedExtractionFailure === true &&
      snapshot.exitCode === 1
    )
  )
    failure = new ProviderAdapterError(engine, operation, {
      diagnostics: {
        reason:
          "Tool failed; inspect exit status and stderr for format, dependency, sandbox or resource-limit failures",
        exit_code: snapshot.exitCode ?? null,
        signal: snapshot.signal ?? null,
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        stdout_bytes: snapshot.stdout.bytes,
        stderr_bytes: snapshot.stderr.bytes,
      },
    });
  if (failure === undefined && signal.aborted)
    failure = new AnalysisCancelledError(operation, { cause: signal.reason });
  if (failure instanceof AnalysisError)
    failure.retainCapturedOutput(capturedOutput);
  if (stopped.status === "incomplete") {
    context.retainCleanup(supervisor);
    throw new ProviderCleanupError(
      engine,
      [runId, context.cwd],
      {
        reason: stopped.reason,
        captured_output: capturedOutput,
        leader_pid: spawned.ownership.leaderPid,
        process_group_id: spawned.ownership.processGroupId,
        exit_code: snapshot.exitCode ?? null,
        signal: snapshot.signal ?? null,
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        stdout_bytes: snapshot.stdout.bytes,
        stderr_bytes: snapshot.stderr.bytes,
        previous_error: failure instanceof Error ? failure.message : null,
        ...(failure instanceof AnalysisError
          ? { primary_error: projectAnalysisError(failure) }
          : {}),
      },
      {
        operation,
        cause: failure,
        ...(failure instanceof AnalysisError
          ? { cleanupPrimary: failure }
          : {}),
      },
    ).retainCapturedOutput(capturedOutput);
  }
  if (failure !== undefined) throw failure;
  return {
    stdout: snapshot.stdout,
    stderr: snapshot.stderr,
    exit_code: snapshot.exitCode,
    signal: snapshot.signal ?? null,
    command: context.command,
    args: [...context.args],
    resource_limiter: context.limiter,
    captured_output: capturedOutput,
  };
};

/** Recheck bounded private producer files while the owned process is active. */
export const assertFirmwareOutputBounds = async (
  files: readonly { readonly path: string; readonly maxBytes: number }[],
  operation: string,
): Promise<void> => {
  for (const file of files) {
    const current = await lstat(file.path).catch((cause: unknown) => {
      if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
        return undefined;
      throw cause;
    });
    if (current === undefined) continue;
    if (!current.isFile())
      throw new AnalysisOutputError(
        operation,
        `Private output is not a regular file: ${file.path}`,
      );
    if (current.size > file.maxBytes)
      throw new AnalysisOutputError(
        operation,
        `Private output exceeded ${file.maxBytes} bytes: ${file.path}`,
      );
  }
};

/** Preserve tool failure diagnostics when an accepted exit 1 has no usable report. */
export const readFirmwareCommandReport = async (context: {
  path: string;
  engine: string;
  operation: string;
  execution: Awaited<ReturnType<typeof runFirmwareCommand>>;
  files: FirmwareFileAccess;
  signal?: AbortSignal;
}): Promise<unknown> => {
  try {
    return await context.files.report(
      context.path,
      context.operation,
      context.signal,
    );
  } catch (cause: unknown) {
    if (cause instanceof ArtifactReaderFailure) throw cause;
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
