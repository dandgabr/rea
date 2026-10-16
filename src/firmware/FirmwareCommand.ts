import {
  AnalysisError,
  type AnalysisCapturedOutput,
} from "../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { createHash } from "node:crypto";
import { randomUUID } from "node:crypto";
import { Readable } from "node:stream";
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
import {
  spawnOwnedProviderProcess,
  ProviderProcessSupervisor,
  type OwnedProviderProcessSpawnOptions,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../process/ProcessOwnership.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";
import {
  hashFirmwareFile,
  inventoryFirmwareOutput,
  readFirmwareReport,
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
    sha256 = await hashFirmwareFile(command, undefined, undefined, operation);
  } catch (cause: unknown) {
    if (cause instanceof AnalysisError && cause.cleanupIncomplete) throw cause;
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
  /** A fixed adapter protocol may assign meaning to a nonzero status (for example exact-CID absence). */
  acceptedExitCodes?: readonly number[];
  /** Host OCI clients have a distinct measured policy; producer limits remain the default. */
  limitProfile?: "producer" | "container-transport" | "metadata-observer";
  /** Fixed internal protocol input; copied before launch and bounded to16KiB. */
  protocolInput?: Buffer;
  /** Adapter-owned bounded binary protocol; disables stdout diagnostics capture. */
  protocolStdout?: (stdout: Readable) => Promise<void>;
  inheritedDescriptors?: readonly number[];
  retainCleanup(supervisor: ProviderProcessSupervisor): void;
}) => {
  const { engine, operation, signal } = context;
  signal.throwIfAborted();
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
      "Metadata request exceeds its16KiB protocol input budget",
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
            `--fsize=${context.limitProfile === "metadata-observer" ? 1048576 : (context.outputBudget?.bytes ?? FIRMWARE_LIMITS.reportBytes)}`,
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
          ? 65536
          : FIRMWARE_LIMITS.diagnosticBytes,
    },
  );
  let protocolStdoutObservedBytes = 0;
  const capture = (): AnalysisCapturedOutput => {
    const snapshot = supervisor.snapshot();
    const stdoutBytes = Buffer.from(snapshot.stdout.text, "utf8");
    const stderrBytes = Buffer.from(snapshot.stderr.text, "utf8");
    const stdoutUtf8Valid = snapshot.stdout.invalidUtf8 !== true;
    const stderrUtf8Valid = snapshot.stderr.invalidUtf8 !== true;
    const protocolStdout = context.protocolStdout !== undefined;
    return {
      stdout: snapshot.stdout.text,
      stderr: snapshot.stderr.text,
      truncated: snapshot.diagnosticTruncated ?? false,
      ...(protocolStdout
        ? { stdout_capture: "protocol" as const }
        : {
            stdout_capture: "diagnostic" as const,
            stdout_bytes: snapshot.stdout.bytes,
            stdout_observed_bytes: snapshot.stdout.observedBytes,
            stdout_utf8_valid: stdoutUtf8Valid,
            ...(stdoutUtf8Valid &&
            stdoutBytes.byteLength === snapshot.stdout.bytes
              ? {
                  stdout_sha256: createHash("sha256")
                    .update(stdoutBytes)
                    .digest("hex"),
                }
              : {}),
          }),
      stderr_bytes: snapshot.stderr.bytes,
      ...(protocolStdout
        ? { stdout_observed_bytes: protocolStdoutObservedBytes }
        : {}),
      stderr_observed_bytes: snapshot.stderr.observedBytes,
      exit_code: snapshot.exitCode ?? null,
      signal: snapshot.signal ?? null,
      stderr_utf8_valid: stderrUtf8Valid,
      ...(stderrUtf8Valid && stderrBytes.byteLength === snapshot.stderr.bytes
        ? {
            stderr_sha256: createHash("sha256")
              .update(stderrBytes)
              .digest("hex"),
          }
        : {}),
      command: context.command,
      arguments: [...context.args],
      resource_limiter: context.limiter,
    };
  };
  const checkDiagnostics = () => {
    const snapshot = supervisor.snapshot();
    if (snapshot.diagnosticTruncated || snapshot.outputIncomplete) {
      throw new AnalysisOutputError(
        operation,
        snapshot.outputIncomplete
          ? "Tool output was incomplete and cannot be interpreted as a complete result"
          : `Tool diagnostics exceeded the ${FIRMWARE_LIMITS.diagnosticBytes}-byte capture budget`,
        {
          capturedOutput: capture(),
        },
      );
    }
  };
  let failure: unknown;
  let protocolFailure: unknown;
  const protocolOutput =
    context.protocolStdout === undefined
      ? undefined
      : spawned.process.stdout === null
        ? Promise.reject(new Error("Provider omitted protocol stdout"))
        : context
            .protocolStdout(
              Readable.from(
                (async function* () {
                  for await (const value of spawned.process.stdout!) {
                    const chunk = Buffer.isBuffer(value)
                      ? value
                      : Buffer.from(value);
                    protocolStdoutObservedBytes += chunk.byteLength;
                    yield chunk;
                  }
                })(),
              ),
            )
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
      // The writable owns its pipe until child exit; late EPIPE must not become an unhandled event.
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
      if (protocolFailure !== undefined) {
        const observed = supervisor.snapshot();
        throw new ProviderAdapterError(engine, operation, {
          cause: protocolFailure,
          diagnostics: {
            reason:
              protocolFailure instanceof Error
                ? protocolFailure.message
                : String(protocolFailure),
            exit_code: observed.exitCode ?? null,
            signal: observed.signal ?? null,
            stderr: observed.stderr.text,
            stderr_bytes: observed.stderr.bytes,
          },
        });
      }
      checkDiagnostics();
      await assertFirmwareOutputBounds(
        context.boundedOutputFiles ?? [],
        operation,
      );
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
    if (protocolOutput !== undefined) {
      try {
        await protocolOutput;
      } catch (cause: unknown) {
        const observed = supervisor.snapshot();
        throw new ProviderAdapterError(engine, operation, {
          cause,
          diagnostics: {
            reason: cause instanceof Error ? cause.message : String(cause),
            exit_code: observed.exitCode ?? null,
            signal: observed.signal ?? null,
            stderr: observed.stderr.text,
            stderr_bytes: observed.stderr.bytes,
          },
        });
      }
    }
    checkDiagnostics();
    await assertFirmwareOutputBounds(
      context.boundedOutputFiles ?? [],
      operation,
    );
    if (signal.aborted) throw new AnalysisCancelledError(operation);
  } catch (cause: unknown) {
    failure = cause;
  }
  const stopped = await supervisor.stop();
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
        stdout_bytes: snapshot.stdout.bytes,
        stderr_bytes: snapshot.stderr.bytes,
        previous_error: failure instanceof Error ? failure.message : null,
        primary_error:
          failure instanceof AnalysisError
            ? projectAnalysisError(failure)
            : null,
        captured_output: { ...captured, arguments: [...context.args] },
      },
      { operation },
    ).retainCapturedOutput(captured);
  }
  if (failure !== undefined) throw failure;
  if (
    snapshot.exitCode !== 0 &&
    !context.acceptedExitCodes?.includes(snapshot.exitCode ?? -1) &&
    !(
      context.acceptReportedExtractionFailure === true &&
      snapshot.exitCode === 1
    )
  )
    throw new ProviderAdapterError(engine, operation, {
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
    }).retainCapturedOutput(captured);
  return {
    stdout: snapshot.stdout,
    stderr: snapshot.stderr,
    exit_code: snapshot.exitCode,
    signal: snapshot.signal ?? null,
    command: context.command,
    args: [...context.args],
    resource_limiter: context.limiter,
    captured_output: captured,
  };
};

/** Preserve tool failure diagnostics when an accepted exit 1 has no usable report. */
export const readFirmwareCommandReport = async (context: {
  path: string;
  engine: string;
  operation: string;
  execution: Awaited<ReturnType<typeof runFirmwareCommand>>;
  signal?: AbortSignal;
  scope?: ArtifactResourceScope;
}): Promise<unknown> => {
  try {
    return await readFirmwareReport(
      context.path,
      context.operation,
      context.signal,
      context.scope,
    );
  } catch (cause: unknown) {
    if (
      context.signal?.aborted ||
      (cause instanceof AnalysisError && cause.cleanupIncomplete)
    )
      throw cause;
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

/** Bound independently growing reports/artifacts without following producer links. */
export const assertFirmwareOutputBounds = async (
  files: readonly { readonly path: string; readonly maxBytes: number }[],
  operation: string,
): Promise<void> => {
  for (const file of files) {
    const stat = await lstat(file.path).catch((cause: unknown) => {
      if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
        return undefined;
      throw cause;
    });
    if (stat === undefined) continue;
    if (!stat.isFile())
      throw new AnalysisOutputError(
        operation,
        `Private output is not a regular file: ${file.path}`,
      );
    if (stat.size > file.maxBytes)
      throw new AnalysisOutputError(
        operation,
        `Private output exceeded ${file.maxBytes} bytes: ${file.path}`,
      );
  }
};
