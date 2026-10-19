import { createHash } from "node:crypto";
import { join, isAbsolute } from "node:path";
import type { FirmwareAnalysisPort } from "../application/firmware/FirmwareAnalysisPort.js";
import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import {
  firmwareResultSchemas,
  type FirmwareRequest,
  type FirmwarePartialObservation,
} from "../domain/firmware/firmwareAnalysis.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { err, ok } from "../domain/result.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import { SafeOutputTree } from "../artifacts/SafeOutputTree.js";
import { Readable } from "node:stream";
import { z } from "zod";
import { publishFirmwareExtraction } from "./FirmwarePublication.js";
import {
  createFirmwareExtractionObservation,
  createFirmwareInspectionObservation,
} from "./FirmwareExtractionObservation.js";
import {
  readUnblobSystemdFrames,
  type UnblobSystemdFrame,
} from "./UnblobSystemdProtocol.js";
import {
  normalizeUnblobInventory,
  readUnblobDocumentation,
} from "./UnblobInventory.js";
import { unblobExecutionOptions } from "./UnblobOptions.js";
import {
  FIRMWARE_LIMITS,
  BINWALK_PROVIDER_IDENTITY,
  UNBLOB_PROVIDER_IDENTITY,
} from "./FirmwareRelease.js";
import { admitFirmwareVersion } from "./FirmwareVersion.js";
import {
  firmwareToolUnavailable,
  resolveFirmwareCommand,
  runFirmwareCommand,
  readFirmwareCommandReport,
  type FirmwareLauncher,
  type FirmwareCommandResult,
} from "./FirmwareCommand.js";
import {
  inventoryFirmwareOutput,
  FirmwareFileAccess,
} from "./FirmwareFiles.js";
import {
  normalizeBinwalkReport,
  normalizeUnblobReport,
} from "./FirmwareReports.js";

import { firmwareFailure, firmwareCancellation } from "./FirmwareFailures.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";

type Outcome = Awaited<ReturnType<FirmwareAnalysisPort["execute"]>>;
interface PendingFirmwareCleanup {
  supervisor?: ProviderProcessSupervisor;
  tree?: {
    readonly tree: SafeOutputTree;
    readonly lease: AnalysisCleanupLease;
  };
  readonly root: PrivateRuntimeRoot;
  readonly rootLease: AnalysisCleanupLease;
  readonly engine: string;
  readonly operation: string;
}

const bindWorkspaceFailure = (
  pending: PendingFirmwareCleanup,
  failure: AnalysisError,
): AnalysisError => {
  pending.rootLease.bindCleanupError(failure);
  return failure;
};

interface FirmwareCleanupAttempt {
  readonly failure: AnalysisError | undefined;
  readonly executionBlocked: boolean;
}

const combineCleanupFailures = (
  failures: readonly AnalysisError[],
): AnalysisError | undefined => {
  if (failures.length < 2) return failures[0];
  return new ProviderCleanupError(
    "firmware",
    failures.flatMap((failure) => [...failure.cleanupResources]),
    {
      reason: "Multiple owned firmware resources could not be cleaned",
      failures: failures.map((failure) => ({
        engine:
          failure instanceof ProviderAdapterError
            ? failure.providerId
            : "firmware",
        operation:
          failure instanceof ProviderAdapterError
            ? failure.operation
            : "close_firmware",
        resources: [...failure.cleanupResources],
        reason: failure.diagnostics?.reason ?? failure.message,
      })),
    },
    { operation: "close_firmware", cause: new AggregateError(failures) },
  ).bindCleanupDependencies(failures);
};
const waitForPredecessor = (
  predecessor: Promise<void>,
  operation: string,
  signal?: AbortSignal,
): Promise<void> =>
  new Promise((resolve, reject) => {
    const abort = () =>
      reject(new AnalysisCancelledError(operation, { cause: signal?.reason }));
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted === true) abort();
    void predecessor.then(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    });
  });
const commonLimitations = [
  "Signature matches and reported sizes do not establish partition validity, encryption or runtime mappings.",
  "extraction_gaps lists regions that were carved or left unextracted and names extractor dependencies the producer reported as missing. A listed gap does not mean the target is corrupt or that a retained region is empty.",
] as const;
const binwalkLimitations = [
  "Binwalk may infer unknown lengths before emitting its report. Only Linux is supported. One worker, inherited per-process address-space/file-size/CPU limits and a deadline constrain execution; staging byte and entry budgets are polled and may transiently overshoot. Limits are not aggregate process-memory or filesystem quotas.",
] as const;
const unblobLimitations = [
  "Native Unblob availability is exposed when REA_UNBLOB_COMMAND and REA_UNBLOB_RUNTIME_ROOT are configured. Each request performs runtime admission and uses a systemd user service with configured resource and isolation controls; caller-container execution is unavailable. Current-head live CLI/MCP/systemd acceptance remains unverified, and #4110 final ratification is pending.",
  "Unblob's default sandbox and skip rules remain enabled. Missing external extractors, unknown chunks, encrypted chunks and depth limits yield partial coverage. Extracted code is never executed; only regular files are published, without executable permission bits.",
  "The actual launcher executable is hashed. Interpreter, shared libraries and installed Python package dependencies are not independently attested; source revision remains unknown for caller-supplied builds.",
] as const;

const decodeUnblobFrameText = (
  bytes: Buffer,
): { readonly text: string; readonly invalidUtf8: boolean } => {
  try {
    return {
      text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
        bytes,
      ),
      invalidUtf8: false,
    };
  } catch {
    return { text: bytes.toString("utf8"), invalidUtf8: true };
  }
};

const unblobGuestExecution = (
  transport: FirmwareCommandResult,
  frame: Extract<UnblobSystemdFrame, { type: "result" }>,
  operation: string,
): FirmwareCommandResult => {
  let metrics: {
    readonly stdout_observed_bytes: number;
    readonly stderr_observed_bytes: number;
    readonly stdout_truncated: boolean;
    readonly stderr_truncated: boolean;
  };
  try {
    metrics = z
      .strictObject({
        stdout_observed_bytes: z.number().int().nonnegative(),
        stderr_observed_bytes: z.number().int().nonnegative(),
        stdout_truncated: z.boolean(),
        stderr_truncated: z.boolean(),
      })
      .parse(
        JSON.parse(
          new TextDecoder("utf-8", { fatal: true }).decode(frame.auxiliary),
        ) as unknown,
      );
  } catch (cause: unknown) {
    throw new AnalysisOutputError(
      operation,
      "Unblob isolation stream contains invalid diagnostic metadata",
      {
        cause,
        diagnostics: {
          output_source: "unblob_guest_frame",
          transport_capture: jsonValueSchema.parse(
            transport.transport_capture ?? null,
          ),
        },
      },
    );
  }
  const stdout = decodeUnblobFrameText(frame.stdout);
  const stderr = decodeUnblobFrameText(frame.stderr);
  const captured = {
    stdout: stdout.text,
    stderr: stderr.text,
    truncated: metrics.stdout_truncated || metrics.stderr_truncated,
    stdout_bytes: frame.stdout.byteLength,
    stderr_bytes: frame.stderr.byteLength,
    stdout_observed_bytes: metrics.stdout_observed_bytes,
    stderr_observed_bytes: metrics.stderr_observed_bytes,
    stdout_sha256: createHash("sha256").update(frame.stdout).digest("hex"),
    stderr_sha256: createHash("sha256").update(frame.stderr).digest("hex"),
    stdout_utf8_valid: !stdout.invalidUtf8,
    stderr_utf8_valid: !stderr.invalidUtf8,
    exit_code: frame.exitCode,
    command: transport.command,
    arguments: [...transport.args],
  };
  if (metrics.stdout_truncated || metrics.stderr_truncated)
    throw new AnalysisOutputError(
      operation,
      "Unblob diagnostics exceeded the 8 MiB per-stream frame limit",
      { capturedOutput: captured },
    );
  if (stdout.invalidUtf8 || stderr.invalidUtf8)
    throw new AnalysisOutputError(
      operation,
      `Unblob framed ${[
        ...(stdout.invalidUtf8 ? ["stdout"] : []),
        ...(stderr.invalidUtf8 ? ["stderr"] : []),
      ].join(" and ")} is not valid UTF-8`,
      {
        capturedOutput: captured,
        diagnostics: {
          output_source: "unblob_guest_frame",
          transport_capture: jsonValueSchema.parse(
            transport.transport_capture ?? null,
          ),
        },
      },
    );
  const {
    stdoutResult: _stdoutResult,
    transport_capture: transportCapture,
    diagnostic_truncated: transportTruncated,
    output_incomplete: transportIncomplete,
    exit_code: transportExitCode,
    signal: transportSignal,
    stdout: transportStdout,
    stderr: transportStderr,
    ...guest
  } = transport;
  return {
    ...guest,
    exit_code: frame.exitCode,
    signal: null,
    diagnostic_truncated: false,
    stdout: {
      text: stdout.text,
      bytes: frame.stdout.byteLength,
      observedBytes: metrics.stdout_observed_bytes,
    },
    stderr: {
      text: stderr.text,
      bytes: frame.stderr.byteLength,
      observedBytes: metrics.stderr_observed_bytes,
    },
    captured_output: captured,
    transport: {
      command: transportCapture?.command ?? null,
      arguments: transportCapture?.arguments ?? null,
      resource_limiter: transport.resource_limiter ?? null,
      exit_code: transportExitCode ?? null,
      signal: transportSignal,
      stdout: transportStdout,
      stderr: transportStderr,
      captured_output: transportCapture ?? null,
      diagnostic_truncated: transportTruncated,
      ...(transportIncomplete === undefined
        ? {}
        : { output_incomplete: transportIncomplete }),
    },
  };
};

/** Queued bring-your-own firmware adapters with private snapshots and owned cleanup. */
export class FirmwareProvider implements FirmwareAnalysisPort {
  #tail: Promise<void> = Promise.resolve();
  #closed = false;
  #closing: Promise<void> | undefined;
  readonly #files = new FirmwareFileAccess();
  readonly #pendingCleanup = new Map<string, PendingFirmwareCleanup>();
  constructor(
    readonly environment: Readonly<
      Record<string, string | undefined>
    > = process.env,
    readonly launcher?: FirmwareLauncher,
  ) {}

  /** Inspect regions or explicitly extract selected bytes without changing the source. */
  async execute(
    request: FirmwareRequest,
    options?: ExecutionOptions,
  ): Promise<Outcome> {
    if (this.#closed) return err(new AnalysisCancelledError(request.operation));
    const predecessor = this.#tail;
    let release = () => {};
    this.#tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    // Cancel the caller promptly without letting a later request bypass its predecessor.
    try {
      await waitForPredecessor(predecessor, request.operation, options?.signal);
    } catch (cause: unknown) {
      void predecessor.then(release);
      return err(
        cause instanceof AnalysisError
          ? cause
          : new AnalysisCancelledError(request.operation),
      );
    }
    try {
      if (this.#closed)
        return err(new AnalysisCancelledError(request.operation));
      const cleanup = await this.#retryCleanup();
      if (cleanup.executionBlocked && cleanup.failure !== undefined)
        return err(cleanup.failure);
      return await this.#execute(request, options);
    } finally {
      release();
    }
  }

  /** Retry every retained owner, reporting failures without discarding other roots. */
  close(): Promise<void> {
    this.#closed = true;
    return (this.#closing ??= this.#close().finally(() => {
      this.#closing = undefined;
    }));
  }

  async #close(): Promise<void> {
    await this.#tail;
    const failures: AnalysisError[] = [];
    try {
      await this.#files.close();
    } catch (cause: unknown) {
      failures.push(firmwareFailure(cause, "firmware", "close_firmware"));
    }
    const workspace = await this.#retryWorkspaceCleanup();
    if (workspace.failure !== undefined) failures.push(workspace.failure);
    const failure = combineCleanupFailures(failures);
    if (failure !== undefined) throw failure;
  }

  async #retryCleanup(): Promise<FirmwareCleanupAttempt> {
    let fileFailure: AnalysisError | undefined;
    try {
      await this.#files.retryCleanup();
    } catch (cause: unknown) {
      fileFailure = firmwareFailure(cause, "firmware", "close_firmware");
    }
    const workspace = await this.#retryWorkspaceCleanup();
    return {
      failure: combineCleanupFailures([
        ...(fileFailure === undefined ? [] : [fileFailure]),
        ...(workspace.failure === undefined ? [] : [workspace.failure]),
      ]),
      executionBlocked: fileFailure !== undefined || workspace.executionBlocked,
    };
  }

  async #retryWorkspaceCleanup(): Promise<FirmwareCleanupAttempt> {
    const failures: AnalysisError[] = [];
    let executionBlocked = false;
    for (const [path, pending] of this.#pendingCleanup) {
      try {
        const stopped = await pending.supervisor?.stop();
        if (stopped?.status === "incomplete") {
          executionBlocked = true;
          failures.push(
            bindWorkspaceFailure(
              pending,
              new ProviderCleanupError(
                pending.engine,
                [path],
                { reason: stopped.reason },
                { operation: pending.operation },
              ),
            ),
          );
          continue;
        }
        delete pending.supervisor;
      } catch (cause: unknown) {
        executionBlocked = true;
        failures.push(
          bindWorkspaceFailure(
            pending,
            new ProviderCleanupError(
              pending.engine,
              [path],
              {
                reason: cause instanceof Error ? cause.message : String(cause),
              },
              { operation: pending.operation, cause },
            ),
          ),
        );
        continue;
      }
      try {
        if (pending.tree !== undefined) {
          await pending.tree.lease.release();
          delete pending.tree;
        }
      } catch (cause: unknown) {
        failures.push(
          bindWorkspaceFailure(
            pending,
            new ProviderCleanupError(
              pending.engine,
              [path, pending.tree?.tree.outputRoot ?? path],
              {
                reason: cause instanceof Error ? cause.message : String(cause),
              },
              { operation: pending.operation, cause },
            ),
          ),
        );
      }
      if (pending.tree !== undefined) continue;
      try {
        await pending.rootLease.release();
        this.#pendingCleanup.delete(path);
      } catch (cause: unknown) {
        // A verified stopped process cannot use this root. Keep ownership for
        // later removal without blocking a new operation's disjoint workspace.
        failures.push(
          bindWorkspaceFailure(
            pending,
            new ProviderCleanupError(
              pending.engine,
              [path],
              {
                reason: cause instanceof Error ? cause.message : String(cause),
              },
              { operation: pending.operation, cause },
            ),
          ),
        );
      }
    }
    return { failure: combineCleanupFailures(failures), executionBlocked };
  }

  async #execute(
    request: FirmwareRequest,
    options?: ExecutionOptions,
  ): Promise<Outcome> {
    let root: PrivateRuntimeRoot | undefined;
    let rootLease: AnalysisCleanupLease | undefined;
    let partialObservation: FirmwarePartialObservation | undefined;
    const engineName =
      request.operation === "inspect_firmware_regions" &&
      request.input.provider_id === "binwalk"
        ? "binwalk"
        : "unblob";
    const deadline = AbortSignal.timeout(FIRMWARE_LIMITS.timeoutMs);
    const signal =
      options?.signal === undefined
        ? deadline
        : AbortSignal.any([options.signal, deadline]);
    let outcome: Outcome;
    try {
      if (signal.aborted)
        throw new AnalysisCancelledError(request.operation, {
          cause: signal.reason,
        });
      if (
        engineName === "unblob" &&
        "runtime" in request.input &&
        request.input.runtime?.kind === "container"
      )
        throw firmwareToolUnavailable(
          engineName,
          request.operation,
          "caller-container runtime is unavailable; Unblob currently requires the admitted native runtime",
        );
      const command = await resolveFirmwareCommand(
        this.environment,
        engineName,
        request.operation,
        this.#files,
        signal,
      );
      root = await PrivateRuntimeRoot.create({ prefix: "rea-firmware-" });
      const ownedRoot = root;
      const ownedRootLease = new AnalysisCleanupLease(() => ownedRoot.close());
      rootLease = ownedRootLease;
      const target =
        request.operation === "inspect_firmware_provider"
          ? undefined
          : await this.#files.snapshot(request, root.path, signal);
      const run = (
        args: readonly string[],
        outputBudget?: { root: string; bytes: number; entries: number },
        consumeStdout?: (stream: Readable) => Promise<unknown>,
        acceptReportedExtractionFailure = false,
      ) =>
        runFirmwareCommand({
          engine: engineName,
          operation: request.operation,
          ...command,
          args,
          cwd: root?.path ?? "",
          environment: this.environment,
          signal,
          ...(consumeStdout === undefined ? {} : { consumeStdout }),
          ...(engineName === "unblob"
            ? {
                systemdProfile: {
                  rootDirectory: command.rootDirectory!,
                  executable: command.resolvedCommand,
                  ...(target === undefined
                    ? {}
                    : { inputPath: target.inputPath }),
                  ...(request.operation === "extract_firmware"
                    ? {
                        extractionBudget: {
                          bytes: request.input.max_output_bytes,
                          entries: request.input.max_output_files,
                        },
                      }
                    : {}),
                },
              }
            : {}),
          retainCleanup: (supervisor) => {
            this.#pendingCleanup.set(ownedRoot.path, {
              supervisor,
              root: ownedRoot,
              rootLease: ownedRootLease,
              engine: engineName,
              operation: request.operation,
            });
          },
          ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
          ...(outputBudget === undefined
            ? {}
            : { outputBudget, acceptReportedExtractionFailure: true }),
          ...(acceptReportedExtractionFailure
            ? { acceptReportedExtractionFailure: true }
            : {}),
        });
      const versionRun = await run(["--version"]);
      const versionCapturedOutput = versionRun.captured_output ?? {
        stdout: versionRun.stdout.text,
        stderr: versionRun.stderr.text,
        truncated: versionRun.diagnostic_truncated,
        stdout_bytes: versionRun.stdout.bytes,
        stderr_bytes: versionRun.stderr.bytes,
        stdout_observed_bytes: versionRun.stdout.observedBytes,
        stderr_observed_bytes: versionRun.stderr.observedBytes,
        stdout_utf8_valid: versionRun.stdout.invalidUtf8 !== true,
        stderr_utf8_valid: versionRun.stderr.invalidUtf8 !== true,
        ...(versionRun.exit_code === undefined
          ? {}
          : { exit_code: versionRun.exit_code }),
        signal: versionRun.signal,
        command: versionRun.command,
        arguments: [...versionRun.args],
      };
      if (versionRun.stdout.invalidUtf8 === true)
        throw new AnalysisOutputError(
          request.operation,
          "Tool version banner is not valid UTF-8",
          { capturedOutput: versionCapturedOutput },
        );
      const version = versionRun.stdout.text.trim();
      if (versionRun.stdout.bytes > 1024)
        throw firmwareToolUnavailable(
          engineName,
          request.operation,
          `Tool version banner is ${String(versionRun.stdout.bytes)} bytes; expected a short ${engineName} version line.`,
        ).retainCapturedOutput(versionCapturedOutput);
      const admitted = admitFirmwareVersion(engineName, version);
      if (admitted.status === "unsupported" || admitted.status === "unresolved")
        throw firmwareToolUnavailable(
          engineName,
          request.operation,
          admitted.message,
        ).retainCapturedOutput(versionCapturedOutput);
      const engine = {
        name: engineName,
        version: admitted.version,
        executable_path: command.command,
        executable_sha256: command.sha256,
        source_revision: null,
        worker_count:
          request.operation === "extract_firmware"
            ? request.input.options.workers
            : request.operation === "inspect_firmware_regions" &&
                request.input.provider_id === "unblob"
              ? request.input.options.workers
              : 1,
      };
      const reportPath = join(root.path, "report.json");
      let result: unknown;
      let raw: unknown;
      if (request.operation === "inspect_firmware_provider") {
        const dependenciesRun = await run(
          ["--show-external-dependencies"],
          undefined,
          undefined,
          true,
        );
        const partialInventory = normalizeUnblobInventory(
          dependenciesRun,
          "",
          engine,
        );
        partialObservation = {
          kind: "firmware",
          result: jsonValueSchema.parse(partialInventory),
        };
        const documentationPath = join(root.path, "handlers.md");
        const documentationRun = await run([
          "--build-handlers-doc",
          documentationPath,
        ]);
        const documentation = await readUnblobDocumentation(
          this.#files,
          documentationPath,
          signal,
        );
        result = normalizeUnblobInventory(
          dependenciesRun,
          documentation,
          engine,
        );
        raw = {
          version_execution: versionRun,
          dependency_execution: dependenciesRun,
          documentation_execution: documentationRun,
          documentation,
        };
      } else if (
        request.operation === "inspect_firmware_regions" &&
        engineName === "binwalk"
      ) {
        if (target === undefined) throw new Error("Missing firmware snapshot");
        const processRun = await run([
          "--quiet",
          "--search-all",
          "--threads",
          "1",
          "--log",
          reportPath,
          target.inputPath,
        ]);
        const report = await readFirmwareCommandReport({
          path: reportPath,
          engine: engineName,
          operation: request.operation,
          execution: processRun,
          files: this.#files,
          signal,
        });
        result = firmwareResultSchemas.inspect_firmware_regions.parse({
          engine,
          input_size: target.size,
          ...(request.input.range === undefined
            ? {}
            : { selection: target.selection }),
          regions: normalizeBinwalkReport(report, target.inputPath, {
            inputSize: target.size,
            ...(request.operation === "inspect_firmware_regions" &&
            request.input.range !== undefined
              ? { selection: target.selection }
              : {}),
          }),
          coverage: "signature_scan",
        });
        raw = { report, execution: processRun, version_execution: versionRun };
      } else if (
        request.operation === "inspect_firmware_regions" &&
        request.input.provider_id === "unblob"
      ) {
        if (target === undefined) throw new Error("Missing firmware snapshot");
        const nativeOptions = unblobExecutionOptions(request);
        const processRun = await run(
          [
            ...nativeOptions.args,
            "--force",
            "--report",
            reportPath,
            "--log",
            join(root.path, "unblob.log"),
            target.inputPath,
          ],
          undefined,
          undefined,
          true,
        );
        const report = await readFirmwareCommandReport({
          path: reportPath,
          engine: engineName,
          operation: request.operation,
          execution: processRun,
          files: this.#files,
          signal,
        });
        const normalized = normalizeUnblobReport(report, {
          inputPath: "/tmp/rea-input",
          outputRoot: "/tmp/rea-extracted",
          ...target.selection,
          maxDepth: 1,
          skipMagic: nativeOptions.skipMagic,
          skipExtensions: nativeOptions.skipExtensions,
          pluginsUnverified: true,
        });
        if (processRun.exit_code === 1 && normalized.diagnostics.length === 0)
          throw new AnalysisOutputError(
            request.operation,
            "Unblob failed without a reported inspection diagnostic",
          );
        const observation = createFirmwareInspectionObservation({
          engine,
          inputSize: target.size,
          selection: target.selection,
          normalized,
        });
        partialObservation = observation;
        result = observation.result;
        raw = { report, execution: processRun, version_execution: versionRun };
      } else {
        if (request.operation !== "extract_firmware" || target === undefined)
          throw new Error("Missing firmware extraction request or snapshot");
        if (!isAbsolute(request.input.output_directory))
          throw new AnalysisInputError(request.operation, undefined, [
            {
              path: ["output_directory"],
              reason: "invalid_format",
              message: "Extraction output directory must be absolute",
            },
          ]);
        const outputRoot = join(root.path, "extracted");
        const nativeOptions = unblobExecutionOptions(request);
        const staging = await SafeOutputTree.create(
          join(root.path, "unblob-transfer-stage"),
        );
        let resultFrame:
          | Extract<UnblobSystemdFrame, { type: "result" }>
          | undefined;
        const unpublished: {
          relativePath: string;
          path: string;
          size: number;
          kind: "symlink" | "special";
          linkTarget: string | null;
        }[] = [];
        const consumeStdout = async (stream: Readable): Promise<unknown> => {
          for await (const frame of readUnblobSystemdFrames(stream, {
            maxBytes: request.input.max_output_bytes,
            maxEntries: request.input.max_output_files,
            operation: request.operation,
            signal,
          })) {
            if (frame.type === "result") {
              resultFrame = frame;
            } else if (frame.type === "file") {
              await staging.write(
                frame.relativePath,
                Readable.from(frame.bytes),
                { sha256: frame.sha256, bytes: frame.size },
                signal,
              );
            } else if (frame.type === "unpublished") {
              unpublished.push({
                relativePath: frame.relativePath,
                path: "",
                size: frame.size,
                kind: frame.kind,
                linkTarget: frame.linkTarget,
              });
            }
          }
          if (resultFrame === undefined)
            throw new AnalysisOutputError(
              request.operation,
              "Unblob isolation stream omitted its result frame",
            );
          return resultFrame;
        };
        const transportRun = await run(
          [
            ...nativeOptions.args,
            "--report",
            reportPath,
            "--log",
            join(root.path, "unblob.log"),
            "--extract-dir",
            outputRoot,
            target.inputPath,
          ],
          undefined,
          consumeStdout,
          true,
        );
        const frame = transportRun.stdoutResult as
          | Extract<UnblobSystemdFrame, { type: "result" }>
          | undefined;
        if (frame === undefined)
          throw new AnalysisOutputError(
            request.operation,
            "Unblob isolation stream produced no result frame",
          );
        const processRun = unblobGuestExecution(
          transportRun,
          frame,
          request.operation,
        );
        const report = frame.rawReport;
        const normalized = normalizeUnblobReport(report, {
          inputPath: "/tmp/rea-input",
          outputRoot: "/tmp/rea-extracted",
          ...target.selection,
          maxDepth: request.input.max_depth,
          skipMagic: nativeOptions.skipMagic,
          skipExtensions: nativeOptions.skipExtensions,
          pluginsUnverified: true,
        });
        if (frame.exitCode === 1 && normalized.diagnostics.length === 0)
          throw new AnalysisOutputError(
            request.operation,
            "Unblob failed without a reported extraction diagnostic",
          );
        const entries = await inventoryFirmwareOutput(
          staging.outputRoot,
          request.input.max_output_bytes,
          request.input.max_output_files,
          request.operation,
          signal,
        );
        const observation = createFirmwareExtractionObservation({
          outputDirectory: request.input.output_directory,
          maxDepth: request.input.max_depth,
          normalized,
          selection: target.selection,
          engine,
          unpublished,
        });
        partialObservation = observation;
        result = await publishFirmwareExtraction({
          files: this.#files,
          workspacePath: root.path,
          deadline,
          outputDirectory: request.input.output_directory,
          entries,
          normalized,
          observation,
          selection: target.selection,
          maxDepth: request.input.max_depth,
          engine,
          signal,
          retainCleanup: (tree, lease, failure) => {
            ownedRootLease.bindCleanupError(failure);
            const pending: PendingFirmwareCleanup = this.#pendingCleanup.get(
              ownedRoot.path,
            ) ?? {
              root: ownedRoot,
              rootLease: ownedRootLease,
              engine: engineName,
              operation: request.operation,
            };
            pending.tree = { tree, lease };
            this.#pendingCleanup.set(ownedRoot.path, pending);
          },
        });
        raw = { report, execution: processRun, version_execution: versionRun };
      }
      const catalog =
        engineName === "binwalk"
          ? BINWALK_PROVIDER_IDENTITY
          : UNBLOB_PROVIDER_IDENTITY;
      outcome = ok(
        createAnalysisExecution(
          result,
          { ...catalog, version: admitted.version },
          {
            rawResult: raw,
            ...(target === undefined ? {} : { subject: target.subject }),
            limitations: [
              ...commonLimitations,
              ...(engineName === "binwalk"
                ? binwalkLimitations
                : unblobLimitations),
              ...(admitted.status === "compatible"
                ? [admitted.limitation]
                : []),
            ],
            ...(target === undefined
              ? {}
              : {
                  locations: [
                    {
                      kind: "file-offset-range" as const,
                      start: target.selection.offset,
                      end: target.selection.offset + target.selection.length,
                    },
                  ],
                }),
          },
        ),
      );
    } catch (cause: unknown) {
      const failure = firmwareFailure(
        cause,
        engineName,
        request.operation,
        deadline,
      );
      if (partialObservation !== undefined)
        failure.retainPartialObservation(partialObservation);
      outcome = err(failure);
    }
    const finished = await finishFirmwareWorkspace(
      root,
      outcome,
      engineName,
      request,
      rootLease,
      signal,
      deadline,
    );
    if (
      !finished.ok &&
      finished.error.cleanupIncomplete &&
      root !== undefined &&
      rootLease !== undefined &&
      finished.error.cleanupResources.includes(root.path) &&
      !this.#pendingCleanup.has(root.path)
    )
      this.#pendingCleanup.set(root.path, {
        root,
        rootLease,
        engine: engineName,
        operation: request.operation,
      });
    if (
      !finished.ok &&
      root !== undefined &&
      rootLease !== undefined &&
      finished.error.cleanupResources.includes(root.path)
    )
      rootLease.bindCleanupError(finished.error);
    if (finished.ok && signal.aborted)
      return err(
        firmwareCancellation(
          request.operation,
          signal.reason,
          deadline,
        ).retainPartialObservation(
          completedFirmwareObservation(finished.value),
        ),
      );
    return finished;
  }
}

/** Keep a completed extraction beside cleanup failure, or skip removal when ownership is uncertain. */
const finishFirmwareWorkspace = async (
  root: { readonly path: string; close(): Promise<void> } | undefined,
  outcome: Outcome,
  engineName: string,
  request: FirmwareRequest,
  rootLease: AnalysisCleanupLease | undefined,
  signal: AbortSignal,
  deadline: AbortSignal,
): Promise<Outcome> => {
  if (
    !outcome.ok &&
    outcome.error.cleanupIncomplete &&
    (root === undefined || outcome.error.cleanupResources.includes(root.path))
  )
    return outcome;
  try {
    await rootLease?.release();
  } catch (cause: unknown) {
    const cleanup = new ProviderCleanupError(
      engineName,
      [
        root?.path ?? "unknown",
        ...(outcome.ok && request.operation === "extract_firmware"
          ? [request.input.output_directory]
          : []),
      ],
      { reason: cause instanceof Error ? cause.message : String(cause) },
      {
        cause,
        operation: request.operation,
        ...(outcome.ok
          ? {
              partialObservation: completedFirmwareObservation(outcome.value),
            }
          : outcome.error.partialObservation === undefined
            ? {}
            : { partialObservation: outcome.error.partialObservation }),
      },
    );
    rootLease?.bindCleanupError(cleanup);
    if (outcome.ok && signal.aborted) {
      const primary = firmwareCancellation(
        request.operation,
        signal.reason,
        deadline,
      );
      primary.retainPartialObservation(
        completedFirmwareObservation(outcome.value),
      );
      return err(
        analysisErrorWithCleanupFailure(
          primary,
          cleanup,
          request.operation,
        ).bindCleanupDependencies([cleanup]),
      );
    }
    return err(
      outcome.ok
        ? cleanup
        : analysisErrorWithCleanupFailure(
            outcome.error,
            cleanup,
            request.operation,
          ).bindCleanupDependencies([outcome.error, cleanup]),
    );
  }
  return outcome;
};

const completedFirmwareObservation = (
  execution: AnalysisExecution,
): FirmwarePartialObservation => ({
  kind: "firmware",
  result: execution.result,
  provenance: jsonValueSchema.parse({
    raw_result: execution.rawResult,
    provider: execution.provider,
    subject: execution.subject,
    locations: execution.locations,
    limitations: execution.limitations,
    ...(execution.analysisProfile === undefined
      ? {}
      : { analysis_profile: execution.analysisProfile }),
  }),
});
