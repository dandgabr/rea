import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { join, isAbsolute } from "node:path";
import { z } from "zod";
import type { FirmwareAnalysisPort } from "../application/firmware/FirmwareAnalysisPort.js";
import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import {
  binwalkRegionResultSchema,
  type FirmwareRequest,
  type FirmwarePartialObservation,
} from "../domain/firmware/firmwareAnalysis.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisTimeoutError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { err, ok } from "../domain/result.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import { ArtifactAnalysisResources } from "../process/ArtifactAnalysisResources.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import { readLinuxResourceLimits } from "../process/LinuxResourceLimits.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import type { SafeOutputTree } from "../artifacts/SafeOutputTree.js";
import { publishFirmwareExtraction } from "./FirmwarePublication.js";
import {
  createFirmwareExtractionObservation,
  createFirmwareInspectionObservation,
} from "./FirmwareExtractionObservation.js";
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
} from "./FirmwareCommand.js";
import {
  FirmwareFileCleanupError,
  inventoryFirmwareOutput,
  snapshotFirmware,
} from "./FirmwareFiles.js";
import {
  normalizeBinwalkReport,
  normalizeUnblobReport,
} from "./FirmwareReports.js";

type Outcome = Awaited<ReturnType<FirmwareAnalysisPort["execute"]>>;
interface PendingFirmwareCleanup {
  supervisor?: ProviderProcessSupervisor;
  tree?: SafeOutputTree;
  readonly root: PrivateRuntimeRoot;
  readonly engine: string;
  readonly operation: string;
}

interface FirmwareCleanupAttempt {
  readonly failure: ProviderCleanupError | undefined;
  readonly processUnverified: boolean;
}

const combineCleanupFailures = (
  failures: readonly ProviderCleanupError[],
): ProviderCleanupError | undefined => {
  if (failures.length < 2) return failures[0];
  return new ProviderCleanupError(
    "firmware",
    failures.flatMap((failure) => [...failure.cleanupResources]),
    {
      reason: "Multiple owned firmware resources could not be cleaned",
      failures: failures.map((failure) => ({
        engine: failure.providerId,
        operation: failure.operation,
        resources: [...failure.cleanupResources],
        reason: failure.diagnostics?.reason ?? failure.message,
      })),
    },
    { operation: "close_firmware", cause: new AggregateError(failures) },
  );
};
const limitations = [
  "Signature matches and reported sizes do not establish partition validity, encryption or runtime mappings. Binwalk may infer unknown lengths before emitting its report.",
  "Only Linux is supported by this integration. Configured workers, inherited per-process address-space/file-size/CPU limits and a deadline constrain execution; staging byte and entry budgets are polled and may transiently overshoot. Limits are not aggregate process-memory or filesystem quotas.",
  "Unblob's default sandbox setup is requested, but Landlock can silently fall back; isolation is not attested. Caller-selected skip rules and missing external extractors, unknown chunks, encrypted chunks or depth limits constrain coverage. Trusted installed plugin entrypoints can execute code and access the network before sandbox setup with unknown inventory. Extracted code is never automatically executed; only regular files are published, without executable permission bits.",
  "extraction_gaps lists regions that were carved or left unextracted and names extractor dependencies the producer reported as missing. A listed gap does not mean the target is corrupt or that a retained region is empty.",
  "The actual launcher executable is hashed. Interpreter, shared libraries and installed Python package dependencies are not independently attested; source revision remains unknown for caller-supplied builds.",
] as const;

/** Bring-your-own firmware adapters with one outstanding admission and owned cleanup. */
export class FirmwareProvider implements FirmwareAnalysisPort {
  readonly #resources = new ArtifactAnalysisResources(
    "firmware",
    "firmware_analysis",
    readStableArtifact,
    readLinuxResourceLimits,
    {
      message:
        "A firmware operation is already outstanding; retry after it completes.",
      details: { max_outstanding_operations: 1 },
    },
  );
  readonly #pendingScopes = new Map<
    ArtifactResourceScope,
    {
      resources: readonly string[];
      operation: string;
      workspace: PrivateRuntimeRoot | undefined;
    }
  >();
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
    const admitted = await this.#resources.run(async () => {
      const cleanup = await this.#retryCleanup();
      if (cleanup.processUnverified && cleanup.failure !== undefined)
        return err(cleanup.failure);
      return await this.#execute(request, options);
    }, options?.signal);
    // Resource admission is generic; the adapter binds refusals to this named request.
    if (!admitted.ok) {
      if (
        admitted.error instanceof AnalysisResourceConstraintError &&
        admitted.error.operation === "firmware_analysis"
      )
        return err(
          new AnalysisResourceConstraintError(
            request.operation,
            admitted.error.resource,
            admitted.error.reason,
            admitted.error.reportedLimits,
            { cause: admitted.error },
          ),
        );
      if (
        admitted.error instanceof AnalysisCancelledError &&
        admitted.error.operation === "firmware_analysis"
      )
        return err(
          new AnalysisCancelledError(request.operation, {
            cause: admitted.error,
          }),
        );
    }
    return admitted;
  }

  /** Retry every retained owner, reporting failures without discarding other roots. */
  async close(): Promise<void> {
    await this.#resources.close();
    const cleanup = await this.#retryCleanup();
    if (cleanup.failure !== undefined) throw cleanup.failure;
  }

  async #retryCleanup(): Promise<FirmwareCleanupAttempt> {
    const failures: ProviderCleanupError[] = [];
    const unsettledWorkspaces = new Set<PrivateRuntimeRoot>();
    let processUnverified = false;
    for (const [scope, observation] of this.#pendingScopes) {
      try {
        await scope.retryCleanup();
        this.#pendingScopes.delete(scope);
      } catch (cause: unknown) {
        processUnverified = true;
        if (observation.workspace !== undefined)
          unsettledWorkspaces.add(observation.workspace);
        failures.push(
          new ProviderCleanupError(
            "firmware",
            observation.resources,
            { reason: String(cause) },
            { operation: observation.operation, cause },
          ),
        );
      }
    }
    for (const [path, pending] of this.#pendingCleanup) {
      try {
        const stopped = await pending.supervisor?.stop();
        if (stopped?.status === "incomplete") {
          processUnverified = true;
          failures.push(
            new ProviderCleanupError(
              pending.engine,
              [path],
              { reason: stopped.reason },
              { operation: pending.operation },
            ),
          );
          continue;
        }
        delete pending.supervisor;
      } catch (cause: unknown) {
        processUnverified = true;
        failures.push(
          new ProviderCleanupError(
            pending.engine,
            [path],
            { reason: cause instanceof Error ? cause.message : String(cause) },
            { operation: pending.operation, cause },
          ),
        );
        continue;
      }
      try {
        if (pending.tree !== undefined) {
          await pending.tree.rollback();
          delete pending.tree;
        }
      } catch (cause: unknown) {
        failures.push(
          new ProviderCleanupError(
            pending.engine,
            [path, pending.tree?.outputRoot ?? path],
            { reason: cause instanceof Error ? cause.message : String(cause) },
            { operation: pending.operation, cause },
          ),
        );
      }
      // A failed descriptor scope still depends on this exact invocation's staging.
      // Settled disjoint roots retain their independent cleanup path.
      if (unsettledWorkspaces.has(pending.root)) continue;
      try {
        await pending.root.close();
        if (pending.tree === undefined) this.#pendingCleanup.delete(path);
      } catch (cause: unknown) {
        // A verified stopped process cannot use this root. Keep ownership for
        // later removal without blocking a new operation's disjoint workspace.
        failures.push(
          new ProviderCleanupError(
            pending.engine,
            [path],
            { reason: cause instanceof Error ? cause.message : String(cause) },
            { operation: pending.operation, cause },
          ),
        );
      }
    }
    return { failure: combineCleanupFailures(failures), processUnverified };
  }

  async #execute(
    request: FirmwareRequest,
    options?: ExecutionOptions,
  ): Promise<Outcome> {
    const scope = new ArtifactResourceScope();
    let root: PrivateRuntimeRoot | undefined;
    let prepublicationObservation: FirmwarePartialObservation | undefined;
    const engineName = request.input.provider_id;
    const deadline = AbortSignal.timeout(FIRMWARE_LIMITS.timeoutMs);
    const signal =
      options?.signal === undefined
        ? deadline
        : AbortSignal.any([options.signal, deadline]);
    let outcome: Outcome;
    try {
      if (signal.aborted) throw new AnalysisCancelledError(request.operation);
      if (
        request.input.provider_id === "unblob" &&
        request.input.options.plugins_path !== undefined
      )
        throw firmwareToolUnavailable(
          engineName,
          request.operation,
          "Explicit trusted plugin identity is not yet implemented by this firmware adapter",
        );
      const command = await resolveFirmwareCommand(
        this.environment,
        engineName,
        request.operation,
        signal,
        scope,
      );
      signal.throwIfAborted();
      root = await PrivateRuntimeRoot.create({ prefix: "rea-firmware-" });
      const ownedRoot = root;
      signal.throwIfAborted();
      const target = await snapshotFirmware(request, root.path, signal, scope);
      const run = (
        args: readonly string[],
        outputBudget?: { root: string; bytes: number; entries: number },
      ) =>
        runFirmwareCommand({
          engine: engineName,
          operation: request.operation,
          ...command,
          args,
          cwd: root?.path ?? "",
          environment: this.environment,
          signal,
          retainCleanup: (supervisor) => {
            this.#pendingCleanup.set(ownedRoot.path, {
              supervisor,
              root: ownedRoot,
              engine: engineName,
              operation: request.operation,
            });
          },
          ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
          ...(outputBudget === undefined
            ? {}
            : { outputBudget, acceptReportedExtractionFailure: true }),
        });
      const versionRun = await run(["--version"]);
      const version = versionRun.stdout.text.trim();
      if (versionRun.stdout.bytes > 1024)
        throw firmwareToolUnavailable(
          engineName,
          request.operation,
          `Tool version banner is ${String(versionRun.stdout.bytes)} bytes; expected a short ${engineName} version line.`,
        );
      const admitted = admitFirmwareVersion(engineName, version);
      if (admitted.status === "unsupported" || admitted.status === "unresolved")
        throw firmwareToolUnavailable(
          engineName,
          request.operation,
          admitted.message,
        );
      const engine = {
        name: engineName,
        version: admitted.version,
        executable_path: command.command,
        ...(command.resolvedCommand === command.command
          ? {}
          : { resolved_executable_path: command.resolvedCommand }),
        executable_sha256: command.sha256,
        source_revision: null,
        worker_count:
          request.input.provider_id === "unblob"
            ? request.input.options.workers
            : 1,
      };
      const reportPath = join(root.path, "report.json");
      let result: unknown;
      let raw: unknown;
      if (
        request.operation === "inspect_firmware_regions" &&
        request.input.provider_id === "binwalk"
      ) {
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
          signal,
          scope,
          path: reportPath,
          engine: engineName,
          operation: request.operation,
          execution: processRun,
        });
        result = binwalkRegionResultSchema.parse({
          engine,
          input_size: target.size,
          ...(request.input.range === undefined
            ? {}
            : { selection: target.selection }),
          regions: normalizeBinwalkReport(report, target.inputPath, {
            inputSize: target.size,
            ...(request.input.range === undefined
              ? {}
              : { selection: target.selection }),
          }),
          coverage: "signature_scan",
        });
        raw = { report, execution: processRun, version_execution: versionRun };
      } else {
        if (
          request.operation === "extract_firmware" &&
          !isAbsolute(request.input.output_directory)
        )
          throw new AnalysisInputError(request.operation, undefined, [
            {
              path: ["output_directory"],
              reason: "invalid_format",
              message: "Extraction output directory must be absolute",
            },
          ]);
        const outputRoot = join(root.path, "extracted");
        const nativeOptions = unblobExecutionOptions(request);
        const maxDepth =
          request.operation === "extract_firmware"
            ? request.input.max_depth
            : 1;
        const outputBytes =
          request.operation === "extract_firmware"
            ? request.input.max_output_bytes
            : 256 * 1024 * 1024;
        const outputFiles =
          request.operation === "extract_firmware"
            ? request.input.max_output_files
            : 10_000;
        const processRun = await run(
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
          {
            root: outputRoot,
            bytes: outputBytes,
            entries: outputFiles,
          },
        );
        const report = await readFirmwareCommandReport({
          signal,
          scope,
          path: reportPath,
          engine: engineName,
          operation: request.operation,
          execution: processRun,
        });
        const normalized = normalizeUnblobReport(report, {
          operation: request.operation,
          inputPath: target.inputPath,
          outputRoot,
          ...target.selection,
          maxDepth,
          skipMagic: nativeOptions.skipMagic,
          skipExtensions: nativeOptions.skipExtensions,
        });
        raw = { report, execution: processRun, version_execution: versionRun };
        const observation =
          request.operation === "extract_firmware"
            ? createFirmwareExtractionObservation({
                outputDirectory: request.input.output_directory,
                normalized,
                selection: target.selection,
                engine,
              })
            : createFirmwareInspectionObservation({
                engine,
                inputSize: target.size,
                selection: target.selection,
                normalized,
              });
        prepublicationObservation = {
          ...observation,
          provenance: jsonValueSchema.parse({
            raw_result: raw,
            provider: {
              ...UNBLOB_PROVIDER_IDENTITY,
              version: admitted.version,
            },
            subject: target.subject,
            locations: [
              {
                kind: "file-offset-range",
                start: target.selection.offset,
                end: target.selection.offset + target.selection.length,
              },
            ],
            limitations: [
              ...limitations,
              ...(admitted.status === "compatible"
                ? [admitted.limitation]
                : []),
            ],
          }),
        };
        if (processRun.exit_code === 1 && normalized.diagnostics.length === 0)
          throw new AnalysisOutputError(
            request.operation,
            "Unblob failed without a reported extraction diagnostic",
          );
        if (request.operation === "inspect_firmware_regions") {
          result = observation.result;
        } else {
          const entries = await inventoryFirmwareOutput(
            outputRoot,
            request.input.max_output_bytes,
            request.input.max_output_files,
            request.operation,
            signal,
          );
          result = await publishFirmwareExtraction({
            outputDirectory: request.input.output_directory,
            entries,
            normalized,
            observation: prepublicationObservation,
            selection: target.selection,
            maxDepth,
            engine,
            signal,
            scope,
            retainCleanup: (tree) => {
              const pending: PendingFirmwareCleanup = this.#pendingCleanup.get(
                ownedRoot.path,
              ) ?? {
                root: ownedRoot,
                engine: engineName,
                operation: request.operation,
              };
              pending.tree = tree;
              this.#pendingCleanup.set(ownedRoot.path, pending);
            },
          });
        }
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
            subject: target.subject,
            rawResult: raw,
            limitations: [
              ...limitations,
              ...(admitted.status === "compatible"
                ? [admitted.limitation]
                : []),
            ],
            locations: [
              {
                kind: "file-offset-range",
                start: target.selection.offset,
                end: target.selection.offset + target.selection.length,
              },
            ],
          },
        ),
      );
    } catch (cause: unknown) {
      let nested: unknown = cause;
      const seen = new Set<unknown>();
      while (nested instanceof Error && !seen.has(nested)) {
        seen.add(nested);
        if (nested instanceof FirmwareFileCleanupError)
          this.#pendingScopes.set(nested.resourceScope, {
            resources: nested.cleanupResources,
            operation: request.operation,
            workspace: root,
          });
        nested = nested.cause;
      }
      outcome = err(
        cause instanceof AnalysisError && cause.cleanupIncomplete
          ? cause
          : options?.signal?.aborted === true
            ? new AnalysisCancelledError(request.operation)
            : deadline.aborted
              ? new AnalysisTimeoutError(
                  request.operation,
                  FIRMWARE_LIMITS.timeoutMs,
                )
              : cause instanceof AnalysisError
                ? cause
                : cause instanceof z.ZodError
                  ? new AnalysisOutputError(
                      request.operation,
                      "Tool report violated the pinned producer protocol",
                      { cause },
                    )
                  : new ProviderAdapterError(engineName, request.operation, {
                      cause,
                      diagnostics: {
                        reason:
                          cause instanceof Error
                            ? cause.message
                            : String(cause),
                      },
                    }),
      );
      if (!outcome.ok && prepublicationObservation !== undefined)
        outcome.error.retainPartialObservation(prepublicationObservation);
    }
    const finished = await finishFirmwareWorkspace(
      root,
      outcome,
      engineName,
      request,
    );
    if (
      !finished.ok &&
      finished.error.cleanupIncomplete &&
      root !== undefined &&
      !this.#pendingCleanup.has(root.path)
    )
      this.#pendingCleanup.set(root.path, {
        root,
        engine: engineName,
        operation: request.operation,
      });
    return finished;
  }
}

/** Keep a completed extraction beside cleanup failure, or skip removal when ownership is uncertain. */
export const finishFirmwareWorkspace = async (
  root: { readonly path: string; close(): Promise<void> } | undefined,
  outcome: Outcome,
  engineName: string,
  request: FirmwareRequest,
): Promise<Outcome> => {
  if (!outcome.ok && outcome.error.cleanupIncomplete) {
    if (
      root === undefined ||
      outcome.error.cleanupResources.includes(root.path)
    )
      return outcome;
    return err(
      new ProviderCleanupError(
        engineName,
        [...outcome.error.cleanupResources, root.path],
        outcome.error instanceof ProviderAdapterError
          ? (outcome.error.diagnostics ?? { reason: outcome.error.message })
          : { reason: outcome.error.message },
        {
          cause: outcome.error,
          operation: request.operation,
          ...(outcome.error.capturedOutput === undefined
            ? {}
            : { capturedOutput: outcome.error.capturedOutput }),
          ...(outcome.error.partialObservation === undefined
            ? {}
            : { partialObservation: outcome.error.partialObservation }),
        },
      ),
    );
  }
  try {
    await root?.close();
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
    return err(
      outcome.ok
        ? cleanup
        : analysisErrorWithCleanupFailure(
            outcome.error,
            cleanup,
            request.operation,
          ),
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
