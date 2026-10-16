import { createHash } from "node:crypto";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { join, isAbsolute } from "node:path";
import { Readable } from "node:stream";
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
import { SafeOutputTree } from "../artifacts/SafeOutputTree.js";
import { publishFirmwareExtraction } from "./FirmwarePublication.js";
import {
  readUnblobSystemdFrames,
  type UnblobSystemdFrame,
} from "./UnblobSystemdProtocol.js";
import {
  createFirmwareExtractionObservation,
  createFirmwareInspectionObservation,
} from "./FirmwareExtractionObservation.js";
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
  FirmwareFileCleanupError,
  inventoryFirmwareOutput,
  snapshotFirmware,
  type UnpublishedFirmwareEntry,
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
  "Listed extraction gaps describe unexamined or unpublished coverage; they do not establish target corruption or an empty filesystem.",
  "Signature matches and reported sizes do not establish partition validity, encryption or runtime mappings. Binwalk may infer unknown lengths before emitting its report.",
  "Only Linux is supported by this integration. Binwalk's address-space/file-size/CPU limits are per process; its output budgets are polled and may transiently overshoot. Unblob is separately confined to an exact systemd unit with aggregate MemoryMax, task, CPU, runtime and tmpfs byte/inode ceilings.",
  "When using Unblob, inventory, inspection and bounded extraction are exposed when its absolute command and runtime paths are configured; current-head live CLI/MCP/systemd acceptance remains unverified. Each request performs runtime admission and requires a protected runtime whose interpreter, Python import roots and ancestors are not owned or writable by the invoking user, plus user systemd and cgroup v2. The producer is confined to an exact service with aggregate MemoryMax, task, CPU, runtime and tmpfs byte/inode ceilings. Startup hooks and distribution metadata are audited before importing Unblob; custom hooks and installed unblob_v1 entrypoints are rejected, and Pluggy entrypoint loading is disabled. Caller-container execution is unavailable because its exact inode quota and lifecycle ownership cannot be proven. Provider inventory, source revision and processing influence remain unknown; coverage is partial. Caller-selected skip rules, missing extractors, unknown or encrypted chunks, and depth limits further constrain coverage. Extracted code is never automatically executed; only regular files are published without executable permission bits.",
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
    let producerTree: SafeOutputTree | undefined;
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
        engineName === "unblob" &&
        request.input.runtime?.kind === "container"
      )
        throw firmwareToolUnavailable(
          engineName,
          request.operation,
          "Unblob caller-container runtime is unavailable because REA cannot prove the selected container's systemd/cgroup limits, tmpfs byte and inode quotas, or lifecycle ownership; no native fallback is attempted",
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
      const target =
        request.operation === "inspect_firmware_provider"
          ? undefined
          : await snapshotFirmware(request, root.path, signal, scope);
      const run = async (
        args: readonly string[],
        outputBudget?: { root: string; bytes: number; entries: number },
        acceptExitOne = false,
        consumeStdout?: (stream: Readable) => Promise<unknown>,
      ) => {
        return runFirmwareCommand({
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
          ...(consumeStdout === undefined ? {} : { consumeStdout }),
          ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
          acceptReportedExtractionFailure:
            acceptExitOne || outputBudget !== undefined,
          ...(outputBudget === undefined ? {} : { outputBudget }),
        });
      };
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
      const version = versionRun.stdout.text.trim();
      if (versionRun.stdout.bytes > 1024)
        throw firmwareToolUnavailable(
          engineName,
          request.operation,
          `Tool version banner is ${String(versionRun.stdout.bytes)} bytes; expected a short ${engineName} version line.`,
        ).retainCapturedOutput(versionCapturedOutput);
      if (versionRun.stdout.invalidUtf8 === true)
        throw new AnalysisOutputError(
          request.operation,
          "Tool version is not valid UTF-8",
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
        ...(command.resolvedCommand === command.command
          ? {}
          : { resolved_executable_path: command.resolvedCommand }),
        executable_sha256: command.sha256,
        source_revision: null,
        worker_count:
          engineName === "unblob" &&
          request.operation !== "inspect_firmware_provider"
            ? request.input.options.workers
            : 1,
      };
      if (request.operation === "inspect_firmware_provider") {
        const inventoryRaw: Record<string, unknown> = {
          version_execution: versionRun,
        };
        let inventoryResult: Record<string, unknown> = {
          provider_id: "unblob",
          engine,
          dependency_readiness: "unknown",
          format_inventory_coverage: "partial",
        };
        const retainInventory = () => {
          inventoryResult = { ...inventoryResult, engine };
          prepublicationObservation = {
            kind: "firmware",
            result: jsonValueSchema.parse(inventoryResult),
            provenance: jsonValueSchema.parse({
              raw_result: inventoryRaw,
              subject: null,
              provider: {
                ...UNBLOB_PROVIDER_IDENTITY,
                version: admitted.version,
              },
            }),
          };
        };
        const runInventory = async (...args: Parameters<typeof run>) => {
          retainInventory();
          try {
            return await run(...args);
          } finally {
            retainInventory();
          }
        };
        retainInventory();
        const dependenciesRun = await runInventory(
          ["--show-external-dependencies"],
          undefined,
          true,
        );
        inventoryRaw.dependency_execution = dependenciesRun;
        retainInventory();
        if (dependenciesRun.stdout.invalidUtf8 === true)
          throw new AnalysisOutputError(
            request.operation,
            "Native dependency inventory is not valid UTF-8",
            {
              capturedOutput: {
                stdout: dependenciesRun.stdout.text,
                stderr: dependenciesRun.stderr.text,
                truncated: false,
                stdout_bytes: dependenciesRun.stdout.bytes,
                stdout_utf8_valid: false,
              },
            },
          );
        inventoryResult = normalizeUnblobInventory(dependenciesRun, "", engine);
        retainInventory();
        const documentationPath = join(root.path, "handlers.md");
        const documentationRun = await runInventory([
          "--build-handlers-doc",
          documentationPath,
        ]);
        inventoryRaw.documentation_execution = documentationRun;
        retainInventory();
        const documentation = await readUnblobDocumentation(
          documentationPath,
          signal,
          scope,
        );
        inventoryRaw.documentation = documentation;
        inventoryResult = normalizeUnblobInventory(
          dependenciesRun,
          documentation,
          engine,
        );
        retainInventory();
        outcome = ok(
          createAnalysisExecution(
            inventoryResult,
            { ...UNBLOB_PROVIDER_IDENTITY, version: admitted.version },
            {
              rawResult: {
                version_execution: versionRun,
                dependency_execution: dependenciesRun,
                documentation_execution: documentationRun,
                documentation,
              },
              limitations: [
                ...limitations,
                "Dependency marks report executable lookup, not working extractors. Native public documentation omits handlers without public DOC metadata.",
              ],
            },
          ),
        );
      } else {
        if (target === undefined) throw new Error("Missing firmware snapshot");
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
          raw = {
            report,
            execution: processRun,
            version_execution: versionRun,
          };
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
          const nativeOptions = unblobExecutionOptions(request);
          const maxDepth =
            request.operation === "extract_firmware"
              ? request.input.max_depth
              : 1;
          const outputRoot = "/tmp/rea-extracted";
          let frameResult:
            | Extract<UnblobSystemdFrame, { type: "result" }>
            | undefined;
          const unpublishedFrames: UnpublishedFirmwareEntry[] = [];
          let frameFileCount = 0;
          let frameFileBytes = 0;
          if (request.operation === "extract_firmware")
            producerTree = await SafeOutputTree.create(
              join(root.path, "unblob-transfer-stage"),
            );
          const extractionArgs =
            request.operation === "extract_firmware"
              ? [
                  ...nativeOptions.args,
                  "--extract-dir",
                  join(root.path, "extracted"),
                  "--force",
                  "--report",
                  reportPath,
                  target.inputPath,
                ]
              : [
                  ...nativeOptions.args,
                  "--skip-extraction",
                  "--force",
                  "--report",
                  reportPath,
                  "--log",
                  join(root.path, "unblob.log"),
                  target.inputPath,
                ];
          const rawProcessRun = await run(
            extractionArgs,
            undefined,
            request.operation === "extract_firmware",
            request.operation === "extract_firmware"
              ? async (stream) => {
                  for await (const frame of readUnblobSystemdFrames(stream, {
                    maxBytes: Math.min(
                      request.input.max_output_bytes,
                      FIRMWARE_LIMITS.extractionBytes,
                    ),
                    maxEntries: Math.min(
                      request.input.max_output_files,
                      FIRMWARE_LIMITS.extractionEntries,
                    ),
                    operation: request.operation,
                    signal,
                  })) {
                    if (frame.type === "result") {
                      frameResult = frame;
                      continue;
                    }
                    if (frame.type === "directory") continue;
                    if (frame.type === "unpublished") {
                      unpublishedFrames.push({
                        relativePath: frame.relativePath,
                        path: "",
                        size: frame.size,
                        kind: frame.kind,
                        linkTarget: frame.linkTarget,
                      });
                      continue;
                    }
                    frameFileCount += 1;
                    frameFileBytes += frame.size;
                    if (
                      frameFileCount > request.input.max_output_files ||
                      frameFileBytes > request.input.max_output_bytes
                    )
                      throw new AnalysisOutputError(
                        request.operation,
                        "Unblob framed output exceeded the caller's extraction budget",
                      );
                    const stage = producerTree;
                    if (stage === undefined)
                      throw new AnalysisOutputError(
                        request.operation,
                        "Unblob extraction staging tree is unavailable",
                      );
                    await stage.write(
                      frame.relativePath,
                      Readable.from(frame.bytes),
                      { sha256: frame.sha256, bytes: frame.size },
                      signal,
                    );
                  }
                  if (frameResult === undefined)
                    throw new AnalysisOutputError(
                      request.operation,
                      "Unblob isolation stream omitted its result frame",
                    );
                  return frameResult;
                }
              : undefined,
          );
          const { stdoutResult: _stdoutResult, ...plainProcessRun } =
            rawProcessRun;
          let processRun: FirmwareCommandResult = plainProcessRun;
          if (request.operation === "extract_firmware") {
            const {
              transport_capture: transportCapture,
              diagnostic_truncated: transportDiagnosticTruncated,
              output_incomplete: transportOutputIncomplete,
              exit_code: transportExitCode,
              signal: transportSignal,
              stdout: transportStdout,
              stderr: transportStderr,
              ...guestProcessRun
            } = plainProcessRun;
            frameResult ??= _stdoutResult as
              | Extract<UnblobSystemdFrame, { type: "result" }>
              | undefined;
            if (frameResult === undefined)
              throw new AnalysisOutputError(
                request.operation,
                "Unblob isolation stream produced no framed result",
              );
            let outputMetrics: {
              stdout_observed_bytes: number;
              stderr_observed_bytes: number;
              stdout_truncated: boolean;
              stderr_truncated: boolean;
            };
            try {
              outputMetrics = z
                .object({
                  stdout_observed_bytes: z.number().int().nonnegative(),
                  stderr_observed_bytes: z.number().int().nonnegative(),
                  stdout_truncated: z.boolean(),
                  stderr_truncated: z.boolean(),
                })
                .strict()
                .parse(
                  JSON.parse(
                    new TextDecoder("utf-8", { fatal: true }).decode(
                      frameResult.auxiliary,
                    ),
                  ) as unknown,
                );
            } catch (cause: unknown) {
              throw new AnalysisOutputError(
                request.operation,
                "Unblob output frame has invalid diagnostic accounting",
                { cause },
              );
            }
            const decodeText = (bytes: Buffer) => {
              try {
                return {
                  text: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
                  utf8Valid: true,
                };
              } catch {
                return { text: bytes.toString("utf8"), utf8Valid: false };
              }
            };
            const guestStdout = decodeText(frameResult.stdout);
            const guestStderr = decodeText(frameResult.stderr);
            const guestCapture = {
              stdout: guestStdout.text,
              stderr: guestStderr.text,
              truncated:
                outputMetrics.stdout_truncated ||
                outputMetrics.stderr_truncated,
              stdout_bytes: frameResult.stdout.length,
              stderr_bytes: frameResult.stderr.length,
              stdout_observed_bytes: outputMetrics.stdout_observed_bytes,
              stderr_observed_bytes: outputMetrics.stderr_observed_bytes,
              stdout_sha256: createHash("sha256")
                .update(frameResult.stdout)
                .digest("hex"),
              stderr_sha256: createHash("sha256")
                .update(frameResult.stderr)
                .digest("hex"),
              stdout_utf8_valid: guestStdout.utf8Valid,
              stderr_utf8_valid: guestStderr.utf8Valid,
              exit_code: frameResult.exitCode,
              command: command.command,
              arguments: [...extractionArgs],
            };
            if (!guestStdout.utf8Valid || !guestStderr.utf8Valid)
              throw new AnalysisOutputError(
                request.operation,
                `Unblob framed ${[
                  ...(!guestStdout.utf8Valid ? ["stdout"] : []),
                  ...(!guestStderr.utf8Valid ? ["stderr"] : []),
                ].join(" and ")} is not valid UTF-8`,
                {
                  capturedOutput: guestCapture,
                  diagnostics: {
                    output_source: "unblob_guest_frame",
                    transport_capture: jsonValueSchema.parse(
                      transportCapture ?? null,
                    ),
                  },
                },
              );
            processRun = {
              ...guestProcessRun,
              transport: {
                command: transportCapture?.command ?? null,
                arguments: transportCapture?.arguments ?? null,
                resource_limiter: transportCapture?.command ?? null,
                exit_code: transportExitCode,
                signal: transportSignal,
                stdout: transportStdout,
                stderr: transportStderr,
                captured_output: transportCapture,
                diagnostic_truncated: transportDiagnosticTruncated,
                ...(transportOutputIncomplete === undefined
                  ? {}
                  : { output_incomplete: transportOutputIncomplete }),
              },
              exit_code: frameResult.exitCode,
              signal: null,
              diagnostic_truncated:
                outputMetrics.stdout_truncated ||
                outputMetrics.stderr_truncated,
              stdout: {
                text: guestStdout.text,
                bytes: frameResult.stdout.length,
                observedBytes: outputMetrics.stdout_observed_bytes,
              },
              stderr: {
                text: guestStderr.text,
                bytes: frameResult.stderr.length,
                observedBytes: outputMetrics.stderr_observed_bytes,
              },
              captured_output: guestCapture,
            };
            if (
              outputMetrics.stdout_truncated ||
              outputMetrics.stderr_truncated
            )
              throw new AnalysisOutputError(
                request.operation,
                "Unblob diagnostics exceeded the 8 MiB per-stream frame limit",
                {
                  capturedOutput: {
                    stdout: processRun.stdout.text,
                    stderr: processRun.stderr.text,
                    truncated: true,
                    stdout_bytes: processRun.stdout.bytes,
                    stderr_bytes: processRun.stderr.bytes,
                    stdout_observed_bytes: outputMetrics.stdout_observed_bytes,
                    stderr_observed_bytes: outputMetrics.stderr_observed_bytes,
                    stdout_utf8_valid: true,
                    stderr_utf8_valid: true,
                  },
                },
              );
          }
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
            inputPath: "/tmp/rea-input",
            outputRoot: "/tmp/rea-extracted",
            ...target.selection,
            maxDepth,
            skipMagic: nativeOptions.skipMagic,
            skipExtensions: nativeOptions.skipExtensions,
            pluginsUnverified: true,
          });
          raw = {
            report,
            execution: processRun,
            version_execution: versionRun,
          };
          const observation =
            request.operation === "extract_firmware"
              ? createFirmwareExtractionObservation({
                  outputDirectory: request.input.output_directory,
                  maxDepth,
                  normalized,
                  selection: target.selection,
                  engine,
                  unpublished: unpublishedFrames,
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
            const stagedOutputRoot = producerTree?.outputRoot;
            if (stagedOutputRoot === undefined)
              throw new AnalysisOutputError(
                request.operation,
                "Unblob extraction staging tree was not created",
              );
            const entries = await inventoryFirmwareOutput(
              stagedOutputRoot,
              request.input.max_output_bytes,
              request.input.max_output_files,
              request.operation,
              signal,
            );
            result = await publishFirmwareExtraction({
              outputDirectory: request.input.output_directory,
              entries,
              additionalUnpublished: unpublishedFrames,
              normalized,
              observation: prepublicationObservation,
              maxDepth,
              selection: target.selection,
              engine,
              signal,
              scope,
              retainCleanup: (tree) => {
                const pending: PendingFirmwareCleanup =
                  this.#pendingCleanup.get(ownedRoot.path) ?? {
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
      }
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
            ? new AnalysisCancelledError(request.operation, {
                cause,
                capturedOutput:
                  cause instanceof AnalysisError
                    ? cause.capturedOutput
                    : undefined,
              })
            : deadline.aborted
              ? new AnalysisTimeoutError(
                  request.operation,
                  FIRMWARE_LIMITS.timeoutMs,
                  {
                    cause,
                    capturedOutput:
                      cause instanceof AnalysisError
                        ? cause.capturedOutput
                        : undefined,
                  },
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
    if (producerTree !== undefined) {
      const stagedTree = producerTree;
      try {
        await stagedTree.rollback();
        producerTree = undefined;
      } catch (cause: unknown) {
        const cleanup = new ProviderCleanupError(
          engineName,
          [stagedTree.outputRoot, ...(root === undefined ? [] : [root.path])],
          {
            reason:
              cause instanceof Error
                ? cause.message
                : "Unblob transfer staging cleanup could not be verified",
          },
          {
            operation: request.operation,
            cause,
            ...(prepublicationObservation === undefined
              ? {}
              : { partialObservation: prepublicationObservation }),
          },
        );
        if (outcome.ok && prepublicationObservation !== undefined)
          cleanup.retainPartialObservation(prepublicationObservation);
        outcome = err(cleanup);
        if (root !== undefined)
          this.#pendingCleanup.set(root.path, {
            root,
            tree: stagedTree,
            engine: engineName,
            operation: request.operation,
          });
      }
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
