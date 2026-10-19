import {
  AnalysisCleanupLease,
  AnalysisCleanupLeaseGroup,
} from "../../artifacts/AnalysisCleanupLease.js";
import { firmwareFailure, firmwareCancellation } from "../FirmwareFailures.js";
import {
  isBinwalkNgRequest,
  type FirmwareRequest,
} from "../../domain/firmware/firmwareAnalysis.js";
import { binwalkNgResultSchemas } from "../../domain/firmware/binwalkNgResults.js";
import { inspectBinwalkNgRuntime } from "./BinwalkNgInventory.js";
import { ArtifactAnalysisResources } from "../../process/ArtifactAnalysisResources.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { readLinuxResourceLimits } from "../../process/LinuxResourceLimits.js";
import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../../application/AnalysisProvider.js";
import type { BinwalkNgRequest } from "../../domain/firmware/binwalkNgAnalysis.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import {
  firmwareToolUnavailable,
  type FirmwareLauncher,
} from "../FirmwareCommand.js";
import { FirmwareFileAccess } from "../FirmwareFiles.js";
import { BINWALK_NG_RELEASE, FIRMWARE_LIMITS } from "../FirmwareRelease.js";
import { runBinwalkNgWorkflow } from "./BinwalkNgWorkflow.js";
import { requireBinwalkNgTmpfs } from "./BinwalkNgSystemdBoundary.js";

interface OwnedWorkflow {
  root: PrivateRuntimeRoot;
  scope: ArtifactResourceScope;
  files: FirmwareFileAccess;
  operation: string;
  cleanupLease: AnalysisCleanupLease;
  supervisor?: ProviderProcessSupervisor;
  tree?: SafeOutputTree;
}
type Outcome = Result<AnalysisExecution, AnalysisError>;
const limitations = [
  "Signature matches and provider-reported sizes do not establish partition validity, encryption, authentication or runtime mappings. Empty native analyses do not attest a successful read or absence of findings.",
  "The selected binwalk-ng 4.0.0 profile is a compatibility declaration. Runtime executable, selected regular-file mounts, launcher and limiter are fingerprinted; the installed source revision remains unknown. Identity readback is not syscall-level TOCTOU prevention.",
  "Each invocation runs in a dedicated user-systemd cgroup and the exact bubblewrap namespace/mount policy. Effective cgroup v2 memory, swap, task and CPU limits are read back in-unit before execution. The manager environment is enumerated by name and removed from the service; selected runtime files and immutable input alone are readable inside bubblewrap.",
  "The private work tree must be tmpfs; producer writes are charged to the same 512 MiB cgroup memory ceiling. Individual report/PNG reads remain capped at 8 MiB and captures are separately bounded. This is not a caller-configurable 512 MiB output quota.",
  "Extraction is admitted only when a complete native helper inventory matches exact caller-selected helper path, digest, version and signature-capability mappings; every child remains in the bounded cgroup and fixed helper-only PATH. Source/build provenance is retained as unknown when unverified.",
  "Unknown and unexamined files remain explicit. Empty native analyses do not attest successful examination. Extracted code is never executed. No unrestricted fallback is used.",
  "Entropy preserves native Shannon values and measured byte windows without encryption/compression interpretation. Native plot dimensions are verified from the bounded PNG header, not a complete image decode. Optional PNG controls publication only.",
] as const;

const nativeOperations = new Set([
  "inspect_firmware_provider",
  "inspect_firmware_regions",
  "inspect_firmware_entropy",
  "carve_firmware",
  "extract_firmware",
]);

/** Single-outstanding BYO binwalk-ng provider owning all processes, private roots and output cleanup. */
export class BinwalkNgProvider {
  readonly #resources = new ArtifactAnalysisResources(
    "binwalk-ng",
    "firmware",
    readStableArtifact,
    readLinuxResourceLimits,
    {
      message: "One heavy binwalk-ng operation is already outstanding",
      details: { maximum_outstanding: 1 },
    },
  );
  readonly #owned = new Set<OwnedWorkflow>();
  constructor(
    readonly environment: Readonly<
      Record<string, string | undefined>
    > = process.env,
    readonly launcher?: FirmwareLauncher,
  ) {}

  async execute(
    request: FirmwareRequest,
    options?: ExecutionOptions,
  ): Promise<Outcome> {
    if (!isBinwalkNgRequest(request))
      return err(
        firmwareToolUnavailable(
          "binwalk-ng",
          request.operation,
          "This adapter requires explicit binwalk-ng selection",
        ),
      );
    if (!nativeOperations.has(request.operation))
      return err(
        firmwareToolUnavailable(
          "binwalk-ng",
          request.operation,
          "This Binwalk-NG operation is not admitted by the selected provider profile",
        ),
      );
    const deadline = AbortSignal.timeout(FIRMWARE_LIMITS.timeoutMs);
    const signal =
      options?.signal === undefined
        ? deadline
        : AbortSignal.any([options.signal, deadline]);
    return this.#resources.run(
      async () => {
        if (signal.aborted)
          return err(
            firmwareCancellation(request.operation, signal.reason, deadline),
          );
        const cleanup = await this.#cleanup();
        if (cleanup !== undefined) return err(cleanup);
        return this.#execute(request, signal, deadline);
      },
      signal,
      request.operation,
    );
  }

  async close(): Promise<void> {
    await this.#resources.close();
    const cleanup = await this.#cleanup();
    if (cleanup !== undefined) throw cleanup;
  }

  async #cleanup(): Promise<AnalysisError | undefined> {
    const failures: AnalysisError[] = [];
    for (const owner of this.#owned) {
      try {
        await owner.cleanupLease.release();
        this.#owned.delete(owner);
      } catch (cause: unknown) {
        const interpreted = firmwareFailure(
          cause,
          "binwalk-ng",
          owner.operation,
        );
        if (interpreted.cleanupIncomplete) failures.push(interpreted);
        else {
          const cleanup = new ProviderCleanupError(
            "binwalk-ng",
            [
              owner.root.path,
              ...(owner.tree === undefined ? [] : [owner.tree.outputRoot]),
            ],
            { reason: cause instanceof Error ? cause.message : String(cause) },
            { operation: owner.operation, cause },
          );
          new AnalysisCleanupLeaseGroup(cleanup, [owner.cleanupLease]);
          failures.push(cleanup);
        }
      }
    }
    if (failures.length < 2) return failures[0];
    return new ProviderCleanupError(
      "binwalk-ng",
      failures.flatMap((failure) => [...failure.cleanupResources]),
      {
        reason: "Owned firmware resources remain pending cleanup",
        failures: failures.map((failure) => ({
          operation:
            failure instanceof ProviderAdapterError
              ? failure.operation
              : "close_firmware",
          diagnostics: failure.diagnostics ?? null,
        })),
      },
      { operation: "close_firmware", cause: new AggregateError(failures) },
    ).bindCleanupDependencies(failures);
  }

  async #execute(
    request: BinwalkNgRequest,
    signal: AbortSignal,
    deadline: AbortSignal,
  ): Promise<Outcome> {
    let owner: OwnedWorkflow | undefined;
    let outcome: Outcome;
    try {
      if (signal.aborted)
        throw firmwareCancellation(request.operation, signal.reason, deadline);
      const required = (name: string) => {
        const value = this.environment[name];
        if (value === undefined || value.length === 0)
          throw firmwareToolUnavailable(
            "binwalk-ng",
            request.operation,
            `Required explicit runtime configuration is absent: ${name}`,
          );
        return value;
      };
      const runtime = {
        command: required("REA_BINWALK_NG_COMMAND"),
        bubblewrap: required("REA_FIRMWARE_BWRAP_COMMAND"),
        manifest: required("REA_BINWALK_NG_RUNTIME_MANIFEST"),
        limiter:
          this.environment.REA_FIRMWARE_PRLIMIT_COMMAND ?? "/usr/bin/prlimit",
        systemdRun:
          this.environment.REA_FIRMWARE_SYSTEMD_RUN_COMMAND ??
          "/usr/bin/systemd-run",
      };
      const root = await PrivateRuntimeRoot.create({
        prefix: "rea-binwalk-ng-",
      });
      const workflow: OwnedWorkflow = {
        root,
        scope: new ArtifactResourceScope(),
        files: new FirmwareFileAccess(),
        operation: request.operation,
        cleanupLease: new AnalysisCleanupLease(async () => {
          const stopped = await workflow.supervisor?.stop();
          if (stopped?.status === "incomplete") throw Error(stopped.reason);
          delete workflow.supervisor;
          await workflow.scope.retryCleanup();
          await workflow.files.close();
          await workflow.tree?.rollback();
          delete workflow.tree;
          await workflow.root.close();
        }, [root.path]),
      };
      owner = workflow;
      this.#owned.add(owner);
      if (this.launcher === undefined)
        await requireBinwalkNgTmpfs(root.path, request.operation);
      const owned = owner;
      const common = {
        root: root.path,
        runtime,
        signal,
        scope: owner.scope,
        files: owner.files,
        retainCleanup: (supervisor: ProviderProcessSupervisor) => {
          owned.supervisor = supervisor;
        },
        ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
      };
      let target:
        | Awaited<ReturnType<FirmwareFileAccess["snapshot"]>>
        | undefined;
      const produced =
        request.operation === "inspect_firmware_provider"
          ? await inspectBinwalkNgRuntime(common)
          : await (async () => {
              if (!("path" in request.input))
                throw firmwareToolUnavailable(
                  "binwalk-ng",
                  request.operation,
                  "Firmware input path is unavailable",
                );
              target = await owner.files.snapshot(
                {
                  operation: request.operation,
                  input: {
                    path: request.input.path,
                    ...(request.operation === "extract_firmware" &&
                    "range" in request.input &&
                    request.input.range !== undefined
                      ? { range: request.input.range }
                      : {}),
                  },
                },
                root.path,
                signal,
              );
              return runBinwalkNgWorkflow({
                ...common,
                request,
                target,
                ownTree: (tree: SafeOutputTree) => {
                  owned.tree = tree;
                },
                releaseTree: () => {
                  delete owned.tree;
                },
              });
            })();
      outcome = ok(
        createAnalysisExecution(
          binwalkNgResultSchemas[request.operation].parse(produced.result),
          {
            id: "binwalk-ng",
            name: "binwalk-ng",
            version: BINWALK_NG_RELEASE.version,
          },
          {
            ...(target === undefined ? {} : { subject: target.subject }),
            rawResult: produced.raw,
            limitations,
            locations:
              target === undefined
                ? []
                : [
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
      const stderr =
        cause instanceof ProviderAdapterError
          ? typeof cause.diagnostics?.stderr === "string" &&
            cause.diagnostics.stderr.length > 0
            ? cause.diagnostics.stderr
            : cause.capturedOutput?.stderr
          : undefined;
      const featureAbsent =
        request.operation === "inspect_firmware_entropy" &&
        cause instanceof ProviderAdapterError &&
        !cause.cleanupIncomplete &&
        stderr !== undefined &&
        stderr.includes(
          'binwalk was built without the "entropy-plot" feature, entropy analysis isn\'t available',
        );
      const error =
        featureAbsent && cause instanceof ProviderAdapterError
          ? new AnalysisCapabilityUnavailableError(
              "binwalk-ng",
              request.operation,
              "The selected native build reports that entropy-plot is unavailable",
              {
                cause,
                diagnostics: { ...cause.diagnostics, stderr },
                capturedOutput: cause.capturedOutput,
              },
            )
          : signal.aborted && cause === signal.reason
            ? firmwareCancellation(request.operation, signal.reason, deadline)
            : firmwareFailure(
                cause,
                "binwalk-ng",
                request.operation,
                deadline,
                owner?.cleanupLease,
              );
      if (
        cause instanceof AnalysisError &&
        cause.partialObservation !== undefined
      )
        error.retainPartialObservation(cause.partialObservation);
      if (error.cleanupIncomplete && owner?.supervisor !== undefined)
        new AnalysisCleanupLeaseGroup(error, [owner.cleanupLease]);
      outcome = err(error);
    }
    // Failed descriptor/process finalization retains its exact owner until an explicit retry.
    if (!outcome.ok && outcome.error.cleanupIncomplete) return outcome;
    const cleanup = await this.#cleanup();
    if (outcome.ok && signal.aborted) {
      const completed = outcome.value;
      outcome = err(
        firmwareCancellation(
          request.operation,
          signal.reason,
          deadline,
        ).retainPartialObservation({
          kind: "firmware",
          result: completed.result,
          provenance: jsonValueSchema.parse({
            raw_result: completed.rawResult,
            subject: completed.subject,
            provider: completed.provider,
          }),
        }),
      );
    }
    if (cleanup !== undefined) {
      if (outcome.ok)
        cleanup.retainPartialObservation({
          kind: "firmware",
          result: outcome.value.result,
          provenance: jsonValueSchema.parse({
            raw_result: outcome.value.rawResult,
            subject: outcome.value.subject,
            provider: outcome.value.provider,
          }),
        });
      else if (outcome.error.partialObservation !== undefined)
        cleanup.retainPartialObservation(outcome.error.partialObservation);
      if (!outcome.ok)
        return err(
          analysisErrorWithCleanupFailure(
            outcome.error,
            cleanup,
            request.operation,
          ).bindCleanupDependencies([outcome.error, cleanup]),
        );
      return err(cleanup);
    }
    return outcome;
  }
}
