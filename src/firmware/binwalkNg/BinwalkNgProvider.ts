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
import {
  AnalysisCapabilityUnavailableError,
  AnalysisCancelledError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
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
import { snapshotFirmware } from "../FirmwareFiles.js";
import { BINWALK_NG_RELEASE, FIRMWARE_LIMITS } from "../FirmwareRelease.js";
import { runBinwalkNgWorkflow } from "./BinwalkNgWorkflow.js";
import { requireBinwalkNgTmpfs } from "./BinwalkNgSystemdBoundary.js";

interface OwnedWorkflow {
  root: PrivateRuntimeRoot;
  scope: ArtifactResourceScope;
  operation: string;
  supervisor?: ProviderProcessSupervisor;
  tree?: SafeOutputTree;
}
type Outcome = Result<AnalysisExecution, AnalysisError>;
const limitations = [
  "Signature matches and provider-reported sizes do not establish partition validity, encryption, authentication or runtime mappings. Empty native analyses do not attest a successful read or absence of findings.",
  "The selected binwalk-ng 4.0.0 profile is a compatibility declaration. Runtime executable, selected regular-file mounts, launcher and limiter are fingerprinted; the installed source revision remains unknown. Identity readback is not syscall-level TOCTOU prevention.",
  "Each invocation runs in a dedicated user-systemd cgroup and the exact bubblewrap namespace/mount policy. Effective cgroup v2 memory, swap, task and CPU limits are read back in-unit before execution. The manager environment is enumerated by name and removed from the service; selected runtime files and immutable input alone are readable inside bubblewrap.",
  "The private work tree must be tmpfs; producer writes are charged to the same 512 MiB cgroup memory ceiling. Individual report/PNG reads remain capped at 8 MiB and captures are separately bounded. This is not a caller-configurable 512 MiB output quota.",
  "Provider inventory, one-pass signature scan, native entropy and internal carving are admitted under the verified native boundary. Extraction remains unavailable before target reads because signature-selected external helper execution and helper-path identity have not been admitted.",
  "Unknown and unexamined files remain explicit. Empty native analyses do not attest successful examination. Extracted code is never executed. No unrestricted fallback is used.",
  "Entropy preserves native Shannon values and measured byte windows without encryption/compression interpretation. Native plot dimensions are verified from the bounded PNG header, not a complete image decode. Optional PNG controls publication only.",
] as const;

const nativeOperations = new Set([
  "inspect_firmware_provider",
  "inspect_firmware_regions",
  "inspect_firmware_entropy",
  "carve_firmware",
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
          "Binwalk-NG extraction remains unavailable until signature-selected external helpers and exact helper-path identity are admitted",
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
          return err(new AnalysisCancelledError(request.operation));
        const cleanup = await this.#cleanup();
        if (cleanup !== undefined) return err(cleanup);
        return this.#execute(request, options, signal, deadline);
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

  async #cleanup(): Promise<ProviderCleanupError | undefined> {
    const failures: ProviderCleanupError[] = [];
    for (const owner of this.#owned) {
      try {
        const stopped = await owner.supervisor?.stop();
        if (stopped?.status === "incomplete") throw new Error(stopped.reason);
        delete owner.supervisor;
        await owner.scope.retryCleanup();
        await owner.tree?.rollback();
        delete owner.tree;
        await owner.root.close();
        this.#owned.delete(owner);
      } catch (cause: unknown) {
        failures.push(
          new ProviderCleanupError(
            "binwalk-ng",
            [
              owner.root.path,
              ...(owner.tree === undefined ? [] : [owner.tree.outputRoot]),
            ],
            { reason: cause instanceof Error ? cause.message : String(cause) },
            { operation: owner.operation, cause },
          ),
        );
      }
    }
    if (failures.length === 0) return undefined;
    return new ProviderCleanupError(
      "binwalk-ng",
      failures.flatMap((failure) => [...failure.cleanupResources]),
      {
        reason: "Owned firmware resources remain pending cleanup",
        failures: failures.map((failure) => ({
          operation: failure.operation,
          diagnostics: failure.diagnostics ?? null,
        })),
      },
      { operation: "close_firmware", cause: new AggregateError(failures) },
    );
  }

  async #execute(
    request: BinwalkNgRequest,
    options: ExecutionOptions | undefined,
    signal: AbortSignal,
    deadline: AbortSignal,
  ): Promise<Outcome> {
    let owner: OwnedWorkflow | undefined;
    let outcome: Outcome;
    try {
      signal.throwIfAborted();
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
      owner = {
        root,
        scope: new ArtifactResourceScope(),
        operation: request.operation,
      };
      this.#owned.add(owner);
      if (this.launcher === undefined)
        await requireBinwalkNgTmpfs(root.path, request.operation);
      const owned = owner;
      const common = {
        root: root.path,
        runtime,
        signal,
        scope: owner.scope,
        retainCleanup: (supervisor: ProviderProcessSupervisor) => {
          owned.supervisor = supervisor;
        },
        ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
      };
      let target: Awaited<ReturnType<typeof snapshotFirmware>> | undefined;
      const produced =
        request.operation === "inspect_firmware_provider"
          ? await inspectBinwalkNgRuntime(common)
          : await (async () => {
              target = await snapshotFirmware(
                request,
                root.path,
                signal,
                owner.scope,
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
      const featureAbsent =
        request.operation === "inspect_firmware_entropy" &&
        cause instanceof ProviderAdapterError &&
        typeof cause.diagnostics?.stderr === "string" &&
        cause.diagnostics.stderr.includes(
          'binwalk was built without the "entropy-plot" feature, entropy analysis isn\'t available',
        );
      const error =
        cause instanceof ProviderCleanupError
          ? cause
          : featureAbsent && cause instanceof ProviderAdapterError
            ? new AnalysisCapabilityUnavailableError(
                "binwalk-ng",
                request.operation,
                "The selected native build reports that entropy-plot is unavailable",
                { cause, diagnostics: cause.diagnostics },
              )
            : options?.signal?.aborted === true
              ? new AnalysisCancelledError(request.operation)
              : deadline.aborted
                ? new AnalysisTimeoutError(
                    request.operation,
                    FIRMWARE_LIMITS.timeoutMs,
                  )
                : cause instanceof AnalysisError
                  ? cause
                  : new ProviderAdapterError("binwalk-ng", request.operation, {
                      cause,
                      diagnostics: {
                        reason:
                          cause instanceof Error
                            ? cause.message
                            : String(cause),
                      },
                    });
      if (
        cause instanceof AnalysisError &&
        cause.partialObservation !== undefined
      )
        error.retainPartialObservation(cause.partialObservation);
      outcome = err(error);
    }
    // Unconfirmed process/descriptor owners must survive with their mounted workspace.
    if (!outcome.ok && outcome.error.cleanupIncomplete) return outcome;
    const cleanup = await this.#cleanup();
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
          ),
        );
      return err(cleanup);
    }
    return outcome;
  }
}
