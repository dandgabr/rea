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
import { FIRMWARE_LIMITS } from "../FirmwareRelease.js";
import { runBinwalkNgWorkflow } from "./BinwalkNgWorkflow.js";

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
  "Every invocation and descendant uses the probed bubblewrap namespace/mount/environment policy. Only selected runtime files and immutable input are readable, and the owned work tree is writable. No unrestricted fallback is used.",
  "Per-process address-space/CPU/file-size limits and one global deadline are enforced. Polled staging budgets may transiently overshoot; these are not aggregate process-memory or filesystem quotas.",
  "Recursion is an explicit bounded queue, respecting native do_not_recurse, empty/nonregular files and admitted depth. Unknown and unexamined files remain explicit. External extractor diagnostics discarded by native JSON remain unknown even after exit zero.",
  "Carving lineage requires actual source-byte comparison. Decompressed or unattributed children have unknown original byte ranges. Extracted code is never executed. Only regular files are published with private nonexecutable permissions.",
  "Entropy preserves native Shannon values and measured byte windows without encryption/compression interpretation. Native plot dimensions are verified from the bounded PNG header, not a complete image decode. Optional PNG controls publication only.",
] as const;

/** Queued BYO binwalk-ng provider owning all processes, private roots and output cleanup. */
export class BinwalkNgProvider {
  #tail: Promise<void> = Promise.resolve();
  #closed = false;
  readonly #owned = new Set<OwnedWorkflow>();
  constructor(
    readonly environment: Readonly<
      Record<string, string | undefined>
    > = process.env,
    readonly launcher?: FirmwareLauncher,
  ) {}

  async execute(
    request: BinwalkNgRequest,
    options?: ExecutionOptions,
  ): Promise<Outcome> {
    if (this.#closed) return err(new AnalysisCancelledError(request.operation));
    const predecessor = this.#tail;
    let release = () => {};
    this.#tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      await waitForPredecessor(predecessor, options?.signal, request.operation);
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
      const cleanup = await this.#cleanup();
      if (cleanup !== undefined) return err(cleanup);
      return await this.#execute(request, options);
    } finally {
      release();
    }
  }

  async close(): Promise<void> {
    this.#closed = true;
    await this.#tail;
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
    options?: ExecutionOptions,
  ): Promise<Outcome> {
    const deadline = AbortSignal.timeout(FIRMWARE_LIMITS.timeoutMs);
    const signal =
      options?.signal === undefined
        ? deadline
        : AbortSignal.any([options.signal, deadline]);
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
      const owned = owner;
      const target = await snapshotFirmware(request, root.path, signal);
      const produced = await runBinwalkNgWorkflow({
        request,
        root: root.path,
        target,
        runtime,
        signal,
        scope: owner.scope,
        retainCleanup: (supervisor) => {
          owned.supervisor = supervisor;
        },
        ownTree: (tree) => {
          owned.tree = tree;
        },
        releaseTree: () => {
          delete owned.tree;
        },
        ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
      });
      outcome = ok(
        createAnalysisExecution(
          produced.result,
          { id: "binwalk-ng", name: "binwalk-ng", version: "4.0.0" },
          {
            subject: target.subject,
            rawResult: produced.raw,
            limitations,
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

const waitForPredecessor = (
  predecessor: Promise<void>,
  signal: AbortSignal | undefined,
  operation: string,
) =>
  new Promise<void>((resolve, reject) => {
    const abort = () => reject(new AnalysisCancelledError(operation));
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted === true) abort();
    void predecessor.then(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    });
  });
