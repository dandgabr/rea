import type { JsonValue } from "./jsonValue.js";

/** Stable tags exposed by safe analysis-error projections. */
const ANALYSIS_ERROR_TAGS = [
  "AnalysisProtocolError",
  "AnalysisInputError",
  "AnalysisAccessDeniedError",
  "AnalysisArtifactChangedError",
  "AnalysisOutputError",
  "AnalysisCapabilityUnavailableError",
  "AnalysisUnsupportedTargetError",
  "AnalysisCancelledError",
  "AnalysisTimeoutError",
  "AnalysisResourceConstraintError",
  "ProviderSelectionError",
  "ProviderAdapterError",
  "BrowserObservationError",
  "ArtifactOperationError",
  "ProcessCaptureError",
  "EvidenceIntegrityError",
  "EvidenceFileError",
  "UnknownRegistryError",
  "HopperTimeoutError",
  "HopperCancelledError",
  "HopperProtocolError",
  "HopperRemoteError",
  "HopperProcessError",
  "HopperStartError",
  "ConfigurationError",
  "NoBinaryOpenError",
  "BinaryTargetError",
] as const;

/** Stable tag for an expected analysis failure. */
export type AnalysisErrorTag = (typeof ANALYSIS_ERROR_TAGS)[number];

/** Retained command output associated with a typed failure; truncation stays explicit. */
export interface AnalysisCapturedOutput {
  readonly stdout: string;
  readonly stderr: string;
  readonly truncated: boolean;
  readonly stdout_bytes?: number;
  readonly stderr_bytes?: number;
  readonly exit_code?: number | null;
  readonly signal?: string | null;
  readonly stdout_observed_bytes?: number;
  readonly stderr_observed_bytes?: number;
  /** Identifies stdout intentionally consumed as a binary protocol stream. */
  readonly stdout_capture?: "diagnostic" | "protocol";
  /** Digests describe retained source bytes, before text decoding. */
  readonly stdout_sha256?: string;
  readonly stderr_sha256?: string;
  readonly stdout_utf8_valid?: boolean;
  readonly stderr_utf8_valid?: boolean;
  readonly command?: string;
  readonly arguments?: string[];
  readonly resource_limiter?: string;
}

/** Cleanup uncertainty attached to the original typed analysis failure. */
export interface AnalysisCleanupObservation {
  readonly reason: string;
  readonly resources: readonly string[];
}

/** Optional provider-neutral context that must survive typed error projection. */
export interface AnalysisErrorOptions extends ErrorOptions {
  /** Producer-owned, caller-safe facts retained through every typed projection. */
  readonly diagnostics?: Readonly<Record<string, JsonValue>> | undefined;
  readonly capturedOutput?: AnalysisCapturedOutput | undefined;
  readonly cleanup?: AnalysisCleanupObservation | undefined;
  readonly partialObservation?: AnalysisPartialObservation | undefined;
}

/** Base class for expected analysis, provider, and session failures. */
export abstract class AnalysisError extends Error {
  readonly diagnostics: Readonly<Record<string, JsonValue>> | undefined;
  #capturedOutput: AnalysisCapturedOutput | undefined;
  get capturedOutput(): AnalysisCapturedOutput | undefined {
    return this.#capturedOutput;
  }
  readonly cleanup: AnalysisCleanupObservation | undefined;
  cleanupIncomplete: boolean;
  readonly cleanupResources: readonly string[];
  constructor(message: string, options?: AnalysisErrorOptions) {
    super(message, options);
    this.diagnostics =
      options?.diagnostics === undefined
        ? undefined
        : structuredClone(options.diagnostics);
    this.#capturedOutput =
      options?.capturedOutput === undefined
        ? undefined
        : { ...options.capturedOutput };
    // Preserve the existing own/enumerable error serialization contract while
    // the tagged failure owns later bounded snapshot attachment.
    Object.defineProperty(this, "capturedOutput", {
      enumerable: true,
      get: () => this.#capturedOutput,
    });
    this.cleanup = options?.cleanup;
    this.cleanupIncomplete = options?.cleanup !== undefined;
    this.cleanupResources = options?.cleanup?.resources ?? [];
    this.partialObservation = options?.partialObservation;
  }
  abstract readonly _tag: AnalysisErrorTag;
  readonly userMessage: string | undefined = undefined;
  readonly userCategory: "cancelled" | undefined = undefined;
  readonly executionFailure: string | undefined = undefined;
  partialObservation: AnalysisPartialObservation | undefined;
  readonly cleanupReport: ProcessCaptureCleanupReport | undefined = undefined;

  /** Retain a later lifecycle failure without replacing the original typed error. */
  retainSecondaryFailure(
    failure: AnalysisError,
    diagnostics: Readonly<Record<string, JsonValue>>,
  ): this {
    // Secondary resources remain owned by their cleanup lifecycle; preserve
    // the primary error's live cleanup status and original output.
    Object.assign(this, {
      diagnostics: structuredClone({ ...this.diagnostics, ...diagnostics }),
      cause: new AggregateError(
        this.cause === undefined ? [failure] : [this.cause, failure],
        "Analysis failed and a later lifecycle operation also failed.",
        { cause: this.cause },
      ),
    });
    return this;
  }

  /** Clear live cleanup status only after its owning resource confirms retry success. */
  resolveCleanup(): this {
    this.cleanupIncomplete = false;
    return this;
  }

  /** Retain a completed observation when a later step fails. */
  retainPartialObservation(observation: AnalysisPartialObservation): this {
    this.partialObservation ??= observation;
    return this;
  }

  /** Attach an owned bounded command snapshot without replacing the primary failure. */
  retainCapturedOutput(output: AnalysisCapturedOutput): this {
    this.#capturedOutput ??= Object.freeze({
      ...output,
      ...(output.arguments === undefined
        ? {}
        : { arguments: [...output.arguments] }),
    });
    return this;
  }
}
import type {
  PartialProcessCaptureObservation,
  ProcessCaptureCleanupReport,
} from "./process/processCapture.js";
import type { FileOffsetPartialObservation } from "./native/fileOffsetPartialObservation.js";
import type { NativeCallPartialObservation } from "./native/nativeCallPartialObservation.js";
import type { ElectronActivePartialObservation } from "./javascript/electronActiveObservation.js";
import type { JavaScriptRuntimeObservation } from "./javascript/javascriptRuntimeObservation.js";
import type {
  ArtifactInventoryPartialObservation,
  ArtifactExtractionPartialObservation,
} from "./artifactPartialObservation.js";
import type { WebScriptExportPartialObservation } from "./webScriptExport.js";
import type { JavaScriptRecoveryPartialObservation } from "./javascript/javascriptRecovery.js";
import type { BrowserScenarioPartialObservation } from "./browserScenarioCapture.js";
import type { Evidence } from "./evidence.js";
import type { ElectronPagePartialObservation } from "./javascript/electronObservation.js";
import type { AndroidPartialObservation } from "./android/androidPartialObservation.js";
import type { FirmwarePartialObservation } from "./firmware/firmwareAnalysis.js";
import type {
  AdbActivityStartPartialObservation,
  AdbAcquiredFilePartialObservation,
  AdbPackagePullPartialObservation,
} from "./adb/adbDeviceAnalysis.js";
import type { NativeUiObservationResult } from "./native/nativeUiObservation.js";
import type { BinaryLayout } from "./native/binaryLayout.js";
import type {
  RecordedCrash,
  RecordedCrashPartialObservation,
} from "./native/recordedCrash.js";
import type { WebPageInspection } from "./browserObservationSchemas.js";
import type { WebExecution } from "./webExecution.js";
import type { WebEventListeners } from "./webEventListeners.js";

/** Provider-neutral evidence collected before a typed analysis failure. */
export type AnalysisPartialObservation =
  | PartialProcessCaptureObservation
  | NativeCallPartialObservation
  | FileOffsetPartialObservation
  | ElectronActivePartialObservation
  | BrowserScenarioPartialObservation
  | WebPageInspection
  | WebExecution
  | WebEventListeners
  | JavaScriptRuntimeObservation
  | ArtifactInventoryPartialObservation
  | ArtifactExtractionPartialObservation
  | WebScriptExportPartialObservation
  | JavaScriptRecoveryPartialObservation
  | Evidence
  | BinaryLayout
  | RecordedCrash
  | RecordedCrashPartialObservation
  | AndroidPartialObservation
  | FirmwarePartialObservation
  | NativeUiObservationResult
  | ElectronPagePartialObservation
  | AdbActivityStartPartialObservation
  | AdbAcquiredFilePartialObservation
  | AdbPackagePullPartialObservation;
