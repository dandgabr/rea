import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../AnalysisProvider.js";
import type {
  FirmwareCorpusInput,
  FirmwareCorpusOperation,
} from "../../domain/corpus/firmwareCorpus.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";
import type { JsonValue } from "../../domain/jsonValue.js";

/** Private lifecycle directive; never included in Evidence or producer payloads. */
export interface FirmwareCorpusExecution extends AnalysisExecution {
  readonly collectionDisposition?: "retain" | "explicit-reattempt";
  /** Provider-owned safe projection after private configuration becomes known.
   * Applies to every returned observation, including failed/partial/cancelled work.
   * Errors own their caller-safe partialObservation and bypass service projection.
   * Contains neither a private credential context nor a deferred callback.
   */
  readonly publicParameters?: Readonly<Record<string, JsonValue>>;
}

/** Corpus authority is independent of local artifact provider sessions. */
export interface FirmwareCorpusPort {
  execute<Name extends FirmwareCorpusOperation>(
    operation: Name,
    input: FirmwareCorpusInput<Name>,
    options?: ExecutionOptions,
  ): Promise<Result<FirmwareCorpusExecution, AnalysisError>>;
  close?(): Promise<void>;
}
