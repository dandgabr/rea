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

/** Corpus authority is independent of local artifact provider sessions. */
export interface FirmwareCorpusPort {
  execute<Name extends FirmwareCorpusOperation>(
    operation: Name,
    input: FirmwareCorpusInput<Name>,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
  close?(): Promise<void>;
}
