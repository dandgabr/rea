import type { FirmwareCorpusPort } from "../../application/corpus/FirmwareCorpusPort.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import type {
  FirmwareCorpusInput,
  FirmwareCorpusOperation,
} from "../../domain/corpus/firmwareCorpus.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import { err } from "../../domain/result.js";
import { FACT_NATIVE_PROVIDER_IDENTITY } from "./FactRelease.js";

/** Native FACT interchange is unavailable until its producer can be isolated. */
export class FactNativeProvider implements FirmwareCorpusPort {
  execute<Name extends FirmwareCorpusOperation>(
    operation: Name,
    _input: FirmwareCorpusInput<Name>,
    _options?: ExecutionOptions,
  ) {
    const reason =
      operation === "export_corpus_firmware"
        ? "FACT native export is unavailable for every runtime until REA can enforce filesystem, network and device isolation before producer identity or execution."
        : "This operation requires the independent FACT REST authority";
    return Promise.resolve(
      err(
        new AnalysisCapabilityUnavailableError(
          FACT_NATIVE_PROVIDER_IDENTITY.id,
          operation,
          reason,
        ),
      ),
    );
  }

  async close(): Promise<void> {}
}
