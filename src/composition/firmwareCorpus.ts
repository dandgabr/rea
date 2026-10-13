import { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { FirmwareCorpusPort } from "../application/corpus/FirmwareCorpusPort.js";
import { FactRestProvider } from "../firmware/fact/FactRestProvider.js";
import { FactNativeProvider } from "../firmware/fact/FactNativeProvider.js";

/** Independent REST/native authorities selected by the named workflow, never input shape. */
export const createFirmwareCorpusProvider = (): FirmwareCorpusPort => {
  const rest = new FactRestProvider(),
    native = new FactNativeProvider();
  return {
    execute(operation, input, options) {
      return operation === "export_corpus_firmware" ||
        operation === "import_corpus_firmware"
        ? native.execute(operation, input, options)
        : rest.execute(operation, input, options);
    },
    async close() {
      const results = await Promise.allSettled([rest.close(), native.close()]);
      const failures = results.flatMap((result) =>
        result.status === "rejected" ? [result.reason] : [],
      );
      if (failures.length === 1 && failures[0] instanceof AnalysisError)
        throw failures[0];
      if (failures.length)
        throw new ProviderCleanupError(
          "fact-core",
          failures.flatMap((failure) =>
            failure instanceof AnalysisError ? failure.cleanupResources : [],
          ),
          { owners_failed: failures.length },
          {
            operation: "close_firmware_corpus",
            cause: new AggregateError(
              failures,
              "FACT corpus provider cleanup failed",
            ),
          },
        );
    },
  };
};
