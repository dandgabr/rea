import type { FirmwareCorpusPort } from "./FirmwareCorpusPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  firmwareCorpusInputs,
  type FirmwareCorpusOperation,
} from "../../domain/corpus/firmwareCorpus.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { ok, err, type Result } from "../../domain/result.js";

/** Shared named validation, external authority and one-shot Evidence retention. */
export class FirmwareCorpusService {
  private readonly collections = new Map<
    string,
    Promise<Result<Evidence, AnalysisError>>
  >();
  constructor(readonly provider: FirmwareCorpusPort) {}
  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }
  async execute(
    operation: FirmwareCorpusOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const parsed = firmwareCorpusInputs[operation].safeParse(input);
    if (!parsed.success) return err(new AnalysisInputError(operation));
    const parameters = jsonObjectSchema.parse(parsed.data);
    if (
      "connection" in parameters &&
      typeof parameters.connection === "object" &&
      parameters.connection !== null &&
      !Array.isArray(parameters.connection)
    ) {
      const { authorization: _authorization, ...publicConnection } =
        parameters.connection;
      parameters.connection = publicConnection;
    }
    const run = async (): Promise<Result<Evidence, AnalysisError>> => {
      const executed = await this.provider.execute(
        operation,
        parsed.data,
        options,
      );
      if (!executed.ok) return executed;
      const execution = executed.value;
      return ok(
        createEvidence(execution.subject ?? undefined, execution.provider, {
          operation,
          parameters,
          result: execution.result,
          ...(execution.rawResult === null
            ? {}
            : { rawResult: execution.rawResult }),
          authority: "external-service",
          confidence: "observed",
          subjectUnavailableReason:
            "Corpus object identity is provider-local; virtual paths are not local artifacts",
          locations: execution.locations,
          limitations: execution.limitations,
        }),
      );
    };
    if (operation !== "collect_corpus_yara") return run();
    const key = JSON.stringify(parameters);
    const previous = this.collections.get(key);
    if (previous) return previous;
    const pending = run();
    this.collections.set(key, pending);
    return pending;
  }
}
