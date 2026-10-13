import { knownSensitiveValueRedactor } from "../../domain/knownSensitiveValueRedaction.js";
import type { FirmwareCorpusPort } from "./FirmwareCorpusPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  firmwareCorpusInputs,
  type FirmwareCorpusOperation,
} from "../../domain/corpus/firmwareCorpus.js";
import {
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisCancelledError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { digestCanonicalValue } from "../../domain/canonicalDigest.js";
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
    // The public graph is a separate JSON snapshot; delivery and consuming identity
    // retain the original private transport context and selected values.
    const redactedParameters = knownSensitiveValueRedactor(
      "connection" in parsed.data
        ? parsed.data.connection.authorization
        : undefined,
      "latin1",
      { operation },
    ).value(parameters);
    if (!redactedParameters.ok) return redactedParameters;
    const collectionState: { disposition: "retain" | "explicit-reattempt" } = {
      disposition: "retain",
    };
    const run = async (): Promise<Result<Evidence, AnalysisError>> => {
      const executed = await this.provider.execute(
        operation,
        parsed.data,
        options,
      );
      if (!executed.ok) {
        if (
          executed.error instanceof AnalysisCancelledError ||
          (executed.error instanceof AnalysisResourceConstraintError &&
            executed.error.resource === "capacity")
        )
          collectionState.disposition = "explicit-reattempt";
        return executed;
      }
      const execution = executed.value;
      collectionState.disposition = execution.collectionDisposition ?? "retain";
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
    const collection = firmwareCorpusInputs.collect_corpus_yara.parse(
      parsed.data,
    );
    // The private key binds transport authority without exporting credential fingerprints.
    const key = digestCanonicalValue(
      {
        origin: new URL(collection.connection.endpoint).origin,
        profile: collection.connection.profile,
        authorization: collection.connection.authorization ?? null,
        search_id: collection.search_id,
      },
      "Corpus consuming resource",
    );
    const previous = this.collections.get(key);
    if (previous) return previous;
    // First caller owns the fetch and its signal. Joining waiters cannot cancel
    // that shared consumption; the resulting observation survives delivery cancellation.
    const pending = run();
    this.collections.set(key, pending);
    const result = await pending;
    if (
      collectionState.disposition === "explicit-reattempt" &&
      this.collections.get(key) === pending
    )
      this.collections.delete(key);
    return result;
  }
}
