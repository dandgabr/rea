import { knownSensitiveValueRedactor } from "../../domain/knownSensitiveValueRedaction.js";
import type { FirmwareCorpusPort } from "./FirmwareCorpusPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  firmwareCorpusInputs,
  type FirmwareCorpusOperation,
} from "../../domain/corpus/firmwareCorpus.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisCancelledError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { digestCanonicalValue } from "../../domain/canonicalDigest.js";
import { ok, err, type Result } from "../../domain/result.js";

/** Operations allowed by the current FACT authority decision. */
const FACT_PUBLIC_OPERATIONS: ReadonlySet<FirmwareCorpusOperation> = new Set([
  "inspect_firmware_corpus",
  "search_corpus_objects",
  "inspect_corpus_object",
  "inspect_corpus_analysis",
  "inspect_corpus_parent_analysis",
  "inspect_corpus_comparison",
  "collect_corpus_yara",
  "inspect_corpus_statistics",
  "inspect_corpus_gaps",
  "download_corpus_binary",
  "export_corpus_firmware",
]);
const FACT_UNAVAILABLE_REASON =
  "This operation is outside the recorded FACT integration scope; plugin, scheduler, egress or mutation authority has not been verified.";
const MAX_RETAINED_YARA_COLLECTIONS = 8;
// FACT REST bounds one JSON response to 8 MiB. Reserve a little extra for the
// Evidence envelope and caller metadata, then bound the lifetime aggregate.
const YARA_EVIDENCE_RESERVATION_BYTES = 9 * 1024 * 1024;
const MAX_RETAINED_YARA_EVIDENCE_BYTES = 64 * 1024 * 1024;
const MAX_YARA_SEARCH_ID_BYTES = 1024;

/** Shared named validation, external authority and one-shot Evidence retention. */
export class FirmwareCorpusService {
  private readonly collections = new Map<
    string,
    Promise<Result<Evidence, AnalysisError>>
  >();
  private retainedYaraEvidenceBytes = 0;
  constructor(readonly provider: FirmwareCorpusPort) {}
  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }
  async execute(
    operation: FirmwareCorpusOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (
      !FACT_PUBLIC_OPERATIONS.has(operation) ||
      !Object.hasOwn(firmwareCorpusInputs, operation)
    )
      return err(
        new AnalysisCapabilityUnavailableError(
          "fact-core",
          operation,
          FACT_UNAVAILABLE_REASON,
        ),
      );
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
          parameters: execution.publicParameters ?? parameters,
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
    if (
      Buffer.byteLength(collection.search_id, "utf8") > MAX_YARA_SEARCH_ID_BYTES
    )
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "capacity",
          "FACT YARA search identifier exceeds the retained Evidence budget",
          { maximum_search_id_bytes: MAX_YARA_SEARCH_ID_BYTES },
        ),
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
    if (
      this.collections.size >= MAX_RETAINED_YARA_COLLECTIONS ||
      this.retainedYaraEvidenceBytes + YARA_EVIDENCE_RESERVATION_BYTES >
        MAX_RETAINED_YARA_EVIDENCE_BYTES
    )
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "capacity",
          "Retained FACT YARA observations reached the per-service cache limit",
          {
            retained_collections: this.collections.size,
            maximum_retained_collections: MAX_RETAINED_YARA_COLLECTIONS,
            retained_evidence_bytes: this.retainedYaraEvidenceBytes,
            reserved_evidence_bytes: YARA_EVIDENCE_RESERVATION_BYTES,
            maximum_retained_evidence_bytes: MAX_RETAINED_YARA_EVIDENCE_BYTES,
          },
        ),
      );
    // Reserve the cache key before starting the consuming request. The first
    // caller owns its signal; joining waiters cannot cancel shared consumption.
    let resolvePending!: (value: Result<Evidence, AnalysisError>) => void;
    let rejectPending!: (reason: unknown) => void;
    const pending = new Promise<Result<Evidence, AnalysisError>>(
      (resolve, reject) => {
        resolvePending = resolve;
        rejectPending = reject;
      },
    );
    this.retainedYaraEvidenceBytes += YARA_EVIDENCE_RESERVATION_BYTES;
    this.collections.set(key, pending);
    void run().then(resolvePending, rejectPending);
    const result = await pending;
    if (
      collectionState.disposition === "explicit-reattempt" &&
      this.collections.get(key) === pending
    ) {
      this.collections.delete(key);
      this.retainedYaraEvidenceBytes -= YARA_EVIDENCE_RESERVATION_BYTES;
    }
    return result;
  }
}
