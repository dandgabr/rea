import { MIMEType } from "node:util";
import { knownSensitiveValueRedactor } from "../../domain/knownSensitiveValueRedaction.js";
import { FACT_REST_PROVIDER_IDENTITY } from "./FactRelease.js";
import { createEvidence } from "../../domain/evidence.js";
import type { AnalysisResourceConstraintError } from "../../domain/analysisErrorCore.js";
import type { FirmwareCorpusPort } from "../../application/corpus/FirmwareCorpusPort.js";
import type {
  FirmwareCorpusOperation,
  FirmwareCorpusInput,
} from "../../domain/corpus/firmwareCorpus.js";
import { corpusConnectionSchema } from "../../domain/corpus/firmwareCorpus.js";
import {
  createAnalysisExecution,
  type ExecutionOptions,
} from "../../application/AnalysisProvider.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import { ok, err } from "../../domain/result.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  FACT_LIMITS,
  factHash,
  factUid,
  readFactResponse,
  FactResponseResources,
  factResult,
} from "./FactProtocol.js";
import { FactJsonParser } from "./FactJsonParser.js";
import { factJsonBytes } from "./FactTransfer.js";
import { ArtifactAnalysisResources } from "../../process/ArtifactAnalysisResources.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { readLinuxResourceLimits } from "../../process/LinuxResourceLimits.js";
import {
  freezeJsonSnapshot,
  freezeOwnedJsonSnapshotSteps,
} from "../../domain/immutableJson.js";
import { setImmediate as yieldTurn } from "node:timers/promises";
import { validateFactProducerResponse } from "./FactProducerResponse.js";
import {
  FactFileResources,
  FactPublicationFailure,
  requireFreshFactOutput,
  publishFactFile,
} from "./FactFiles.js";

const MAX_FACT_SEARCH_URL_BYTES = 2 * 1024 * 1024;

/** Fixed semantic operations; callers cannot select arbitrary HTTP paths or methods. */
export class FactRestProvider implements FirmwareCorpusPort {
  private readonly admission = new ArtifactAnalysisResources(
    "fact-core",
    "firmware-corpus",
    readStableArtifact,
    readLinuxResourceLimits,
    {
      message: "FACT permits one outstanding heavy operation per provider",
      details: { outstanding_operations: 1 },
    },
  );
  constructor(
    readonly files = new FactFileResources(),
    readonly parser = new FactJsonParser(),
    readonly responses = new FactResponseResources(),
  ) {}
  async close(): Promise<void> {
    await this.admission.close();
    const failures: unknown[] = [];
    for (const close of [
      () => this.responses.close(),
      () => this.parser.close(),
      () => this.files.close(),
    ]) {
      try {
        await close();
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length)
      throw new AggregateError(failures, "FACT cleanup remains unresolved");
  }
  execute<Name extends FirmwareCorpusOperation>(
    operation: Name,
    input: FirmwareCorpusInput<Name>,
    options?: ExecutionOptions,
  ) {
    const excluded = new Set([
      "upload_corpus_firmware",
      "reanalyze_corpus_firmware",
      "enqueue_corpus_analysis",
      "start_corpus_yara",
      "delete_corpus_firmware",
      "start_corpus_comparison",
    ]);
    if (excluded.has(operation as string))
      return Promise.resolve(
        err(
          new AnalysisCapabilityUnavailableError(
            "fact-core",
            operation,
            "Operation is outside the verified FACT REST scope.",
          ),
        ),
      );
    if (options?.signal?.aborted)
      return this.executeOwned(operation, input, options);
    return this.admission.run(
      () => this.executeOwned(operation, input, options),
      options?.signal,
    );
  }
  private async executeOwned<Name extends FirmwareCorpusOperation>(
    operation: Name,
    input: FirmwareCorpusInput<Name>,
    options?: ExecutionOptions,
  ) {
    if (!("connection" in input))
      return err(
        new AnalysisCapabilityUnavailableError(
          "fact-core",
          operation,
          "This operation requires the independent native interchange provider",
        ),
      );
    const connection = corpusConnectionSchema.parse(input.connection);
    const signal = AbortSignal.any([
      options?.signal ?? new AbortController().signal,
      AbortSignal.timeout(FACT_LIMITS.deadlineMs),
    ]);
    const redact = knownSensitiveValueRedactor(
      connection.authorization,
      "latin1",
      { operation },
    );
    let path = "",
      method = "GET";
    const query = new URLSearchParams();
    let collectionDisposition: "retain" | "explicit-reattempt" = "retain";
    let observedData: JsonValue = null;
    let delivered = false,
      httpStatus: number | null = null,
      rawDigest: string | null = null;
    const limitations = [
      "Caller-selected FACT source profile is a declaration; status does not attest service version or commit.",
      "Provider-local UIDs and virtual paths are external-service evidence; they are not host paths.",
    ];
    if (operation === "collect_corpus_yara")
      limitations.push(
        "One-shot GET may consume the result even if delivery is lost. The retained local Evidence is reused; rule-to-UID results omit match offsets.",
      );
    if (operation === "inspect_corpus_gaps")
      limitations.push(
        "Producer requires delete privilege for this non-destructive GET.",
      );
    const finish = async (
      state: "not-delivered" | "accepted" | "completed" | "failed" | "unknown",
      data: JsonValue,
      diagnostics: string[] = [],
    ) => {
      if (
        this.files.pendingResources.length ||
        this.parser.pendingResources.length ||
        this.responses.pendingResources.length
      )
        diagnostics.push(
          `Cleanup remains uncertain for owned resources: ${[...this.files.pendingResources, ...this.parser.pendingResources, ...this.responses.pendingResources].join(", ")}`,
        );
      const privacyFailure = (error: AnalysisResourceConstraintError) => {
        const summary =
          data !== null && typeof data === "object" && !Array.isArray(data)
            ? {
                producer_state: state,
                retained_cleanup_resources:
                  this.files.pendingResources.length +
                  this.parser.pendingResources.length +
                  this.responses.pendingResources.length,
                artifact: data.artifact ?? null,
                publication: data.publication ?? null,
              }
            : {
                producer_state: state,
                retained_cleanup_resources:
                  this.files.pendingResources.length +
                  this.parser.pendingResources.length +
                  this.responses.pendingResources.length,
              };
        const projected = knownSensitiveValueRedactor(
          connection.authorization,
          "latin1",
          { operation },
        ).value(summary);
        error.retainPartialObservation(
          createEvidence(undefined, FACT_REST_PROVIDER_IDENTITY, {
            operation,
            parameters: {},
            result: factResult({
              state: delivered ? "unknown" : "not-delivered",
              endpoint: connection.endpoint,
              profile: connection.profile,
              http_status: httpStatus,
              observed_at: new Date().toISOString(),
              raw_sha256: rawDigest,
              coverage: "producer-response",
              data: projected.ok ? projected.value : null,
              diagnostics: [
                "Privacy projection refused; unprojected producer text is not exported",
              ],
            }),
            authority: "external-service",
            confidence: "observed",
          }),
        );
        return err(error);
      };
      const projectedData = redact.value(data);
      if (!projectedData.ok) return privacyFailure(projectedData.error);
      const ownedData = projectedData.value;
      const projectedDiagnostics: string[] = [];
      for (const diagnostic of diagnostics) {
        const projected = redact.text(diagnostic);
        if (!projected.ok) return privacyFailure(projected.error);
        projectedDiagnostics.push(projected.value);
      }
      for (const step of freezeOwnedJsonSnapshotSteps(ownedData)) {
        void step;
        await yieldTurn();
      }
      return ok({
        ...createAnalysisExecution(
          freezeJsonSnapshot(
            factResult({
              state,
              endpoint: connection.endpoint,
              profile: connection.profile,
              http_status: httpStatus,
              observed_at: new Date().toISOString(),
              raw_sha256: rawDigest,
              coverage:
                operation === "search_corpus_objects"
                  ? "requested-page"
                  : "producer-response",
              data: ownedData,
              diagnostics: projectedDiagnostics,
            }),
          ),
          FACT_REST_PROVIDER_IDENTITY,
          { limitations },
        ),
        collectionDisposition:
          state === "not-delivered"
            ? ("explicit-reattempt" as const)
            : collectionDisposition,
      });
    };
    try {
      signal.throwIfAborted();
      switch (operation) {
        case "inspect_firmware_corpus":
          path = "/rest/status";
          break;
        case "search_corpus_objects":
          if ("kind" in input && "query" in input) {
            try {
              // Measure JSON escaping before allocating the serialized query.
              factJsonBytes(input.query);
            } catch (cause: unknown) {
              throw new Error(
                "FACT search query exceeds its JSON byte budget",
                { cause },
              );
            }
            path =
              input.kind === "firmware"
                ? "/rest/firmware"
                : "/rest/file_object";
            query.set("query", JSON.stringify(input.query));
            query.set("offset", String(input.offset));
            query.set("limit", String(input.limit));
            if (input.kind === "firmware") {
              query.set("recursive", String(input.recursive));
              query.set("inverted", String(input.inverted));
            }
          }
          break;
        case "inspect_corpus_object":
          if ("kind" in input && "uid" in input && "summary" in input) {
            path = `/rest/${input.kind === "firmware" ? "firmware" : "file_object"}/${input.uid}`;
            if (input.kind === "firmware")
              query.set("summary", String(input.summary));
          }
          break;
        case "inspect_corpus_analysis":
          if ("uid" in input && "plugin" in input) {
            path = `/rest/analysis/${input.uid}/${encodeURIComponent(input.plugin)}`;
          }
          break;
        case "inspect_corpus_parent_analysis":
          if ("plugin" in input && "uid" in input)
            path = `/plugins/${input.plugin}/rest/${input.uid}`;
          break;
        case "inspect_corpus_comparison":
          if ("uids" in input) path = `/rest/compare/${input.uids.join(";")}`;
          break;
        case "collect_corpus_yara":
          if ("search_id" in input)
            path = `/rest/binary_search/${encodeURIComponent(input.search_id)}`;
          break;
        case "inspect_corpus_statistics":
          path = `/rest/statistics${"category" in input && input.category !== undefined ? `/${input.category}` : ""}`;
          break;
        case "inspect_corpus_gaps":
          path = "/rest/missing";
          break;
        case "download_corpus_binary":
          if ("uid" in input && "output_path" in input && "repacked" in input) {
            await requireFreshFactOutput(input.output_path);
            path = `/rest/binary/${input.uid}`;
            query.set("tar", String(input.repacked));
          }
          break;
        default:
          throw Error(
            "Native interchange requires separate instance authority",
          );
      }
      if (!path)
        throw Error("Operation input does not match its named contract");
      const url = new URL(path, connection.endpoint);
      url.search = query.toString();
      if (
        operation === "search_corpus_objects" &&
        Buffer.byteLength(url.href, "utf8") > MAX_FACT_SEARCH_URL_BYTES
      )
        throw new Error("FACT search URL exceeds its encoded byte budget");
      const wireBudget =
        FACT_LIMITS.jsonBytes +
        (operation === "download_corpus_binary"
          ? 4 * Math.ceil(FACT_LIMITS.rawBytes / 3)
          : 0);
      delivered = true;
      const response = await fetch(url, {
        method,
        headers:
          connection.authorization === undefined
            ? {}
            : { Authorization: connection.authorization },
        redirect: "manual",
        signal,
      });
      httpStatus = response.status;
      const raw = await readFactResponse(
        response,
        wireBudget,
        signal,
        this.responses,
      );
      rawDigest = factHash(raw);
      let mediaType: MIMEType | undefined;
      try {
        mediaType = new MIMEType(response.headers.get("content-type") ?? "");
      } catch {
        // Invalid/missing producer media types cannot establish JSON facts.
      }
      if (mediaType?.essence !== "application/json")
        throw Error("FACT response Content-Type must declare application/json");
      const parsedEnvelope = await this.parser.parse(
        raw,
        operation === "download_corpus_binary",
        signal,
      );
      if (parsedEnvelope.cleanupDiagnostic !== undefined)
        limitations.push(parsedEnvelope.cleanupDiagnostic);
      let data = parsedEnvelope.data;
      observedData = data;
      const outcome = validateFactProducerResponse(
        operation,
        input,
        data,
        response.status,
      );
      collectionDisposition = outcome.collectionDisposition;
      if (outcome.state === "failed" || outcome.state === "unknown")
        return finish(outcome.state, data, outcome.diagnostics);
      if (
        operation === "download_corpus_binary" &&
        "uid" in input &&
        "repacked" in input &&
        "output_path" in input
      ) {
        if (
          data === null ||
          typeof data !== "object" ||
          Array.isArray(data) ||
          parsedEnvelope.binary === undefined
        )
          throw Error("Binary response is malformed");
        const bytes = parsedEnvelope.binary;
        const sha = factHash(bytes);
        if (typeof data.SHA256 !== "string" || sha !== data.SHA256)
          throw Error("Downloaded bytes do not match reported SHA256");
        if (!input.repacked && factUid(bytes) !== input.uid)
          throw Error("Original binary does not match selected UID");
        const { binary: _binary, ...metadata } = data;
        data = {
          ...metadata,
          artifact: {
            path: input.output_path,
            size: bytes.length,
            sha256: sha,
            kind: input.repacked ? "repacked-archive" : "original",
            root_uid: input.uid,
            verified: true,
          },
        };
        observedData = data;
        await publishFactFile(input.output_path, bytes, this.files);
      }
      return finish(outcome.state, data);
    } catch (cause) {
      if (cause instanceof FactPublicationFailure) {
        observedData = {
          producer: observedData,
          publication: cause.publication,
        };
      }
      return finish(delivered ? "unknown" : "not-delivered", observedData, [
        cause instanceof Error ? cause.message : String(cause),
      ]);
    }
  }
}
