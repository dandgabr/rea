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
  factRedactor,
  readFactResponse,
  factResult,
} from "./FactProtocol.js";
import { FactJsonParser } from "./FactJsonParser.js";
import { factJsonBytes, factUploadBody } from "./FactTransfer.js";
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
  snapshotFactFile,
  requireFreshFactOutput,
  publishFactFile,
} from "./FactFiles.js";

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
  ) {}
  async close(): Promise<void> {
    await this.admission.close();
    const failures: unknown[] = [];
    for (const close of [() => this.parser.close(), () => this.files.close()]) {
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
    if (
      operation === "enqueue_corpus_analysis" &&
      connection.profile === "release-4.4.1"
    )
      return err(
        new AnalysisCapabilityUnavailableError(
          "fact-core",
          operation,
          "Single-file analysis PUT is unavailable in release 4.4.1; select the source profile only for the matching supplied service",
        ),
      );
    const signal = AbortSignal.any([
      options?.signal ?? new AbortController().signal,
      AbortSignal.timeout(FACT_LIMITS.deadlineMs),
    ]);
    const redact = factRedactor(connection.authorization);
    let path = "",
      method = "GET",
      payload: JsonValue | undefined;
    const query = new URLSearchParams();
    let upload: ReturnType<typeof factUploadBody> | undefined;
    let snapshot: Awaited<ReturnType<typeof snapshotFactFile>> | undefined;
    let collectionDisposition: "retain" | "explicit-reattempt" = "retain";
    let observedData: JsonValue = null;
    let delivered = false,
      httpStatus: number | null = null,
      rawDigest: string | null = null;
    const limitations = [
      "Caller-selected FACT source profile is a declaration; status does not attest service version or commit.",
      "Provider-local UIDs and virtual paths are external-service evidence; they are not host paths.",
    ];
    if (
      [
        "upload_corpus_firmware",
        "reanalyze_corpus_firmware",
        "enqueue_corpus_analysis",
        "start_corpus_comparison",
        "start_corpus_yara",
      ].includes(operation)
    )
      limitations.push(
        "External jobs may execute trusted plugins and permit egress. Canceling the REA request does not cancel, retry or compensate an external job.",
      );
    if (operation === "collect_corpus_yara")
      limitations.push(
        "One-shot GET may consume the result even if delivery is lost. The retained local Evidence is reused; rule-to-UID results omit match offsets.",
      );
    if (operation === "inspect_corpus_gaps")
      limitations.push(
        "Producer requires delete privilege for this non-destructive GET.",
      );
    if (operation === "delete_corpus_firmware")
      limitations.push(
        "Deletes firmware, analyses and uniquely owned descendants; shared objects remain under producer ownership.",
      );
    const finish = async (
      state: "not-delivered" | "accepted" | "completed" | "failed" | "unknown",
      data: JsonValue,
      diagnostics: string[] = [],
    ) => {
      if (snapshot !== undefined) {
        const cleaned = await this.files.release(snapshot.runtime);
        if (!cleaned.ok)
          diagnostics.push(
            "Snapshot cleanup failed; ownership retained for close",
          );
        snapshot = undefined;
      }
      if (
        this.files.pendingResources.length ||
        this.parser.pendingResources.length
      )
        diagnostics.push(
          `Cleanup remains uncertain for owned resources: ${[...this.files.pendingResources, ...this.parser.pendingResources].join(", ")}`,
        );
      const ownedData = redact.value(data);
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
              diagnostics: diagnostics.map(redact.text),
            }),
          ),
          { id: "fact-core", name: "FACT Core", version: null },
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
        case "enqueue_corpus_analysis":
          if ("uid" in input && "plugin" in input) {
            path = `/rest/analysis/${input.uid}/${encodeURIComponent(input.plugin)}`;
            if (operation === "enqueue_corpus_analysis") {
              method = "PUT";
              if ("force" in input && connection.profile === "source-54aed90b")
                query.set("force", String(input.force));
            }
          }
          break;
        case "inspect_corpus_parent_analysis":
          if ("plugin" in input && "uid" in input)
            path = `/plugins/${input.plugin}/rest/${input.uid}`;
          break;
        case "upload_corpus_firmware":
          if ("metadata" in input && "path" in input && "plugins" in input) {
            snapshot = await snapshotFactFile(input.path, signal, this.files);
            path = "/rest/firmware";
            method = "PUT";
            upload = factUploadBody(
              {
                ...input.metadata,
                requested_analysis_systems: input.plugins,
              },
              snapshot.bytes,
            );
          }
          break;
        case "reanalyze_corpus_firmware":
          if ("uid" in input && "plugins" in input && "re_unpack" in input) {
            path = `/rest/firmware/${input.uid}`;
            method = "PUT";
            query.set(
              "update",
              JSON.stringify(
                input.re_unpack
                  ? [...input.plugins, "unpacker"]
                  : input.plugins,
              ),
            );
          }
          break;
        case "start_corpus_comparison":
          if ("uids" in input && "redo" in input) {
            path = "/rest/compare";
            method = "PUT";
            payload = { uid_list: input.uids, redo: input.redo };
          }
          break;
        case "inspect_corpus_comparison":
          if ("uids" in input) path = `/rest/compare/${input.uids.join(";")}`;
          break;
        case "start_corpus_yara":
          if ("rule_file" in input) {
            path = "/rest/binary_search";
            method = "POST";
            payload = {
              rule_file: input.rule_file,
              ...(input.uid === undefined ? {} : { uid: input.uid }),
            };
          }
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
        case "delete_corpus_firmware":
          if ("uid" in input) {
            path = `/rest/firmware/${input.uid}`;
            method = "DELETE";
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
      if (payload !== undefined && operation !== "upload_corpus_firmware")
        factJsonBytes(payload);
      const serialized =
        payload === undefined ? undefined : JSON.stringify(payload);
      const wireBudget =
        (upload === undefined
          ? undefined
          : FACT_LIMITS.jsonBytes +
            4 * Math.ceil(snapshot!.bytes.length / 3)) ??
        FACT_LIMITS.jsonBytes +
          (operation === "download_corpus_binary"
            ? 4 * Math.ceil(FACT_LIMITS.rawBytes / 3)
            : 0);
      delivered = true;
      const response = await fetch(url, {
        method,
        headers: {
          ...(connection.authorization === undefined
            ? {}
            : { Authorization: connection.authorization }),
          ...(serialized === undefined && upload === undefined
            ? {}
            : { "Content-Type": "application/json" }),
        },
        ...(upload === undefined
          ? serialized === undefined
            ? {}
            : { body: serialized }
          : { body: upload.body, duplex: "half" }),
        redirect: "manual",
        signal,
      });
      httpStatus = response.status;
      const raw = await readFactResponse(response, wireBudget, signal);
      rawDigest = factHash(raw);
      const parsedEnvelope = await this.parser.parse(
        raw,
        operation === "upload_corpus_firmware"
          ? "upload-echo"
          : operation === "download_corpus_binary",
        signal,
      );
      if (parsedEnvelope.cleanupDiagnostic !== undefined)
        limitations.push(parsedEnvelope.cleanupDiagnostic);
      let data = parsedEnvelope.data;
      observedData = data;
      if (
        operation === "upload_corpus_firmware" &&
        data !== null &&
        typeof data === "object" &&
        !Array.isArray(data) &&
        data.request !== null &&
        typeof data.request === "object" &&
        !Array.isArray(data.request) &&
        Object.hasOwn(data.request, "binary")
      ) {
        const { binary: _echo, ...request } = data.request;
        data.request = {
          ...request,
          binary_observation: {
            encoded_chars: parsedEnvelope.binaryEncodedChars,
            decoded_bytes: parsedEnvelope.binaryDecodedBytes,
            sha256: parsedEnvelope.binarySha256,
            representation: "base64 omitted from retained Evidence",
          },
        };
      }
      const outcome = validateFactProducerResponse(
        operation,
        input,
        data,
        response.status,
      );
      collectionDisposition = outcome.collectionDisposition;
      if (outcome.state === "failed" || outcome.state === "unknown")
        return finish(outcome.state, data, outcome.diagnostics);
      if (operation === "upload_corpus_firmware" && snapshot !== undefined) {
        if (
          data === null ||
          typeof data !== "object" ||
          Array.isArray(data) ||
          data.uid !== factUid(snapshot.bytes)
        )
          return finish("unknown", data, [
            "Uploaded byte identity does not match the producer UID",
          ]);
      }
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
