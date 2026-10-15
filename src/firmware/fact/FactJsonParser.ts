import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";
import type { JsonValue } from "../../domain/jsonValue.js";
import { FACT_LIMITS } from "./FactProtocol.js";
import { FACT_JSON_WORKER_SOURCE } from "./FactJsonWorkerSource.js";

/** Heap bound applies to the worker's V8 heap only; byte buffers have separate bounds. */
export const FACT_JSON_WORKER_HEAP = {
  maxOldGenerationSizeMb: 64,
  maxYoungGenerationSizeMb: 8,
  stackSizeMb: 4,
} as const;
export interface FactParsedEnvelope {
  readonly data: JsonValue;
  readonly binary: Buffer | undefined;
  readonly binaryEncodedChars: number;
  readonly binaryDecodedBytes: number;
  readonly binarySha256: string;
  readonly metadataBytes: number;
  readonly cleanupDiagnostic?: string;
}

/** Parse hostile envelopes outside the caller heap, retaining cleanup ownership on failure. */
export class FactJsonParser {
  private readonly pending = new Map<Worker, string>();
  constructor(
    readonly byteBudget: { rawBytes: number; jsonBytes: number } = FACT_LIMITS,
  ) {
    for (const [key, maximum] of [
      ["rawBytes", FACT_LIMITS.rawBytes],
      ["jsonBytes", FACT_LIMITS.jsonBytes],
    ] as const) {
      const value = byteBudget[key];
      if (!Number.isSafeInteger(value) || value < 1 || value > maximum)
        throw Error(
          "FACT parser byte policy exceeds the declared resource limits",
        );
    }
  }
  get pendingResources(): string[] {
    return [...this.pending.values()];
  }
  async close(): Promise<void> {
    const failures: unknown[] = [];
    for (const worker of this.pending.keys()) {
      try {
        await worker.terminate();
        this.pending.delete(worker);
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length)
      throw new AggregateError(
        failures,
        "FACT parser worker cleanup remains unresolved",
      );
  }
  async parse(
    raw: Buffer,
    binaryKind: boolean,
    signal: AbortSignal,
  ): Promise<FactParsedEnvelope> {
    signal.throwIfAborted();
    const binaryAllowed = binaryKind !== false;
    const binaryMode = binaryKind ? "download" : false;
    const wireLimit =
      this.byteBudget.jsonBytes +
      (binaryAllowed ? 4 * Math.ceil(this.byteBudget.rawBytes / 3) : 0);
    if (raw.length > wireLimit)
      throw Error("FACT response exceeds the binary/metadata wire byte budget");
    // The transfer takes ownership of an unpooled byte buffer; no worker copy is retained.
    const owned =
      raw.byteOffset === 0 && raw.byteLength === raw.buffer.byteLength
        ? raw
        : Buffer.allocUnsafeSlow(raw.length);
    if (owned !== raw) raw.copy(owned);
    const transferred = owned.buffer;
    if (!(transferred instanceof ArrayBuffer))
      throw Error(
        "FACT response buffer must have exclusive transferable ownership",
      );
    const worker = new Worker(FACT_JSON_WORKER_SOURCE, {
      eval: true,
      resourceLimits: FACT_JSON_WORKER_HEAP,
      workerData: {
        bytes: transferred,
        binaryAllowed,
        binaryMode,
        rawBytes: this.byteBudget.rawBytes,
        jsonBytes: this.byteBudget.jsonBytes,
        modules: [
          pathToFileURL(
            createRequire(import.meta.url).resolve("stream-json/parser.js"),
          ).href,
          pathToFileURL(createRequire(import.meta.url).resolve("stream-chain"))
            .href,
          pathToFileURL(
            createRequire(import.meta.url).resolve("stream-chain/fun.js"),
          ).href,
        ],
      },
      transferList: [transferred],
    });
    this.pending.set(worker, "FACT JSON parsing worker");
    let output: FactParsedEnvelope | undefined;
    let failure: unknown;
    try {
      output = await new Promise<FactParsedEnvelope>((resolve, reject) => {
        const onAbort = () =>
          reject(
            Error("FACT response parsing canceled; delivery remains unknown"),
          );
        signal.addEventListener("abort", onAbort, { once: true });
        const finish = () => signal.removeEventListener("abort", onAbort);
        worker.once("message", (message: unknown) => {
          finish();
          if (
            message === null ||
            typeof message !== "object" ||
            !("kind" in message)
          ) {
            reject(Error("FACT parser worker reply is malformed"));
            return;
          }
          if (message.kind === "failed" && "reason" in message) {
            reject(Error(String(message.reason)));
            return;
          }
          if (
            message.kind === "parsed" &&
            "data" in message &&
            "binary" in message &&
            message.binary instanceof Uint8Array &&
            "metadataBytes" in message &&
            typeof message.metadataBytes === "number" &&
            "binaryEncodedChars" in message &&
            typeof message.binaryEncodedChars === "number"
          )
            resolve({
              data: message.data as JsonValue,
              binary:
                binaryKind === true
                  ? Buffer.from(
                      message.binary.buffer,
                      message.binary.byteOffset,
                      message.binary.byteLength,
                    )
                  : undefined,
              metadataBytes: message.metadataBytes,
              binaryEncodedChars: message.binaryEncodedChars,
              binaryDecodedBytes:
                "binaryDecodedBytes" in message
                  ? Number(message.binaryDecodedBytes)
                  : 0,
              binarySha256:
                "binarySha256" in message ? String(message.binarySha256) : "",
            });
          else reject(Error("FACT parser worker reply is malformed"));
        });
        worker.once("error", (cause: Error) => {
          finish();
          reject(
            Error(
              `FACT parser worker memory or execution boundary failed: ${cause.message}`,
            ),
          );
        });
        worker.once("exit", (code) => {
          finish();
          reject(
            Error(
              `FACT parser worker exited before a complete response (${code})`,
            ),
          );
        });
        if (signal.aborted) onAbort();
      });
    } catch (cause) {
      failure = cause;
    }
    try {
      await worker.terminate();
      this.pending.delete(worker);
    } catch (cause) {
      if (output !== undefined)
        return {
          ...output,
          cleanupDiagnostic: `FACT parser worker cleanup failed; owner retained: ${cause instanceof Error ? cause.message : String(cause)}`,
        };
      if (failure === undefined) failure = cause;
    }
    if (failure !== undefined) throw failure;
    if (output === undefined)
      throw Error("FACT parser did not produce a complete envelope");
    return output;
  }
}
