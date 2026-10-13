import { createHash } from "node:crypto";
import type { JsonValue } from "../../domain/jsonValue.js";
import { firmwareCorpusResultSchema } from "../../domain/corpus/firmwareCorpus.js";

/** Raw binary and JSON envelope constraints; base64 expansion is measured separately. */
export const FACT_LIMITS = {
  rawBytes: 128 * 1024 * 1024,
  jsonBytes: 8 * 1024 * 1024,
  deadlineMs: 120_000,
  memoryBytes: 1024 * 1024 * 1024,
  outputBytes: 256 * 1024 * 1024,
  outputEntries: 10_000,
} as const;
export const factHash = (bytes: Uint8Array | string): string =>
  createHash("sha256").update(bytes).digest("hex");
export const factUid = (bytes: Uint8Array): string =>
  `${factHash(bytes)}_${bytes.byteLength}`;

/** A response reader remains owned until cancellation and lock release succeed. */
export class FactResponseResources {
  private readonly readers = new Set<ReadableStreamDefaultReader<Uint8Array>>();
  get pendingResources(): string[] {
    return [...this.readers].map(() => "FACT HTTP response body");
  }
  acquire(response: Response) {
    const reader = response.body?.getReader();
    if (reader !== undefined) this.readers.add(reader);
    return reader;
  }
  async release(
    reader: ReadableStreamDefaultReader<Uint8Array>,
  ): Promise<void> {
    // Retain the exact reader, including its lock, if cancellation fails.
    await reader.cancel();
    reader.releaseLock();
    this.readers.delete(reader);
  }
  async close(): Promise<void> {
    const failures: unknown[] = [];
    for (const reader of this.readers) {
      try {
        await this.release(reader);
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length)
      throw new AggregateError(
        failures,
        "FACT response body cleanup remains unresolved",
      );
  }
}

/** Bound incoming bytes before retaining or parsing the producer envelope. */
export async function readFactResponse(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
  resources: FactResponseResources,
): Promise<Buffer> {
  const reader = resources.acquire(response);
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    const length = response.headers.get("content-length");
    if (length !== null && Number(length) > maxBytes)
      throw Error("FACT response exceeds its wire byte budget");
    if (!reader) return Buffer.alloc(0);
    for (;;) {
      signal.throwIfAborted();
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > maxBytes)
        throw Error("FACT response exceeds its wire byte budget");
      chunks.push(Buffer.from(item.value));
    }
    const owned = Buffer.allocUnsafeSlow(size);
    let at = 0;
    for (const chunk of chunks) {
      chunk.copy(owned, at);
      at += chunk.length;
    }
    chunks.length = 0;
    return owned;
  } finally {
    // Cleanup uncertainty is reported by the resource owner without replacing
    // useful observed bytes or the original admission/transport failure.
    if (reader !== undefined)
      await resources.release(reader).catch(() => undefined);
  }
}
export const factResult = (
  input: Parameters<typeof firmwareCorpusResultSchema.parse>[0],
) => firmwareCorpusResultSchema.parse(input);
