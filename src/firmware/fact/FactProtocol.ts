import { createHash } from "node:crypto";
import { jsonValueSchema, type JsonValue } from "../../domain/jsonValue.js";
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

/** Only the explicitly supplied transport key is secret; firmware findings are preserved. */
export const factRedactor = (secret: string | undefined) => {
  const variants =
    secret === undefined
      ? []
      : [
          secret,
          encodeURIComponent(secret),
          Buffer.from(secret).toString("base64"),
          Buffer.from(secret).toString("hex"),
          JSON.stringify(secret).slice(1, -1),
        ];
  const percent =
    secret === undefined
      ? undefined
      : new RegExp(
          [...Buffer.from(secret)]
            .map((byte) => {
              const char = String.fromCharCode(byte);
              const escaped = char.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
              return `(?:${escaped}|%${byte.toString(16).padStart(2, "0")})`;
            })
            .join(""),
          "giu",
        );
  const redact = (text: string) => {
    for (const value of variants)
      if (value.length) text = text.split(value).join("[REDACTED]");
    return percent === undefined ? text : text.replace(percent, "[REDACTED]");
  };
  const value = (input: JsonValue): JsonValue =>
    typeof input === "string"
      ? redact(input)
      : Array.isArray(input)
        ? input.map(value)
        : input !== null && typeof input === "object"
          ? Object.fromEntries(
              Object.entries(input).map(([key, item]) => [
                redact(key),
                value(item),
              ]),
            )
          : input;
  return { text: redact, value };
};

/** Bound incoming bytes before retaining or parsing the producer envelope. */
export async function readFactResponse(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<Buffer> {
  const length = response.headers.get("content-length");
  if (length !== null && Number(length) > maxBytes)
    throw Error("FACT response exceeds its wire byte budget");
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for (;;) {
      signal.throwIfAborted();
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > maxBytes)
        throw Error("FACT response exceeds its wire byte budget");
      chunks.push(Buffer.from(item.value));
    }
    return Buffer.concat(chunks, size);
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
export const parseFactJson = (bytes: Buffer): JsonValue =>
  jsonValueSchema.parse(JSON.parse(bytes.toString("utf8")));
export const factResult = (
  input: Parameters<typeof firmwareCorpusResultSchema.parse>[0],
) => firmwareCorpusResultSchema.parse(input);
