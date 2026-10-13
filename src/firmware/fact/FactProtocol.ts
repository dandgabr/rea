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
          Buffer.from(secret).toString("hex").toUpperCase(),
          JSON.stringify(secret).slice(1, -1),
        ];
  const percent =
    secret === undefined
      ? undefined
      : new RegExp(
          [...secret]
            .map((char) => {
              const escaped = char.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
              const encoded = [...Buffer.from(char)]
                .map(
                  (byte) =>
                    "%" +
                    byte
                      .toString(16)
                      .padStart(2, "0")
                      .replace(
                        /[a-f]/gu,
                        (hex) => `[${hex}${hex.toUpperCase()}]`,
                      ),
                )
                .join("");
              return `(?:${escaped}|${encoded})`;
            })
            .join(""),
          "gu",
        );
  const redact = (text: string) => {
    for (const value of variants)
      if (value.length) text = text.split(value).join("[REDACTED]");
    return percent === undefined ? text : text.replace(percent, "[REDACTED]");
  };
  // The parser transfers exclusive ownership. Redact that representation once,
  // rather than allocating a second expanded producer graph.
  const value = (input: JsonValue): JsonValue => {
    if (secret === undefined) return input;
    if (typeof input === "string") return redact(input);
    const pending: JsonValue[] = [input];
    while (pending.length) {
      const item = pending.pop();
      if (Array.isArray(item)) {
        for (let at = 0; at < item.length; at++) {
          const child = item[at]!;
          if (typeof child === "string") item[at] = redact(child);
          else if (child !== null && typeof child === "object")
            pending.push(child);
        }
      } else if (item !== null && typeof item === "object") {
        for (const key of Object.keys(item)) {
          const child = item[key]!;
          const redacted = typeof child === "string" ? redact(child) : child;
          const replacement = redact(key);
          if (replacement !== key) {
            delete item[key];
            let selected = replacement;
            let suffix = 1;
            while (Object.hasOwn(item, selected))
              selected = `${replacement} (${suffix++})`;
            Object.defineProperty(item, selected, {
              value: redacted,
              enumerable: true,
              writable: true,
              configurable: true,
            });
          } else
            Object.defineProperty(item, key, {
              value: redacted,
              enumerable: true,
              writable: true,
              configurable: true,
            });
          if (child !== null && typeof child === "object") pending.push(child);
        }
      }
    }
    return input;
  };
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
    const owned = Buffer.allocUnsafeSlow(size);
    let at = 0;
    for (const chunk of chunks) {
      chunk.copy(owned, at);
      at += chunk.length;
    }
    chunks.length = 0;
    return owned;
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
export const factResult = (
  input: Parameters<typeof firmwareCorpusResultSchema.parse>[0],
) => firmwareCorpusResultSchema.parse(input);
