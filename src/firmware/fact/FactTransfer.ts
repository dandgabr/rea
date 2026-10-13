import type { JsonValue } from "../../domain/jsonValue.js";
import { FACT_LIMITS } from "./FactProtocol.js";

/** Measure JSON escaping and UTF-8 before allocating its serialized representation. */
export function factJsonBytes(value: JsonValue): number {
  const pending: JsonValue[] = [value];
  let bytes = 0;
  while (pending.length) {
    const item = pending.pop()!;
    if (typeof item === "string") bytes += factStringBytes(item);
    else if (item === null) bytes += 4;
    else if (typeof item === "boolean") bytes += item ? 4 : 5;
    else if (typeof item === "number") bytes += String(item).length;
    else if (Array.isArray(item)) {
      bytes += 2 + Math.max(0, item.length - 1);
      for (const child of item) pending.push(child);
    } else {
      const keys = Object.keys(item);
      bytes += 2 + Math.max(0, keys.length - 1);
      for (const key of keys) {
        bytes += factStringBytes(key) + 1;
        pending.push(item[key]!);
      }
    }
    if (bytes > FACT_LIMITS.jsonBytes)
      throw Error("FACT nonbinary JSON metadata exceeds its byte budget");
  }
  return bytes;
}

function factStringBytes(value: string): number {
  let bytes = 2;
  for (let at = 0; at < value.length; at++) {
    const code = value.charCodeAt(at);
    if (code === 34 || code === 92 || [8, 9, 10, 12, 13].includes(code))
      bytes += 2;
    else if (code < 32) bytes += 6;
    else if (code < 128) bytes++;
    else if (code < 2048) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(at + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        at++;
      } else bytes += 6;
    } else if (code >= 0xdc00 && code <= 0xdfff) bytes += 6;
    else bytes += 3;
    if (bytes > FACT_LIMITS.jsonBytes)
      throw Error("FACT nonbinary JSON metadata exceeds its byte budget");
  }
  return bytes;
}

/** Metadata and the actual binary expansion have independent allocation bounds. */
export function factUploadBody(
  metadata: Record<string, JsonValue>,
  bytes: Buffer,
) {
  const metadataBytes = factJsonBytes({ ...metadata, binary: "" });
  if (bytes.length > FACT_LIMITS.rawBytes)
    throw Error("FACT upload exceeds its raw byte budget");
  const envelope = JSON.stringify({ ...metadata, binary: "" });
  function* chunks() {
    yield Buffer.from(envelope.slice(0, -2));
    // Divisible by three: each bounded chunk is an independent canonical quartet sequence.
    for (let at = 0; at < bytes.length; at += 65535)
      yield Buffer.from(bytes.subarray(at, at + 65535).toString("base64"));
    yield Buffer.from('"}');
  }
  const producer = chunks();
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      const next = producer.next();
      if (next.done) controller.close();
      else controller.enqueue(next.value);
    },
    cancel() {
      producer.return(undefined);
    },
  });
  return { body, wireBytes: metadataBytes + 4 * Math.ceil(bytes.length / 3) };
}
