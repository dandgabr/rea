import { Readable } from "node:stream";
import type { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import type { BinwalkNgAggregateBudget } from "./BinwalkNgAggregateBudget.js";

const MAGIC = Buffer.from("REABWNG1");
const MAX_HEADER_BYTES = 16 * 1024;

class FramedInput {
  readonly #iterator: AsyncIterator<Buffer | string>;
  #chunk: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  #offset = 0;
  #ended = false;
  #readBytes = 0;

  constructor(source: Readable) {
    this.#iterator = source[Symbol.asyncIterator]();
  }

  async readExact(size: number): Promise<Buffer> {
    const result = Buffer.allocUnsafe(size);
    let written = 0;
    while (written < size) {
      const chunk = await this.#take(size - written);
      if (chunk === undefined)
        throw new Error(
          `Binwalk-NG transfer ended inside a frame after ${this.#readBytes} bytes (needed ${size - written} more)`,
        );
      chunk.copy(result, written);
      written += chunk.length;
      this.#readBytes += chunk.length;
    }
    return result;
  }

  async *readPayload(size: number): AsyncGenerator<Buffer> {
    let remaining = size;
    while (remaining > 0) {
      const chunk = await this.#take(Math.min(remaining, 64 * 1024));
      if (chunk === undefined)
        throw new Error(
          `Binwalk-NG transfer payload is truncated after ${this.#readBytes} bytes (needed ${remaining} more)`,
        );
      remaining -= chunk.length;
      this.#readBytes += chunk.length;
      yield chunk;
    }
  }

  async assertEnd(): Promise<void> {
    if ((await this.#take(1)) !== undefined)
      throw new Error(
        "Binwalk-NG transfer has trailing bytes after its end frame",
      );
  }

  async #take(maximum: number): Promise<Buffer | undefined> {
    while (this.#offset === this.#chunk.length) {
      if (this.#ended) return undefined;
      const next = await this.#iterator.next();
      if (next.done) {
        this.#ended = true;
        return undefined;
      }
      this.#chunk = Buffer.isBuffer(next.value)
        ? next.value
        : Buffer.from(next.value);
      this.#offset = 0;
      if (this.#chunk.length === 0) continue;
    }
    const end = Math.min(this.#chunk.length, this.#offset + maximum);
    const part = this.#chunk.subarray(this.#offset, end);
    this.#offset = end;
    return part;
  }
}

type FileFrame = {
  readonly type: "file";
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
};
type EndFrame = {
  readonly type: "end";
  readonly files: number;
  readonly bytes: number;
};

const parseFrame = (input: Buffer): FileFrame | EndFrame => {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      input,
    );
  } catch (cause: unknown) {
    throw new Error("Binwalk-NG transfer frame is not valid UTF-8", { cause });
  }
  const raw: unknown = JSON.parse(text);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw))
    throw new Error("Binwalk-NG transfer frame must be an object");
  const value = raw as Record<string, unknown>;
  if (
    value.type === "file" &&
    typeof value.path === "string" &&
    value.path.length > 0 &&
    Number.isSafeInteger(value.bytes) &&
    (value.bytes as number) >= 0 &&
    typeof value.sha256 === "string" &&
    /^[a-f0-9]{64}$/u.test(value.sha256)
  )
    return value as FileFrame;
  if (
    value.type === "end" &&
    Number.isSafeInteger(value.files) &&
    (value.files as number) >= 0 &&
    Number.isSafeInteger(value.bytes) &&
    (value.bytes as number) >= 0
  )
    return value as EndFrame;
  throw new Error("Binwalk-NG transfer frame is malformed");
};

/** Stream validated producer frames into an owned tree under aggregate ceilings. */
export const consumeBinwalkNgTransfer = async (
  source: Readable,
  tree: SafeOutputTree,
  limits: {
    readonly maxBytes: number;
    readonly maxFiles: number;
    readonly maxEntries: number;
    readonly aggregateBudget?: BinwalkNgAggregateBudget;
    readonly signal: AbortSignal;
  },
): Promise<{ readonly files: number; readonly bytes: number }> => {
  if (
    !Number.isSafeInteger(limits.maxBytes) ||
    limits.maxBytes < 0 ||
    !Number.isSafeInteger(limits.maxFiles) ||
    limits.maxFiles < 0
  )
    throw new Error("Invalid Binwalk-NG transfer ceilings");
  const input = new FramedInput(source);
  if (!(await input.readExact(MAGIC.length)).equals(MAGIC))
    throw new Error("Binwalk-NG transfer magic is invalid");
  let files = 0;
  let bytes = 0;
  const directories = new Set<string>();
  while (true) {
    limits.signal.throwIfAborted();
    const headerLength = (await input.readExact(4)).readUInt32BE();
    if (headerLength < 2 || headerLength > MAX_HEADER_BYTES)
      throw new Error("Binwalk-NG transfer header exceeds its fixed limit");
    const frame = parseFrame(await input.readExact(headerLength));
    if (frame.type === "end") {
      if (frame.files !== files || frame.bytes !== bytes)
        throw new Error(
          "Binwalk-NG transfer totals disagree with received files",
        );
      await input.assertEnd();
      return { files, bytes };
    }
    if (files >= limits.maxFiles)
      throw new Error("Binwalk-NG transfer exceeds aggregate file budget");
    if (frame.bytes > limits.maxBytes - bytes)
      throw new Error("Binwalk-NG transfer exceeds aggregate byte budget");
    const parts = frame.path.split("/");
    if (
      frame.path.startsWith("/") ||
      parts.some((part) => part.length === 0 || part === "." || part === "..")
    )
      throw new Error(
        "Binwalk-NG transfer path is not a relative normalized path",
      );
    for (let index = 1; index < parts.length; index++)
      directories.add(parts.slice(0, index).join("/"));
    if (directories.size + files + 1 > limits.maxEntries)
      throw new Error("Binwalk-NG transfer exceeds aggregate entry budget");
    limits.aggregateBudget?.admitTransfer(frame.path, frame.bytes);
    await tree.write(
      frame.path,
      Readable.from(input.readPayload(frame.bytes)),
      { sha256: frame.sha256, bytes: frame.bytes },
      limits.signal,
    );
    files += 1;
    bytes += frame.bytes;
  }
};
