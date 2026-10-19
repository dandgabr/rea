import { createHash } from "node:crypto";
import type { Readable } from "node:stream";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";

const MAGIC = Buffer.from("REAUB1\0\0", "ascii");
const HEADER_BYTES = 40;
const ENTRY_HEADER_BYTES = 45;
const MAX_TEXT_FRAME_BYTES = 8 * 1024 * 1024;
const MAX_STREAM_CHUNK_BYTES = 64 * 1024;

export type UnblobSystemdFrame =
  | {
      readonly type: "result";
      readonly exitCode: number;
      readonly stdout: Buffer;
      readonly stderr: Buffer;
      readonly rawReport: unknown;
      readonly auxiliary: Buffer;
      readonly entryCount: number;
      readonly totalBytes: number;
    }
  | {
      readonly type: "file";
      readonly relativePath: string;
      readonly size: number;
      readonly sha256: string;
      readonly bytes: AsyncIterable<Buffer>;
    }
  | {
      readonly type: "unpublished";
      readonly relativePath: string;
      readonly kind: "symlink" | "special";
      readonly size: number;
      readonly linkTarget: string | null;
    }
  | { readonly type: "directory"; readonly relativePath: string };

/** Decode a bounded framed stream from the isolated systemd service. File bodies stay streaming. */
export async function* readUnblobSystemdFrames(
  source: Readable,
  options: {
    maxBytes: number;
    maxEntries: number;
    operation?: string;
    signal?: AbortSignal;
  },
): AsyncGenerator<UnblobSystemdFrame> {
  const operation = options.operation ?? "extract_firmware";
  const reader = new FrameReader(source, operation, options.signal);
  const header = await reader.readExact(HEADER_BYTES);
  if (!header.subarray(0, MAGIC.length).equals(MAGIC))
    throw invalid(operation, "Unblob isolation stream has an invalid header");
  const exitCode = header.readInt32BE(8);
  const stdoutLength = header.readUInt32BE(12);
  const stderrLength = header.readUInt32BE(16);
  const reportLength = header.readUInt32BE(20);
  const auxiliaryLength = header.readUInt32BE(24);
  const entryCount = header.readUInt32BE(28);
  const totalBytesBig = header.readBigUInt64BE(32);
  if (
    stdoutLength > MAX_TEXT_FRAME_BYTES ||
    stderrLength > MAX_TEXT_FRAME_BYTES ||
    reportLength > MAX_TEXT_FRAME_BYTES ||
    auxiliaryLength > MAX_TEXT_FRAME_BYTES
  )
    throw invalid(
      operation,
      "Unblob isolation text frame exceeds its hard limit",
    );
  if (entryCount > options.maxEntries)
    throw invalid(
      operation,
      `Unblob output entry budget exceeded (${options.maxEntries})`,
    );
  if (totalBytesBig > BigInt(options.maxBytes))
    throw invalid(
      operation,
      `Unblob output byte budget exceeded (${options.maxBytes})`,
    );
  if (totalBytesBig > BigInt(Number.MAX_SAFE_INTEGER))
    throw invalid(
      operation,
      "Unblob output byte count is not safely representable",
    );

  const stdout = await reader.readExact(stdoutLength);
  const stderr = await reader.readExact(stderrLength);
  const reportBytes = await reader.readExact(reportLength);
  const auxiliary = await reader.readExact(auxiliaryLength);
  let rawReport: unknown;
  try {
    rawReport = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
        reportBytes,
      ),
    ) as unknown;
  } catch (cause: unknown) {
    throw invalid(
      operation,
      "Unblob isolation report is not complete valid UTF-8 JSON",
      cause,
    );
  }
  const totalBytes = Number(totalBytesBig);
  yield {
    type: "result",
    exitCode,
    stdout,
    stderr,
    rawReport,
    auxiliary,
    entryCount,
    totalBytes,
  };

  let observedBytes = 0;
  for (let index = 0; index < entryCount; index += 1) {
    const entry = await reader.readExact(ENTRY_HEADER_BYTES);
    const kind = entry.readUInt8(0);
    const pathLength = entry.readUInt16BE(1);
    const targetLength = entry.readUInt16BE(3);
    const sizeBig = entry.readBigUInt64BE(5);
    const sha256 = entry.subarray(13, 45).toString("hex");
    if (sizeBig > BigInt(Number.MAX_SAFE_INTEGER))
      throw invalid(
        operation,
        "Unblob output entry size is not safely representable",
      );
    const size = Number(sizeBig);
    const pathBytes = await reader.readExact(pathLength);
    const targetBytes = await reader.readExact(targetLength);
    const relativePath = decodeUtf8(pathBytes, operation, "output path");
    validateRelativePath(relativePath, operation);
    const linkTarget =
      targetLength === 0
        ? null
        : decodeUtf8(targetBytes, operation, "link target");

    if (kind === 1) {
      if (targetLength !== 0)
        throw invalid(
          operation,
          "Regular file frame unexpectedly contains a link target",
        );
      observedBytes += size;
      if (observedBytes > totalBytes)
        throw invalid(
          operation,
          "Unblob output frames exceed their declared aggregate size",
        );
      const content = reader.take(size);
      const hash = createHash("sha256");
      const checkedBytes = async function* () {
        let seen = 0;
        for await (const chunk of content) {
          seen += chunk.byteLength;
          hash.update(chunk);
          yield chunk;
        }
        if (seen !== size)
          throw invalid(
            operation,
            "Unblob output file length disagrees with its frame",
          );
        if (hash.digest("hex") !== sha256)
          throw invalid(
            operation,
            `Unblob output file digest disagrees: ${relativePath}`,
          );
      };
      yield { type: "file", relativePath, size, sha256, bytes: checkedBytes() };
    } else if (kind === 0) {
      if (size !== 0 || targetLength !== 0)
        throw invalid(
          operation,
          "Unblob directory frame contains unexpected data",
        );
      yield { type: "directory", relativePath };
    } else if (kind === 2 || kind === 3) {
      if (size !== 0)
        throw invalid(
          operation,
          "Unpublished Unblob entry unexpectedly contains file bytes",
        );
      if (kind === 2 && linkTarget === null)
        throw invalid(
          operation,
          "Unblob symlink frame omitted its link target",
        );
      if (kind === 3 && linkTarget !== null)
        throw invalid(
          operation,
          "Unblob special-file frame contains a link target",
        );
      yield {
        type: "unpublished",
        relativePath,
        kind: kind === 2 ? "symlink" : "special",
        size,
        linkTarget,
      };
    } else {
      throw invalid(
        operation,
        `Unblob output frame has unsupported kind ${kind}`,
      );
    }
  }
  if (observedBytes !== totalBytes)
    throw invalid(
      operation,
      "Unblob output frame bytes disagree with the declared aggregate size",
    );
  await reader.assertEnd();
}

class FrameReader {
  readonly #source: Readable;
  #buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  #offset = 0;
  #remaining = 0;

  constructor(
    source: Readable,
    readonly operation: string,
    readonly signal: AbortSignal | undefined,
  ) {
    this.#source = source;
  }

  async readExact(length: number): Promise<Buffer> {
    if (!Number.isSafeInteger(length) || length < 0)
      throw invalid(this.operation, "Unblob frame contains an invalid length");
    if (this.#remaining !== 0)
      throw invalid(
        this.operation,
        "Previous Unblob file frame was not consumed",
      );
    const chunks: Buffer[] = [];
    let remaining = length;
    while (remaining > 0) {
      this.#checkAbort();
      if (this.#offset >= this.#buffer.length) {
        const next = await this.#next();
        if (next.done)
          throw invalid(this.operation, "Unblob isolation stream is truncated");
        this.#buffer = Buffer.from(
          next.value.buffer,
          next.value.byteOffset,
          next.value.byteLength,
        );
        this.#offset = 0;
      }
      const count = Math.min(remaining, this.#buffer.length - this.#offset);
      chunks.push(this.#buffer.subarray(this.#offset, this.#offset + count));
      this.#offset += count;
      remaining -= count;
    }
    return Buffer.concat(chunks, length);
  }

  take(length: number): AsyncIterable<Buffer> {
    if (this.#remaining !== 0)
      throw invalid(
        this.operation,
        "Previous Unblob file frame was not consumed",
      );
    this.#remaining = length;
    const reader = this;
    return {
      async *[Symbol.asyncIterator]() {
        while (reader.#remaining > 0) {
          reader.#checkAbort();
          if (reader.#offset >= reader.#buffer.length) {
            const next = await reader.#next();
            if (next.done)
              throw invalid(reader.operation, "Unblob file frame is truncated");
            reader.#buffer = Buffer.from(
              next.value.buffer,
              next.value.byteOffset,
              next.value.byteLength,
            );
            reader.#offset = 0;
          }
          const count = Math.min(
            reader.#remaining,
            reader.#buffer.length - reader.#offset,
            MAX_STREAM_CHUNK_BYTES,
          );
          yield reader.#buffer.subarray(reader.#offset, reader.#offset + count);
          reader.#offset += count;
          reader.#remaining -= count;
        }
      },
    };
  }

  async assertEnd(): Promise<void> {
    this.#checkAbort();
    if (this.#remaining !== 0 || this.#offset !== this.#buffer.length)
      throw invalid(
        this.operation,
        "Unblob isolation stream has trailing frame bytes",
      );
    const extra = await this.#next();
    if (!extra.done)
      throw invalid(
        this.operation,
        "Unblob isolation stream has trailing frame bytes",
      );
  }

  /** Own a cancellable readable wait, without leaving iterator.next in flight.
   * The supervisor owns the pipe lifetime and any bounded post-protocol drain.
   */
  #next(): Promise<IteratorResult<Uint8Array>> {
    const source = this.#source;
    return new Promise((resolve, reject) => {
      const dispose = () => {
        source.off("readable", read);
        source.off("end", read);
        source.off("close", read);
        source.off("error", failed);
        this.signal?.removeEventListener("abort", read);
      };
      const failed = (cause: unknown) => {
        dispose();
        reject(cause);
      };
      const read = () => {
        try {
          this.#checkAbort();
          const value: unknown = source.read();
          if (value !== null) {
            if (!(value instanceof Uint8Array))
              throw invalid(
                this.operation,
                "Unblob protocol stream did not produce bytes",
              );
            dispose();
            resolve({ done: false, value });
          } else if (source.errored !== null) {
            failed(source.errored);
          } else if (source.readableEnded) {
            dispose();
            resolve({ done: true, value: undefined });
          } else if (source.destroyed || source.closed) {
            failed(
              invalid(
                this.operation,
                "Unblob isolation stream closed before EOF",
              ),
            );
          }
        } catch (cause: unknown) {
          failed(cause);
        }
      };
      source.on("readable", read);
      source.on("end", read);
      source.on("close", read);
      source.on("error", failed);
      this.signal?.addEventListener("abort", read, { once: true });
      read();
    });
  }

  #checkAbort(): void {
    if (this.signal?.aborted === true)
      throw new AnalysisCancelledError(this.operation, {
        cause: this.signal.reason,
      });
  }
}

const decodeUtf8 = (
  bytes: Buffer,
  operation: string,
  field: string,
): string => {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch (cause: unknown) {
    throw invalid(operation, `Unblob ${field} is not valid UTF-8`, cause);
  }
};

const validateRelativePath = (path: string, operation: string): void => {
  if (
    path.length === 0 ||
    path.includes("\0") ||
    path.includes("\\") ||
    path.startsWith("/") ||
    path
      .split("/")
      .some((part) => part.length === 0 || part === "." || part === "..")
  )
    throw invalid(
      operation,
      `Unblob isolation stream contains unsafe output path: ${path}`,
    );
};

const invalid = (operation: string, message: string, cause?: unknown) =>
  new AnalysisOutputError(
    operation,
    message,
    cause === undefined ? {} : { cause },
  );
