import { expect, it } from "vitest";
import { createHash } from "node:crypto";
import { PassThrough, Readable } from "node:stream";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { readUnblobSystemdFrames } from "./UnblobSystemdProtocol.js";

const frameBytes = (
  entries: readonly {
    kind: number;
    path: string;
    bytes?: Buffer;
    target?: string;
  }[],
) => {
  const report = Buffer.from("[]");
  const payloads = entries.map(
    ({ kind, path, bytes = Buffer.alloc(0), target = "" }) => {
      const pathBytes = Buffer.from(path);
      const targetBytes = Buffer.from(target);
      const header = Buffer.alloc(45);
      header.writeUInt8(kind, 0);
      header.writeUInt16BE(pathBytes.length, 1);
      header.writeUInt16BE(targetBytes.length, 3);
      header.writeBigUInt64BE(BigInt(bytes.length), 5);
      createHash("sha256").update(bytes).digest().copy(header, 13);
      return Buffer.concat([header, pathBytes, targetBytes, bytes]);
    },
  );
  const totalBytes = entries.reduce(
    (sum, entry) => sum + (entry.bytes?.length ?? 0),
    0,
  );
  const prefix = Buffer.alloc(40);
  Buffer.from("REAUB1\0\0").copy(prefix, 0);
  prefix.writeInt32BE(0, 8);
  prefix.writeUInt32BE(0, 12);
  prefix.writeUInt32BE(0, 16);
  prefix.writeUInt32BE(report.length, 20);
  prefix.writeUInt32BE(0, 24);
  prefix.writeUInt32BE(entries.length, 28);
  prefix.writeBigUInt64BE(BigInt(totalBytes), 32);
  return Buffer.concat([prefix, report, ...payloads]);
};

const split = (value: Buffer): Readable =>
  Readable.from({
    async *[Symbol.asyncIterator]() {
      for (let offset = 0; offset < value.length; offset += 7)
        yield value.subarray(offset, Math.min(value.length, offset + 7));
    },
  });

it.each(["header", "report", "body", "end"] as const)(
  "cancels a pending %s read without destroying or continuing to consume the owned stream",
  async (stage) => {
    const stream = new PassThrough();
    const controller = new AbortController();
    const reason = { caller: "stopped" };
    const bytes = frameBytes(
      stage === "body"
        ? [{ kind: 1, path: "file", bytes: Buffer.from("ok") }]
        : [],
    );
    if (stage === "report") stream.write(bytes.subarray(0, 40));
    if (stage === "body") stream.write(bytes.subarray(0, bytes.length - 1));
    if (stage === "end") stream.write(bytes);
    const frames = readUnblobSystemdFrames(stream, {
      maxBytes: 100,
      maxEntries: 8,
      signal: controller.signal,
    });
    let pending: Promise<unknown>;
    if (stage === "body") {
      await frames.next();
      const entry = await frames.next();
      if (entry.value?.type !== "file") throw Error("Expected file frame");
      const body = entry.value.bytes;
      pending = (async () => {
        for await (const _chunk of body) {
          /* Drain the declared body. */
        }
      })();
    } else {
      if (stage === "end") await frames.next();
      pending = frames.next();
    }
    const observed = pending.catch((cause: unknown) => cause);
    try {
      await new Promise<void>((resolve) => setImmediate(resolve));
      controller.abort(reason);
      const timeout = Symbol("pending parser did not cancel");
      const failure = await Promise.race([
        observed,
        new Promise((resolve) => setTimeout(() => resolve(timeout), 100)),
      ]);
      expect(failure).toBeInstanceOf(AnalysisCancelledError);
      expect(failure).toMatchObject({ cause: reason });
      expect(stream.destroyed).toBe(false);
      stream.write("late");
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(stream.readableLength).toBe(4);
      expect(stream.listenerCount("readable")).toBe(0);
      expect(stream.listenerCount("error")).toBe(0);
    } finally {
      stream.end();
      await observed;
      await frames.return(undefined);
      stream.destroy();
    }
  },
);

it.each(["end", "destroy", "error"] as const)(
  "requires physical EOF after a complete result frame (%s)",
  async (completion) => {
    const stream = new PassThrough();
    const frames = readUnblobSystemdFrames(stream, {
      maxBytes: 100,
      maxEntries: 8,
    });
    stream.write(frameBytes([]));
    expect((await frames.next()).value).toMatchObject({ type: "result" });
    const pending = frames.next();
    const observed = pending.catch((cause: unknown) => cause);
    const transportError = Error("pipe failed before EOF");
    if (completion === "end") stream.end();
    else stream.destroy(completion === "error" ? transportError : undefined);
    const result = await observed;
    if (completion === "end")
      expect(result).toEqual({ done: true, value: undefined });
    else if (completion === "error") expect(result).toBe(transportError);
    else expect(result).toMatchObject({ _tag: "AnalysisOutputError" });
    expect(stream.listenerCount("readable")).toBe(0);
    await frames.return(undefined);
    stream.destroy();
  },
);

it("streams bounded report and file frames, preserving bytes and metadata", async () => {
  const bytes = Buffer.from("verified firmware payload");
  const frames = readUnblobSystemdFrames(
    split(
      frameBytes([
        { kind: 1, path: "nested/output.bin", bytes },
        { kind: 2, path: "link", target: "nested/output.bin" },
      ]),
    ),
    { maxBytes: 1024, maxEntries: 8 },
  );
  const result = await frames.next();
  expect(result.value).toMatchObject({
    type: "result",
    exitCode: 0,
    rawReport: [],
    entryCount: 2,
    totalBytes: bytes.length,
  });
  const file = await frames.next();
  expect(file.value).toMatchObject({
    type: "file",
    relativePath: "nested/output.bin",
    size: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
  if (file.value?.type !== "file") throw new Error("Expected file frame");
  const receivedChunks: Buffer[] = [];
  for await (const chunk of file.value.bytes) receivedChunks.push(chunk);
  const received = Buffer.concat(receivedChunks);
  expect(received).toEqual(bytes);
  expect((await frames.next()).value).toMatchObject({
    type: "unpublished",
    relativePath: "link",
    kind: "symlink",
    linkTarget: "nested/output.bin",
  });
  expect(await frames.next()).toMatchObject({ done: true });
});

it("rejects traversal before exposing a path and rejects a byte total above the admitted ceiling", async () => {
  const traversal = readUnblobSystemdFrames(
    split(frameBytes([{ kind: 2, path: "../escape", target: "/etc/passwd" }])),
    { maxBytes: 1024, maxEntries: 8 },
  );
  await traversal.next();
  await expect(traversal.next()).rejects.toThrow(/unsafe output path/u);

  const oversized = readUnblobSystemdFrames(
    split(
      frameBytes([{ kind: 1, path: "large.bin", bytes: Buffer.alloc(12) }]),
    ),
    { maxBytes: 8, maxEntries: 8 },
  );
  await expect(oversized.next()).rejects.toThrow(/byte budget/u);
});

it("rejects an entry-count mutation from the producer before reading any entry body", async () => {
  const mutated = frameBytes([
    { kind: 1, path: "file", bytes: Buffer.from("ok") },
  ]);
  mutated.writeUInt32BE(513, 28);
  const parser = readUnblobSystemdFrames(split(mutated), {
    maxBytes: 1024,
    maxEntries: 512,
  });
  await expect(parser.next()).rejects.toThrow(/entry budget exceeded/u);
});

it("rejects truncation, digest mismatch, and trailing frame bytes", async () => {
  const valid = frameBytes([
    { kind: 1, path: "file", bytes: Buffer.from("ok") },
  ]);
  const truncated = readUnblobSystemdFrames(
    split(valid.subarray(0, valid.length - 1)),
    {
      maxBytes: 100,
      maxEntries: 8,
    },
  );
  await truncated.next();
  const entry = await truncated.next();
  if (entry.value?.type !== "file") throw new Error("Expected file frame");
  const consume = async () => {
    for await (const _chunk of entry.value.bytes) {
      // Consume the complete body to observe a premature end of stream.
    }
  };
  await expect(consume()).rejects.toThrow(/truncated/u);

  const wrongDigest = Buffer.from(
    frameBytes([{ kind: 1, path: "file", bytes: Buffer.from("ok") }]),
  );
  const finalByte = wrongDigest.length - 1;
  wrongDigest[finalByte] = wrongDigest[finalByte]! ^ 1;
  const withWrongDigest = readUnblobSystemdFrames(split(wrongDigest), {
    maxBytes: 100,
    maxEntries: 8,
  });
  await withWrongDigest.next();
  const wrongFile = await withWrongDigest.next();
  if (wrongFile.value?.type !== "file") throw new Error("Expected file frame");
  const consumeWrongDigest = async () => {
    for await (const _chunk of wrongFile.value.bytes) {
      // Consume the complete body to verify the advertised digest.
    }
  };
  await expect(consumeWrongDigest()).rejects.toThrow(/digest disagrees/u);

  const trailing = Buffer.concat([frameBytes([]), Buffer.from("extra")]);
  const withTrailing = readUnblobSystemdFrames(split(trailing), {
    maxBytes: 100,
    maxEntries: 8,
  });
  await withTrailing.next();
  await expect(withTrailing.next()).rejects.toThrow(/trailing/u);
});

it("fuzzes malformed framed headers without leaking parser exceptions", async () => {
  let state = 0x51a7;
  const random = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state & 0xff;
  };
  for (let sample = 0; sample < 256; sample += 1) {
    const malformed = Buffer.alloc(64);
    for (let index = 0; index < malformed.length; index += 1)
      malformed[index] = random();
    const parser = readUnblobSystemdFrames(split(malformed), {
      maxBytes: 1024,
      maxEntries: 8,
    });
    await expect(parser.next()).rejects.toBeInstanceOf(Error);
  }
});
