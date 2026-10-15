import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { expect, it } from "vitest";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { consumeBinwalkNgTransfer } from "./BinwalkNgTransfer.js";

const magic = Buffer.from("REABWNG1");
const frame = (header: object, payload = Buffer.alloc(0)) => {
  const json = Buffer.from(JSON.stringify(header));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(json.length);
  return Buffer.concat([length, json, payload]);
};

it("streams framed files into SafeOutputTree and enforces aggregate transfer ceilings", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-binwalk-ng-transfer-"));
  const output = join(root, "output");
  const bytes = Buffer.from("bounded producer output");
  const digest = createHash("sha256").update(bytes).digest("hex");
  const input = Readable.from([
    magic,
    frame(
      {
        type: "file",
        path: "pass/carved.bin",
        bytes: bytes.length,
        sha256: digest,
      },
      bytes,
    ),
    frame({ type: "end", files: 1, bytes: bytes.length }),
  ]);
  let tree: SafeOutputTree | undefined;
  try {
    tree = await SafeOutputTree.create(output);
    const result = await consumeBinwalkNgTransfer(input, tree, {
      maxBytes: bytes.length,
      maxFiles: 1,
      maxEntries: 2,
      signal: AbortSignal.timeout(2_000),
    });
    await tree.commit();
    expect(result).toEqual({ files: 1, bytes: bytes.length });
    expect(await readFile(join(output, "pass", "carved.bin"))).toEqual(bytes);
  } finally {
    await tree?.rollback();
    await rm(root, { recursive: true, force: true });
  }
});

it("rejects a framed aggregate over budget before writing the offending file", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-binwalk-ng-transfer-"));
  const output = join(root, "output");
  const bytes = Buffer.from("too much");
  const input = Readable.from([
    magic,
    frame(
      {
        type: "file",
        path: "over.bin",
        bytes: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      },
      bytes,
    ),
  ]);
  let tree: SafeOutputTree | undefined;
  try {
    tree = await SafeOutputTree.create(output);
    await expect(
      consumeBinwalkNgTransfer(input, tree, {
        maxBytes: bytes.length - 1,
        maxFiles: 1,
        maxEntries: 1,
        signal: AbortSignal.timeout(2_000),
      }),
    ).rejects.toThrow(/aggregate byte budget/u);
  } finally {
    await tree?.rollback();
    await rm(root, { recursive: true, force: true });
  }
});

it("rejects producer bytes whose framed digest does not match", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-binwalk-ng-transfer-digest-"));
  const output = join(root, "output");
  const bytes = Buffer.from("producer bytes");
  const input = Readable.from([
    magic,
    frame(
      {
        type: "file",
        path: "payload.bin",
        bytes: bytes.length,
        sha256: "0".repeat(64),
      },
      bytes,
    ),
  ]);
  let tree: SafeOutputTree | undefined;
  try {
    tree = await SafeOutputTree.create(output);
    await expect(
      consumeBinwalkNgTransfer(input, tree, {
        maxBytes: 1024,
        maxFiles: 1,
        maxEntries: 1,
        signal: AbortSignal.timeout(2_000),
      }),
    ).rejects.toThrow(/disagrees with inventory/u);
  } finally {
    await tree?.rollback();
    await rm(root, { recursive: true, force: true });
  }
});

it("bounded transfer path fuzz refuses traversal, aliases and malformed frame lengths", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-binwalk-ng-transfer-fuzz-"));
  const cases = [
    "../escape",
    "a/../escape",
    "/absolute",
    "a//b",
    "./dot",
    "a/./b",
    ...Array.from(
      { length: 32 },
      (_, index) => `dir${index}/../../escape${index}`,
    ),
  ];
  try {
    for (const path of cases) {
      const tree = await SafeOutputTree.create(join(root, "output"));
      const input = Readable.from([
        magic,
        frame({
          type: "file",
          path,
          bytes: 0,
          sha256: createHash("sha256").update(Buffer.alloc(0)).digest("hex"),
        }),
      ]);
      try {
        await expect(
          consumeBinwalkNgTransfer(input, tree, {
            maxBytes: 0,
            maxFiles: 1,
            maxEntries: 4,
            signal: AbortSignal.timeout(2_000),
          }),
        ).rejects.toThrow(/path is not a relative normalized path/u);
      } finally {
        await tree.rollback();
      }
    }
    const tree = await SafeOutputTree.create(join(root, "malformed"));
    try {
      const invalidLength = Buffer.alloc(4);
      invalidLength.writeUInt32BE(16 * 1024 + 1);
      await expect(
        consumeBinwalkNgTransfer(Readable.from([magic, invalidLength]), tree, {
          maxBytes: 0,
          maxFiles: 0,
          maxEntries: 0,
          signal: AbortSignal.timeout(2_000),
        }),
      ).rejects.toThrow(/header exceeds its fixed limit/u);
    } finally {
      await tree.rollback();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
