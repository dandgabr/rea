import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { expect, it, vi } from "vitest";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { BinwalkNgAggregateBudget } from "./BinwalkNgAggregateBudget.js";
import { consumeBinwalkNgTransfer } from "./BinwalkNgTransfer.js";

const magic = Buffer.from("REABWNG1");
const frame = (
  header: object,
  payload: Buffer<ArrayBufferLike> = Buffer.alloc(0),
) => {
  const json = Buffer.from(JSON.stringify(header));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(json.length);
  return Buffer.concat([length, json, payload]);
};
const stream = (path: string, payload: Buffer) =>
  Readable.from([
    magic,
    frame(
      {
        type: "file",
        path,
        bytes: payload.length,
        sha256: createHash("sha256").update(payload).digest("hex"),
      },
      payload,
    ),
    frame({ type: "end", files: 1, bytes: payload.length }),
  ]);

it("rejects cumulative bytes in pass two before SafeOutputTree writes the file", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-ng-budget-bytes-"));
  const budget = new BinwalkNgAggregateBudget({
    artifactBytes: 3,
    artifactFiles: 2,
    reportBytes: 8,
    reportFiles: 2,
    entries: 16,
    childSnapshotBytes: 3,
    childSnapshotFiles: 2,
  });
  const first = await SafeOutputTree.create(join(root, "pass-0"));
  const second = await SafeOutputTree.create(join(root, "pass-1"));
  try {
    await consumeBinwalkNgTransfer(
      stream("artifacts/0000/first.bin", Buffer.from("ab")),
      first,
      {
        maxBytes: 11,
        maxFiles: 2,
        maxEntries: 16,
        aggregateBudget: budget,
        signal: AbortSignal.timeout(2_000),
      },
    );
    await first.commit();
    const write = vi.spyOn(second, "write");
    await expect(
      consumeBinwalkNgTransfer(
        stream("artifacts/0001/second.bin", Buffer.from("cd")),
        second,
        {
          maxBytes: 11,
          maxFiles: 2,
          maxEntries: 16,
          aggregateBudget: budget,
          signal: AbortSignal.timeout(2_000),
        },
      ),
    ).rejects.toThrow(/aggregate artifact byte budget/u);
    expect(write).not.toHaveBeenCalled();
    expect(
      await readFile(join(root, "pass-0", "artifacts", "0000", "first.bin")),
    ).toEqual(Buffer.from("ab"));
  } finally {
    await first.rollback();
    await second.rollback();
    await rm(root, { recursive: true, force: true });
  }
});

it("rejects cumulative entries across passes before writing", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-ng-budget-entries-"));
  const budget = new BinwalkNgAggregateBudget({
    artifactBytes: 20,
    artifactFiles: 3,
    reportBytes: 20,
    reportFiles: 2,
    entries: 4,
    childSnapshotBytes: 20,
    childSnapshotFiles: 1,
  });
  const first = await SafeOutputTree.create(join(root, "pass-0"));
  const second = await SafeOutputTree.create(join(root, "pass-1"));
  try {
    await consumeBinwalkNgTransfer(
      stream("artifacts/0000/a.bin", Buffer.from("a")),
      first,
      {
        maxBytes: 40,
        maxFiles: 4,
        maxEntries: 16,
        aggregateBudget: budget,
        signal: AbortSignal.timeout(2_000),
      },
    );
    await first.commit();
    const write = vi.spyOn(second, "write");
    await expect(
      consumeBinwalkNgTransfer(
        stream("artifacts/0001/b.bin", Buffer.from("b")),
        second,
        {
          maxBytes: 40,
          maxFiles: 4,
          maxEntries: 16,
          aggregateBudget: budget,
          signal: AbortSignal.timeout(2_000),
        },
      ),
    ).rejects.toThrow(/aggregate entry budget/u);
    expect(write).not.toHaveBeenCalled();
  } finally {
    await first.rollback();
    await second.rollback();
    await rm(root, { recursive: true, force: true });
  }
});

it("rejects cumulative artifact files across passes before writing", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-ng-budget-files-"));
  const budget = new BinwalkNgAggregateBudget({
    artifactBytes: 20,
    artifactFiles: 1,
    reportBytes: 20,
    reportFiles: 2,
    entries: 16,
    childSnapshotBytes: 20,
    childSnapshotFiles: 1,
  });
  const first = await SafeOutputTree.create(join(root, "pass-0"));
  const second = await SafeOutputTree.create(join(root, "pass-1"));
  try {
    await consumeBinwalkNgTransfer(
      stream("artifacts/0000/a.bin", Buffer.from("a")),
      first,
      {
        maxBytes: 40,
        maxFiles: 4,
        maxEntries: 16,
        aggregateBudget: budget,
        signal: AbortSignal.timeout(2_000),
      },
    );
    await first.commit();
    const write = vi.spyOn(second, "write");
    await expect(
      consumeBinwalkNgTransfer(
        stream("artifacts/0001/b.bin", Buffer.from("b")),
        second,
        {
          maxBytes: 40,
          maxFiles: 4,
          maxEntries: 16,
          aggregateBudget: budget,
          signal: AbortSignal.timeout(2_000),
        },
      ),
    ).rejects.toThrow(/aggregate artifact file budget/u);
    expect(write).not.toHaveBeenCalled();
  } finally {
    await first.rollback();
    await second.rollback();
    await rm(root, { recursive: true, force: true });
  }
});

it("rejects the next recursive snapshot before it is copied", () => {
  const budget = new BinwalkNgAggregateBudget({
    artifactBytes: 20,
    artifactFiles: 2,
    reportBytes: 20,
    reportFiles: 3,
    entries: 20,
    childSnapshotBytes: 3,
    childSnapshotFiles: 2,
  });
  budget.admitChildSnapshot(2);
  expect(() => budget.admitChildSnapshot(2)).toThrow(
    /recursive snapshots exceed aggregate byte budget/u,
  );
});

it("charges recursive snapshot files and directories to the aggregate entry ceiling", () => {
  const budget = new BinwalkNgAggregateBudget({
    artifactBytes: 20,
    artifactFiles: 2,
    reportBytes: 20,
    reportFiles: 3,
    entries: 4,
    childSnapshotBytes: 4,
    childSnapshotFiles: 2,
  });
  budget.admitChildSnapshot(1);
  expect(() => budget.admitChildSnapshot(1)).toThrow(
    /recursive snapshots exceed aggregate entry budget/u,
  );
});
