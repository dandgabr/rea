import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import {
  publishBinwalkNgFiles,
  verifyBinwalkNgCarving,
} from "./BinwalkNgArtifacts.js";

it("requires actual source bytes, bounds and a nonempty regular carving before assigning selected-root lineage", async () => {
  const root = await createTestTempDirectory("rea-ng-lineage-");
  const inputPath = join(root, "input.bin"),
    path = join(root, "input.bin_2_gzip.raw");
  await writeFile(inputPath, "abcdef");
  await writeFile(path, "cd");
  const scope = new ArtifactResourceScope();
  const context = {
    inputPath,
    inputSize: 6,
    rootOffset: 16,
    scope,
    signal: new AbortController().signal,
    operation: "carve_firmware",
    entry: {
      path,
      relativePath: "input.bin_2_gzip.raw",
      kind: "file" as const,
      size: 2,
      linkTarget: null,
    },
  };
  try {
    expect(await verifyBinwalkNgCarving(context)).toEqual({
      local_range: { offset: 2, length: 2 },
      original_file_range: { offset: 18, length: 2 },
    });
    expect(
      await verifyBinwalkNgCarving({ ...context, rootOffset: null }),
    ).toEqual({
      local_range: { offset: 2, length: 2 },
      original_file_range: null,
    });
    await writeFile(path, "zz");
    expect(await verifyBinwalkNgCarving(context)).toBeNull();
    expect(
      await verifyBinwalkNgCarving({
        ...context,
        entry: { ...context.entry, size: 0 },
      }),
    ).toBeNull();
    expect(
      await verifyBinwalkNgCarving({
        ...context,
        entry: { ...context.entry, kind: "symlink" },
      }),
    ).toBeNull();
    expect(
      await verifyBinwalkNgCarving({ ...context, inputSize: 3 }),
    ).toBeNull();
  } finally {
    await scope.close();
  }
});

it("retains failed descriptor owners and closes all comparison handles before reporting incomplete cleanup", async () => {
  const root = await createTestTempDirectory("rea-ng-lineage-cleanup-");
  const inputPath = join(root, "input.bin"),
    path = join(root, "input.bin_0_gzip.raw");
  await writeFile(inputPath, "same");
  await writeFile(path, "same");
  const scope = new ArtifactResourceScope();
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(new Error("injected close failure"));
  try {
    await expect(
      verifyBinwalkNgCarving({
        inputPath,
        inputSize: 4,
        rootOffset: 0,
        scope,
        signal: new AbortController().signal,
        operation: "carve_firmware",
        entry: {
          path,
          relativePath: "input.bin_0_gzip.raw",
          kind: "file",
          size: 4,
          linkTarget: null,
        },
      }),
    ).rejects.toMatchObject({
      cleanupIncomplete: true,
      cleanupResources: [inputPath],
    });
    expect(close).toHaveBeenCalledTimes(2);
    await scope.retryCleanup();
    expect(close).toHaveBeenCalledTimes(3);
  } finally {
    close.mockRestore();
    await scope.close();
  }
});

it("preserves durably published files when commit reports a later cleanup failure that rollback can resolve", async () => {
  const root = await createTestTempDirectory("rea-ng-publish-cleanup-");
  const path = join(root, "input.raw"),
    outputDirectory = join(root, "output");
  await writeFile(path, "verified");
  const original = SafeOutputTree.prototype.commit;
  const commit = vi
    .spyOn(SafeOutputTree.prototype, "commit")
    .mockImplementation(async function (this: SafeOutputTree) {
      await original.call(this);
      throw new Error("injected after durable commit");
    });
  let owned: SafeOutputTree | undefined;
  try {
    const result = await publishBinwalkNgFiles({
      outputDirectory,
      entries: [
        {
          path,
          relativePath: "input.raw",
          size: 8,
          kind: "file",
          linkTarget: null,
        },
      ],
      signal: new AbortController().signal,
      operation: "carve_firmware",
      ownTree: (tree) => {
        owned = tree;
      },
      releaseTree: () => {
        owned = undefined;
      },
    });
    expect(result.published_bytes).toBe(8);
    expect(await readFile(join(outputDirectory, "input.raw"), "utf8")).toBe(
      "verified",
    );
    expect(owned).toBeUndefined();
  } finally {
    commit.mockRestore();
    await owned?.rollback();
  }
});
