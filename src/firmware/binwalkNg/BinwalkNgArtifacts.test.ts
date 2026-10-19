import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, readdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { FirmwareFileAccess } from "../FirmwareFiles.js";
import {
  inspectBinwalkNgPng,
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
      sha256: createHash("sha256").update("cd").digest("hex"),
      local_range: { offset: 2, length: 2 },
      original_file_range: { offset: 18, length: 2 },
    });
    expect(
      await verifyBinwalkNgCarving({ ...context, rootOffset: null }),
    ).toEqual({
      sha256: createHash("sha256").update("cd").digest("hex"),
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
  const observed: unknown[] = [];
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
        observe: (proof) => observed.push(proof),
        entry: {
          path,
          relativePath: "input.bin_0_gzip.raw",
          kind: "file",
          size: 4,
          linkTarget: null,
        },
      }),
    ).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      cleanup: { resources: [path] },
      cleanupLease: expect.any(Object),
    });
    expect(observed).toEqual([
      expect.objectContaining({
        sha256: createHash("sha256").update("same").digest("hex"),
        original_file_range: { offset: 0, length: 4 },
      }),
    ]);
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
      scope: new ArtifactResourceScope(),
      files: new FirmwareFileAccess(),
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

it.each(["symlink" as const, "special" as const])(
  "records %s artifacts as unpublished metadata and never copies them into caller output",
  async (kind) => {
    const root = await createTestTempDirectory(
      "rea-ng-nonregular-publication-",
    );
    const target = join(root, "target.bin");
    const path = join(root, kind === "symlink" ? "alias.bin" : "pipe.bin");
    const outputDirectory = join(root, "output");
    await writeFile(target, "must not follow or publish");
    if (kind === "symlink") await symlink("target.bin", path);
    else
      execFileSync("/usr/bin/mkfifo", [path], {
        env: { PATH: "/usr/bin:/bin" },
      });
    let owned: SafeOutputTree | undefined;
    try {
      const result = await publishBinwalkNgFiles({
        outputDirectory,
        entries: [
          {
            path,
            relativePath: kind === "symlink" ? "alias.bin" : "pipe.bin",
            size: 0,
            kind,
            linkTarget: kind === "symlink" ? "target.bin" : null,
          },
        ],
        signal: new AbortController().signal,
        operation: "extract_firmware",
        scope: new ArtifactResourceScope(),
        files: new FirmwareFileAccess(),
        ownTree: (tree) => {
          owned = tree;
        },
        releaseTree: () => {
          owned = undefined;
        },
      });
      expect(result.files).toEqual([]);
      expect(result.unpublished_entries).toEqual([
        {
          relative_path: kind === "symlink" ? "alias.bin" : "pipe.bin",
          kind,
          link_target: kind === "symlink" ? "target.bin" : null,
        },
      ]);
      expect(await readdir(outputDirectory)).toEqual([]);
      expect(owned).toBeUndefined();
    } finally {
      await owned?.rollback();
    }
  },
);

it("delivers established private PNG facts to their observation owner before a descriptor close failure", async () => {
  const root = await createTestTempDirectory("rea-ng-png-close-");
  const path = join(root, "entropy.png");
  const bytes = Buffer.alloc(24);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(bytes);
  bytes.writeUInt32BE(13, 8);
  bytes.write("IHDR", 12);
  bytes.writeUInt32BE(2048, 16);
  bytes.writeUInt32BE(1024, 20);
  await writeFile(path, bytes);
  const scope = new ArtifactResourceScope();
  const observed: unknown[] = [];
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(new Error("injected PNG descriptor failure"));
  try {
    await expect(
      inspectBinwalkNgPng(
        path,
        scope,
        new AbortController().signal,
        "inspect_firmware_entropy",
        (png) => observed.push(png),
      ),
    ).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      cleanup: { resources: [path] },
      cleanupLease: expect.any(Object),
    });
    expect(observed).toEqual([
      expect.objectContaining({
        size: 24,
        width: 2048,
        height: 1024,
        path: null,
        publication_state: "unpublished",
        sha256: createHash("sha256").update(bytes).digest("hex"),
      }),
    ]);
    await scope.retryCleanup();
    expect(close).toHaveBeenCalledTimes(2);
  } finally {
    close.mockRestore();
    await scope.close();
  }
});
