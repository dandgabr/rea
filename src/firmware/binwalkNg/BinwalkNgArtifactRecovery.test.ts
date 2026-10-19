import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { withArtifactRegularFile } from "../../artifacts/ArtifactFileOperation.js";
import { open, writeFile, type FileHandle } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import {
  inspectBinwalkNgPng,
  verifyBinwalkNgCarving,
} from "./BinwalkNgArtifacts.js";
const pngHeader = (width: number, height: number) => {
  const bytes = Buffer.alloc(24);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(bytes);
  bytes.writeUInt32BE(13, 8);
  bytes.write("IHDR", 12);
  bytes.writeUInt32BE(width, 16);
  bytes.writeUInt32BE(height, 20);
  return bytes;
};
it("retains invalid PNG validation and its actual descriptor owner when close fails", async () => {
  const root = await createTestTempDirectory("rea-ng-invalid-png-close-");
  const path = join(root, "entropy.png");
  await writeFile(path, pngHeader(1024, 1024));
  const scope = new ArtifactResourceScope();
  const observed: unknown[] = [];
  await expect(
    inspectBinwalkNgPng(
      path,
      scope,
      new AbortController().signal,
      "inspect_firmware_entropy",
      (p) => observed.push(p),
    ),
  ).rejects.toMatchObject({
    _tag: "AnalysisOutputError",
    reason: expect.stringContaining("2048x1024 source profile"),
  });
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(new Error("injected descriptor close failure"));
  try {
    await expect(
      inspectBinwalkNgPng(
        path,
        scope,
        new AbortController().signal,
        "inspect_firmware_entropy",
        (p) => observed.push(p),
      ),
    ).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      cleanup: { resources: [path] },
      fileCleanupFailure: expect.objectContaining({ path }),
    });
    expect(observed).toEqual([]);
    expect(close).toHaveBeenCalledTimes(1);
    await scope.retryCleanup();
    expect(close).toHaveBeenCalledTimes(2);
  } finally {
    close.mockRestore();
    await scope.close();
  }
});
it("distinguishes cancellation during PNG reading from its failed descriptor cleanup", async () => {
  const root = await createTestTempDirectory("rea-ng-cancel-png-close-");
  const path = join(root, "entropy.png");
  await writeFile(path, pngHeader(2048, 1024));
  const probe = await open(path);
  const prototype = Object.getPrototypeOf(probe) as FileHandle;
  await probe.close();
  const original = prototype.createReadStream;
  const controller = new AbortController();
  const read = vi
    .spyOn(prototype, "createReadStream")
    .mockImplementation(function (
      this: FileHandle,
      ...args: Parameters<FileHandle["createReadStream"]>
    ) {
      const stream = original.apply(this, args);
      stream.once("data", () => controller.abort());
      return stream;
    });
  const scope = new ArtifactResourceScope();
  const observed: unknown[] = [];
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(
      new Error("injected canceled descriptor close failure"),
    );
  try {
    await expect(
      inspectBinwalkNgPng(
        path,
        scope,
        controller.signal,
        "inspect_firmware_entropy",
        (p) => observed.push(p),
      ),
    ).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      cleanup: { resources: [path] },
      fileCleanupFailure: expect.objectContaining({ path }),
    });
    expect(controller.signal.aborted).toBe(true);
    expect(observed).toEqual([]);
    await scope.retryCleanup();
    expect(close).toHaveBeenCalledTimes(2);
  } finally {
    read.mockRestore();
    close.mockRestore();
    await scope.close();
  }
});
it("retains second-file acquisition failure while retrying the first acquired carving descriptor", async () => {
  const root = await createTestTempDirectory("rea-ng-acquire-carving-close-");
  const inputPath = join(root, "input.bin"),
    path = join(root, "input.bin_0_gzip.raw");
  await writeFile(inputPath, "same");
  const scope = new ArtifactResourceScope();
  const observed: unknown[] = [];
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(
      new Error("injected first descriptor close failure"),
    );
  try {
    await expect(
      verifyBinwalkNgCarving({
        inputPath,
        inputSize: 4,
        rootOffset: 0,
        scope,
        signal: new AbortController().signal,
        operation: "carve_firmware",
        observe: (p) => observed.push(p),
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
      cleanup: { resources: [inputPath] },
      fileCleanupFailure: expect.any(Object),
    });
    expect(observed).toEqual([]);
    expect(close).toHaveBeenCalledTimes(1);
    await scope.retryCleanup();
    expect(close).toHaveBeenCalledTimes(2);
  } finally {
    close.mockRestore();
    await scope.close();
  }
});
it("bounded rejected-header recovery fuzz: seed 0x4e473209, 16 inputs retain diagnosis and close exactly the retained owner", async () => {
  let seed = 0x4e473209;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  const root = await createTestTempDirectory("rea-ng-header-recovery-fuzz-");
  for (let index = 0; index < 16; index++) {
    const path = join(root, `${index}.png`),
      width = 1 + (next() % 1023),
      height = 1 + (next() % 1023);
    await writeFile(path, pngHeader(width, height));
    const scope = new ArtifactResourceScope();
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockRejectedValueOnce(new Error("injected close failure"));
    try {
      await expect(
        inspectBinwalkNgPng(
          path,
          scope,
          new AbortController().signal,
          "inspect_firmware_entropy",
        ),
      ).rejects.toMatchObject({
        name: "ArtifactReaderFailure",
        cleanup: { resources: [path] },
        fileCleanupFailure: expect.objectContaining({ path }),
      });
      await scope.close();
      expect(close).toHaveBeenCalledTimes(2);
    } finally {
      close.mockRestore();
      await scope.close();
    }
  }
});

it("shares captured primary facts and every failed descriptor owner across a multi-file cleanup failure", async () => {
  const root = await createTestTempDirectory("rea-ng-multi-primary-");
  const paths = [join(root, "left"), join(root, "right")];
  for (const path of paths) await writeFile(path, "observed bytes");
  const scope = new ArtifactResourceScope(),
    controller = new AbortController();
  let primary: AnalysisOutputError | undefined;
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(new Error("first close"))
    .mockRejectedValueOnce(new Error("second close"));
  try {
    const work = withArtifactRegularFile(
      paths[0]!,
      scope,
      controller.signal,
      (left) =>
        withArtifactRegularFile(
          paths[1]!,
          scope,
          controller.signal,
          async () => {
            const bytes = Buffer.alloc(14);
            await left.read(bytes, 0, 14, 0);
            primary = new AnalysisOutputError(
              "carve_firmware",
              "validation after acquired observation",
              {
                capturedOutput: {
                  stdout: "native partial stdout",
                  stderr: "native diagnostic",
                  truncated: false,
                },
                partialObservation: {
                  kind: "firmware",
                  result: { read_bytes: bytes.toString("utf8") },
                },
              },
            );
            controller.abort();
            throw primary;
          },
        ),
    );
    const failure: unknown = await work.catch((cause: unknown) => cause);
    expect(failure).toMatchObject({
      partialObservation: {
        kind: "firmware",
        result: { read_bytes: "observed bytes" },
      },
      cleanupLease: expect.any(Object),
    });
    expect(primary?.capturedOutput).toEqual({
      stdout: "native partial stdout",
      stderr: "native diagnostic",
      truncated: false,
    });
    expect(close).toHaveBeenCalledTimes(2);
    await scope.retryCleanup();
    expect(close).toHaveBeenCalledTimes(4);
  } finally {
    close.mockRestore();
    await scope.close();
  }
});
