import { createHash } from "node:crypto";
import { open, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { FirmwareFileAccess } from "./FirmwareFiles.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";

it.each([false, true])(
  "hash cancellation retains its sole descriptor owner (failed close: %s)",
  async (failedClose) => {
    const root = await createTestTempDirectory("rea-firmware-reader-");
    const path = join(root, "input.bin");
    const bytes = Buffer.alloc(128 * 1024, 0x63);
    await writeFile(path, bytes);
    const sample = await open(path, "r");
    const prototype = Object.getPrototypeOf(sample) as typeof sample;
    await sample.close();
    const controller = new AbortController();
    const files = new FirmwareFileAccess();
    const read = prototype.read;
    let actualReads = 0;
    const readSpy = vi
      .spyOn(prototype, "read")
      .mockImplementation(async function (
        this: typeof sample,
        ...args: Parameters<typeof read>
      ) {
        const result = await Reflect.apply(read, this, args);
        if (result.bytesRead > 0 && ++actualReads === 1)
          controller.abort(new Error("cancel after actual read"));
        return result;
      });
    const stream = prototype.createReadStream;
    const streamSpy = vi
      .spyOn(prototype, "createReadStream")
      .mockImplementation(function (
        this: typeof sample,
        ...args: Parameters<typeof stream>
      ) {
        const result = Reflect.apply(stream, this, args);
        result.once("data", () =>
          controller.abort(new Error("cancel after actual stream read")),
        );
        return result;
      });
    const close = OwnedFileHandle.prototype.close;
    const closedFds: number[] = [];
    let injected = false;
    const closeSpy = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(function (this: OwnedFileHandle) {
        closedFds.push(this.handle.fd);
        if (failedClose && !injected) {
          injected = true;
          return Promise.reject(new Error("owned close fault"));
        }
        return Reflect.apply(close, this, []);
      });
    try {
      const failure = await files
        .hash(path, controller.signal)
        .catch((cause: unknown) => cause);
      expect(controller.signal.aborted).toBe(true);
      expect(streamSpy).not.toHaveBeenCalled();
      expect(actualReads).toBe(1);
      expect(closedFds[0]).toBeGreaterThanOrEqual(0);
      if (failedClose) {
        expect(failure).toMatchObject({
          name: "ArtifactReaderFailure",
          reason: "cancelled",
          cleanup: { resources: [path] },
          cleanupLease: expect.any(Object),
        });
        await files.retryCleanup();
        expect(closedFds).toHaveLength(2);
        expect(closedFds[1]).toBe(closedFds[0]);
      } else {
        expect(failure).toMatchObject({
          name: "ArtifactReaderFailure",
          reason: "cancelled",
          cancellation: { reason: controller.signal.reason },
        });
        expect(closedFds).toHaveLength(1);
      }
    } finally {
      readSpy.mockRestore();
      streamSpy.mockRestore();
      closeSpy.mockRestore();
      await files.close();
    }
    const verification = new FirmwareFileAccess();
    try {
      expect(await verification.hash(path)).toBe(
        createHash("sha256").update(bytes).digest("hex"),
      );
    } finally {
      await verification.close();
    }
  },
);
