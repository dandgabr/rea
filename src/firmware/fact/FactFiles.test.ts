import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { constants } from "node:fs";
import { writeFile, readFile, rm, stat, open } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import {
  FactFileResources,
  snapshotFactFile,
  publishFactFile,
} from "./FactFiles.js";

it("retains private-root cleanup ownership when snapshot acquisition itself fails", async () => {
  const root = await createTestTempDirectory("rea-fact-failed-snapshot-");
  let attempts = 0;
  const resources = new FactFileResources({
    createRuntime: async () => ({
      path: root,
      close: async () => {
        attempts++;
        if (attempts === 1) throw Error("synthetic removal failure");
        await rm(root, { recursive: true });
      },
    }),
  });
  await expect(
    snapshotFactFile(
      join(root, "missing"),
      new AbortController().signal,
      resources,
    ),
  ).rejects.toThrow("snapshot");
  expect(resources.pendingResources).toContain(root);
  await resources.close();
  expect(attempts).toBe(2);
  expect(resources.pendingResources).toEqual([]);
});
it("rolls back only its uncommitted partial publication and retains failed rollback for close", async () => {
  const root = await createTestTempDirectory("rea-fact-publication-");
  const output = join(root, "firmware.bin");
  let removals = 0;
  const resources = new FactFileResources({
    writeBytes: async (handle, bytes) => {
      await handle.write(bytes.subarray(0, 2));
      throw Error("synthetic write failure");
    },
    removeFile: async (path) => {
      removals++;
      if (removals === 1) throw Error("synthetic unlink failure");
      await rm(path);
    },
  });
  await expect(
    publishFactFile(output, Buffer.from("abc"), resources),
  ).rejects.toMatchObject({
    publication: { path: output, written_bytes: 2, cleanup: "retained" },
  });
  expect(await readFile(output, "utf8")).toBe("ab");
  expect(resources.pendingResources).toContain(output);
  await resources.close();
  await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
  expect(removals).toBe(2);
});
it("preserves successful fresh publication and never removes an existing destination", async () => {
  const root = await createTestTempDirectory("rea-fact-publication-positive-");
  const output = join(root, "firmware.bin");
  const resources = new FactFileResources();
  await publishFactFile(output, Buffer.from("abc"), resources);
  await expect(
    publishFactFile(output, Buffer.from("changed"), resources),
  ).rejects.toThrow("absent");
  await resources.close();
  expect(await readFile(output, "utf8")).toBe("abc");
  const input = join(root, "source.bin");
  await writeFile(input, "snapshot");
  const snapshots = new FactFileResources();
  const source = await snapshotFactFile(
    input,
    new AbortController().signal,
    snapshots,
  );
  expect(source.bytes.toString()).toBe("snapshot");
  await snapshots.release(source.runtime);
});

it.skipIf(process.platform === "win32")(
  "rejects a writer-free FIFO without blocking deadline or cancellation admission",
  async () => {
    const root = await createTestTempDirectory("rea-fact-fifo-");
    const path = join(root, "input.fifo");
    await promisify(execFile)("mkfifo", [path]);
    const resources = new FactFileResources();
    let writerRequired = false;
    const timer = setTimeout(() => {
      writerRequired = true;
      void open(path, constants.O_WRONLY | constants.O_NONBLOCK)
        .then((handle) => handle.close())
        .catch(() => undefined);
    }, 1000);
    try {
      await expect(
        snapshotFactFile(path, AbortSignal.timeout(50), resources),
      ).rejects.toThrow("regular file");
      expect(writerRequired).toBe(false);
      expect(resources.pendingResources).toEqual([]);
      const positive = join(root, "regular.bin");
      await writeFile(positive, "abc");
      const snapshot = await snapshotFactFile(
        positive,
        new AbortController().signal,
        resources,
      );
      expect(snapshot.bytes.toString()).toBe("abc");
      await resources.release(snapshot.runtime);
      const canceled = new AbortController();
      canceled.abort();
      await expect(
        snapshotFactFile(positive, canceled.signal, resources),
      ).rejects.toThrow();
      expect(resources.pendingResources).toEqual([]);
    } finally {
      clearTimeout(timer);
      await resources.close();
      await rm(root, { recursive: true });
    }
  },
);
