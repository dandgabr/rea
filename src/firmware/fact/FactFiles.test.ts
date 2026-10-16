import { chmod, readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { FactFileResources, publishFactFile } from "./FactFiles.js";

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
});

it("refuses shared writable output directories before creating a file", async () => {
  const root = await createTestTempDirectory("rea-fact-shared-publication-");
  const output = join(root, "firmware.bin");
  try {
    await chmod(root, 0o777);
    await expect(
      publishFactFile(output, Buffer.from("abc"), new FactFileResources()),
    ).rejects.toThrow("Output parent must not be group- or world-writable");
    await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    await chmod(root, 0o700);
    await rm(root, { recursive: true, force: true });
  }
});

it("refuses publication when POSIX ownership semantics are unavailable", async () => {
  const root = await createTestTempDirectory("rea-fact-no-posix-ownership-");
  const output = join(root, "firmware.bin");
  const originalGetuid = process.getuid;
  try {
    Object.defineProperty(process, "getuid", {
      configurable: true,
      value: undefined,
    });
    await expect(
      publishFactFile(output, Buffer.from("abc"), new FactFileResources()),
    ).rejects.toThrow("POSIX ownership and permission semantics");
    await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    if (originalGetuid === undefined) {
      delete (process as { getuid?: unknown }).getuid;
    } else {
      Object.defineProperty(process, "getuid", {
        configurable: true,
        value: originalGetuid,
      });
    }
    await rm(root, { recursive: true, force: true });
  }
});
