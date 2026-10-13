import { createHash } from "node:crypto";
import {
  mkdir,
  readFile,
  readdir,
  readlink,
  writeFile,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { firmwareRequestSchema } from "../domain/firmware/firmwareAnalysis.js";
import { snapshotFirmware } from "./FirmwareFiles.js";

it("snapshots inspection and extraction ranges with original basenames and readback digests", async () => {
  const root = await createTestTempDirectory("rea-firmware-basename-");
  const path = join(root, "image.rlib");
  await writeFile(path, Buffer.from("0123456789"));
  for (const operation of [
    "inspect_firmware_regions",
    "extract_firmware",
  ] as const) {
    const staging = join(root, operation);
    await mkdir(staging);
    const request = firmwareRequestSchema.parse({
      operation,
      input: {
        path,
        provider_id: "unblob",
        range: { offset: 2, length: 4 },
        ...(operation === "extract_firmware"
          ? { output_directory: join(root, "out") }
          : {}),
      },
    });
    if (request.operation === "inspect_firmware_provider")
      throw new Error("Unexpected inventory request");
    const snapshot = await snapshotFirmware(
      request,
      staging,
      new AbortController().signal,
    );
    expect(basename(snapshot.inputPath)).toBe("image.rlib");
    expect(await readFile(snapshot.inputPath, "utf8")).toBe("2345");
    expect(snapshot.selection).toEqual({
      offset: 2,
      length: 4,
      sha256: createHash("sha256").update("2345").digest("hex"),
    });
    expect(snapshot.subject.sha256).toBe(
      createHash("sha256").update("0123456789").digest("hex"),
    );
  }
  expect(await readFile(path, "utf8")).toBe("0123456789");
});

it.skipIf(process.platform !== "linux")(
  "closes the acquired source handle when snapshot directory creation fails",
  async () => {
    const root = await createTestTempDirectory("rea-firmware-staging-failure-");
    const path = join(root, "firmware.bin");
    await writeFile(path, "abc");
    await mkdir(join(root, "source"));
    const request = firmwareRequestSchema.parse({
      operation: "inspect_firmware_regions",
      input: { path },
    });
    if (request.operation !== "inspect_firmware_regions")
      throw new Error("Unexpected request");
    const sourceDescriptors = async () => {
      const descriptors = await readdir("/proc/self/fd");
      const targets = await Promise.all(
        descriptors.map((descriptor) =>
          readlink(join("/proc/self/fd", descriptor)).catch(() => undefined),
        ),
      );
      return targets.filter((target) => target === path);
    };
    expect(await sourceDescriptors()).toHaveLength(0);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await expect(
        snapshotFirmware(request, root, new AbortController().signal),
      ).rejects.toMatchObject({ code: "EEXIST", syscall: "mkdir" });
      expect(await sourceDescriptors()).toHaveLength(0);
    }
    expect(await readFile(path, "utf8")).toBe("abc");
    expect(await readdir(join(root, "source"))).toEqual([]);
  },
);
