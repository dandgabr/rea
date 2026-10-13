import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
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
