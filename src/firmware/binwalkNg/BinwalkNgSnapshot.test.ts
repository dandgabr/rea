import { readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { snapshotFirmware } from "../FirmwareFiles.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

it("preserves selected basename, root identity and entropy/scan byte ranges in immutable snapshots", async () => {
  const root = await createTestTempDirectory("rea-ng-snapshot-");
  const path = join(root, "vendor.FW");
  const bytes = Buffer.from("padding!GZIPdata-tail");
  await writeFile(path, bytes);
  const target = await snapshotFirmware(
    {
      operation: "inspect_firmware_entropy",
      input: { path, range: { offset: 8, length: 8 } },
    },
    root,
    new AbortController().signal,
  );
  expect(basename(target.inputPath)).toBe("vendor.FW");
  expect(await readFile(target.inputPath)).toEqual(bytes.subarray(8, 16));
  expect(target.selection).toEqual({
    offset: 8,
    length: 8,
    sha256: createHash("sha256").update(bytes.subarray(8, 16)).digest("hex"),
  });
  expect(target.subject.sha256).toBe(
    createHash("sha256").update(bytes).digest("hex"),
  );
  expect(await readFile(path)).toEqual(bytes);
});
