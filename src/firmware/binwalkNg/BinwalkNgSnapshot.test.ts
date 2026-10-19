import { readFile, writeFile, symlink } from "node:fs/promises";
import { basename, join } from "node:path";
import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { FirmwareFileAccess } from "../FirmwareFiles.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

it("preserves selected basename, root identity and entropy/scan byte ranges in immutable snapshots", async () => {
  const root = await createTestTempDirectory("rea-ng-snapshot-");
  const path = join(root, "vendor.FW");
  const bytes = Buffer.from("padding!GZIPdata-tail");
  await writeFile(path, bytes);
  const files = new FirmwareFileAccess();
  const target = await files.snapshot(
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
  await files.close();
});

it("preserves the caller-selected symlink basename for a whole snapshot without overwriting the source", async () => {
  const root = await createTestTempDirectory("rea-ng-snapshot-name-");
  const source = join(root, "firmware.bin");
  const path = join(root, "vendor.FW");
  await writeFile(source, "whole source");
  await symlink(source, path);
  const files = new FirmwareFileAccess();
  try {
    const target = await files.snapshot(
      { operation: "scan_firmware", input: { path } },
      root,
      new AbortController().signal,
    );
    expect(basename(target.inputPath)).toBe("vendor.FW");
    expect(await readFile(target.inputPath, "utf8")).toBe("whole source");
    expect(await readFile(source, "utf8")).toBe("whole source");
    expect(target.subject.path).toBe(path);
    expect(target.selection).toEqual({
      offset: 0,
      length: 12,
      sha256: target.subject.sha256,
    });
  } finally {
    await files.close();
  }
});
