import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import { FirmwareFileAccess } from "./FirmwareFiles.js";

it("reads bounded UTF-8 metadata through the shared firmware file owner", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-firmware-text-"));
  const path = join(root, "handlers.md");
  const files = new FirmwareFileAccess();
  try {
    await writeFile(path, "## gzip\nPublic handler documentation\n");
    await expect(
      files.readText(path, "inspect_firmware_provider"),
    ).resolves.toBe("## gzip\nPublic handler documentation\n");
    await writeFile(path, Buffer.from([0xff]));
    await expect(
      files.readText(path, "inspect_firmware_provider"),
    ).rejects.toBeInstanceOf(AnalysisOutputError);
  } finally {
    await files.close();
    await rm(root, { recursive: true, force: true });
  }
});
