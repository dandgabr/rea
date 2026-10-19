import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { FirmwareFileAccess } from "../../../src/firmware/FirmwareFiles.js";
import { FIRMWARE_LIMITS } from "../../../src/firmware/FirmwareRelease.js";
import { parseBinwalkNgAnalyses } from "../../../src/firmware/binwalkNg/BinwalkNgReports.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it("admits an exact 8 MiB native report and rejects one byte beyond before parser allocation", async () => {
  const root = await createTestTempDirectory("rea-binwalk-ng-report-");
  const path = join(root, "native.json");
  const files = new FirmwareFileAccess();
  const report = [
    {
      Analysis: {
        file_path: "/private/input",
        file_map: [
          {
            id: "local",
            offset: 0,
            size: 1,
            name: "test",
            description: "",
            confidence: 0,
            always_display: false,
            extraction_declined: false,
          },
        ],
        extractions: {},
      },
    },
  ];
  const hit = report[0]?.Analysis.file_map[0];
  if (hit === undefined) throw new Error("Test signature missing");
  const padding =
    FIRMWARE_LIMITS.reportBytes - Buffer.byteLength(JSON.stringify(report));
  hit.description = "x".repeat(padding);
  const admitted = JSON.stringify(report);
  expect(Buffer.byteLength(admitted)).toBe(8 * 1024 * 1024);
  await writeFile(path, admitted);
  const parsed = parseBinwalkNgAnalyses(
    await files.report(path, "inspect_firmware_regions"),
    new Map([["/private/input", { size: 1, depth: 0, rootOffset: 0 }]]),
  );
  expect(parsed[0]?.regions[0]?.description.length).toBe(padding);
  expect(parsed[0]?.coverage).toBe("signature_scan");
  await writeFile(path, admitted + " ");
  await expect(
    files.report(path, "inspect_firmware_regions"),
  ).rejects.toMatchObject({
    _tag: "AnalysisOutputError",
    reason: "Report exceeded 8388608 bytes",
  });
  await files.close();
});
