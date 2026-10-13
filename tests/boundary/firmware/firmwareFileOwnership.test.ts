import { fileURLToPath } from "node:url";
import { expect } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { processTest } from "../../support/process/processFixture.js";

processTest
  .skipIf(process.platform !== "linux")
  .for([
    "hash",
    "report",
    "snapshot",
    "multiple",
    "input-admission",
    "report-admission",
  ])(
  "retains an actual failed descriptor and original failure until cleanup retry: %s",
  async (mode, { processes }) => {
    const root = await createTestTempDirectory("rea-firmware-file-owner-");
    const result = await processes.run(
      process.execPath,
      [
        fileURLToPath(
          new URL(
            "../../fixtures/firmware/fileOwnershipProbe.mjs",
            import.meta.url,
          ),
        ),
        fileURLToPath(
          new URL("../../../dist/firmware/FirmwareFiles.js", import.meta.url),
        ),
        root,
        mode,
        mode === "report" ? "32" : "0",
      ],
      { timeoutMs: 5_000 },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      mode,
      retained: true,
      retried_close: true,
      source: "unchanged",
      malformed_cases: mode === "report" ? 32 : 0,
    });
  },
);
