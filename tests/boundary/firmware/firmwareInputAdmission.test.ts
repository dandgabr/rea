import { fileURLToPath } from "node:url";
import { expect } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { processTest } from "../../support/process/processFixture.js";

processTest
  .skipIf(process.platform !== "linux")
  .for(["snapshot", "hash", "report"] as const)(
  "rejects a writer-free FIFO without blocking while retaining regular-file admission: %s",
  async (mode, { processes }) => {
    const root = await createTestTempDirectory("rea-firmware-input-admission-");
    const probe = fileURLToPath(
      new URL(
        "../../fixtures/firmware/snapshotAdmissionProbe.mjs",
        import.meta.url,
      ),
    );
    const snapshotModule = fileURLToPath(
      new URL("../../../dist/firmware/FirmwareFiles.js", import.meta.url),
    );
    const result = await processes.run(
      process.execPath,
      [probe, snapshotModule, root, mode],
      { timeoutMs: 2_000 },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      regular: "accepted",
      fifo: "rejected",
      mode,
    });
  },
);
