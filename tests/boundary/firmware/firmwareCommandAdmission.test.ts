import { fileURLToPath } from "node:url";
import { expect } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { processTest } from "../../support/process/processFixture.js";

processTest.skipIf(process.platform !== "linux").for(["caller", "deadline"])(
  "stops actual executable fingerprint reads at first-chunk %s cancellation",
  async (mode, { processes }) => {
    const root = await createTestTempDirectory("rea-firmware-fingerprint-");
    const result = await processes.run(
      process.execPath,
      [
        fileURLToPath(
          new URL(
            "../../fixtures/firmware/commandFingerprintProbe.mjs",
            import.meta.url,
          ),
        ),
        fileURLToPath(
          new URL(
            "../../../dist/application/firmware/FirmwareAnalysisService.js",
            import.meta.url,
          ),
        ),
        fileURLToPath(
          new URL("../../../dist/composition/firmware.js", import.meta.url),
        ),
        fileURLToPath(
          new URL("../../../dist/firmware/FirmwareCommand.js", import.meta.url),
        ),
        root,
        mode,
      ],
      { timeoutMs: 5_000 },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      mode,
      positive_digest:
        "9bc1b2a288b26af7257a36277ae3816a7d4f16e89c1e7e77d0a5c48bad62b360",
      invocation: "preserved",
      bytes_read: 64 * 1024,
      chunks: 1,
      chunks_after_abort: 0,
      closed_handles: 1,
      producer_launches: 0,
      error:
        mode === "deadline" ? "AnalysisTimeoutError" : "AnalysisCancelledError",
    });
  },
);

processTest.skipIf(process.platform !== "linux")(
  "bounds fingerprint cancellation across every chunk position of the actual regular file",
  async ({ processes }) => {
    const root = await createTestTempDirectory(
      "rea-firmware-fingerprint-positions-",
    );
    for (let chunk = 1; chunk <= 16; chunk++) {
      const caseRoot = await createTestTempDirectory(
        `rea-firmware-fingerprint-${chunk}-`,
      );
      const result = await processes.run(
        process.execPath,
        [
          fileURLToPath(
            new URL(
              "../../fixtures/firmware/commandFingerprintProbe.mjs",
              import.meta.url,
            ),
          ),
          fileURLToPath(
            new URL(
              "../../../dist/application/firmware/FirmwareAnalysisService.js",
              import.meta.url,
            ),
          ),
          fileURLToPath(
            new URL("../../../dist/composition/firmware.js", import.meta.url),
          ),
          fileURLToPath(
            new URL(
              "../../../dist/firmware/FirmwareCommand.js",
              import.meta.url,
            ),
          ),
          caseRoot,
          "caller",
          String(chunk),
        ],
        { cwd: root, timeoutMs: 5_000 },
      );
      expect(result.exitCode, `chunk ${chunk}: ${result.stderr}`).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({
        bytes_read: chunk * 64 * 1024,
        chunks: chunk,
        chunks_after_abort: 0,
        closed_handles: 1,
        producer_launches: 0,
        error: "AnalysisCancelledError",
      });
    }
  },
);
