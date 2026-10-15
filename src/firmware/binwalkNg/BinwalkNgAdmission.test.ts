import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { binwalkNgInputSchemas } from "../../domain/firmware/binwalkNgAnalysis.js";
import { BinwalkNgProvider } from "./BinwalkNgProvider.js";

it("refuses extraction before reading the selected input or launching upstream", async () => {
  const root = await createTestTempDirectory("rea-ng-admission-");
  const launch = vi.fn();
  const provider = new BinwalkNgProvider({}, launch);
  const requests = [
    {
      operation: "extract_firmware" as const,
      input: binwalkNgInputSchemas.extract_firmware.parse({
        path: join(root, "missing-input.bin"),
        provider_id: "binwalk-ng",
        output_directory: join(root, "extracted"),
      }),
    },
  ];
  try {
    for (const request of requests) {
      const outcome = await provider.execute(request);
      expect(outcome).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisCapabilityUnavailableError",
          providerId: "binwalk-ng",
          operation: request.operation,
          reason: expect.stringContaining("external helpers"),
        },
      });
    }
    expect(launch).not.toHaveBeenCalled();
  } finally {
    await provider.close();
  }
});
