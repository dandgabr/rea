import { expect, it, vi } from "vitest";
import { binwalkNgInputSchemas } from "../../domain/firmware/binwalkNgAnalysis.js";
import { BinwalkNgProvider } from "./BinwalkNgProvider.js";

it.each([false, true])(
  "admits external extraction request for runtime-bound execution (recursive=%s)",
  async (recursive) => {
    const launch = vi.fn();
    const provider = new BinwalkNgProvider({}, launch);
    const request = {
      operation: "extract_firmware" as const,
      input: binwalkNgInputSchemas.extract_firmware.parse({
        path: "/tmp/firmware.bin",
        provider_id: "binwalk-ng",
        output_directory: "/tmp/extracted",
        max_depth: 3,
        options: { recursive },
      }),
    };
    try {
      const outcome = await provider.execute(request);
      expect(outcome).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisCapabilityUnavailableError",
          operation: request.operation,
          reason: expect.stringContaining("REA_BINWALK_NG_COMMAND"),
        },
      });
      expect(launch).not.toHaveBeenCalled();
    } finally {
      await provider.close();
    }
  },
);
