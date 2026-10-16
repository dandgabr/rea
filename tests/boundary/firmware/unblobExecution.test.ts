import { expect, it } from "vitest";
import {
  firmwareFixture,
  assertFirmwareCleanup,
} from "../../fixtures/firmware/provider.js";

it.each([
  ["inspect_firmware_provider", { provider_id: "unblob" }],
  ["inspect_firmware_regions", { provider_id: "unblob", path: "$input" }],
  [
    "extract_firmware",
    {
      provider_id: "unblob",
      path: "$input",
      output_directory: "$output",
    },
  ],
] as const)(
  "requires an admitted native runtime root for Unblob operation %s before process launch",
  async (operation, input) => {
    const fixture = await firmwareFixture("normal", undefined, "missing");
    const outcome = await fixture.service.execute(operation, {
      ...input,
      ...("path" in input ? { path: fixture.path } : {}),
      ...("output_directory" in input
        ? { output_directory: fixture.output }
        : {}),
    } as Record<string, unknown>);
    expect(outcome).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        operation,
        reason: expect.stringContaining("absolute REA_UNBLOB_RUNTIME_ROOT"),
      },
    });
    expect(fixture.launches).toEqual([]);
    await assertFirmwareCleanup(fixture.launches);
  },
);
