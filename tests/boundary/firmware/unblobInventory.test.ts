import { expect, it } from "vitest";
import { firmwareFixture } from "../../fixtures/firmware/provider.js";

it("requires an admitted runtime root before Unblob provider inventory", async () => {
  const fixture = await firmwareFixture();
  const outcome = await fixture.service.execute("inspect_firmware_provider", {
    provider_id: "unblob",
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisCapabilityUnavailableError",
      operation: "inspect_firmware_provider",
      reason: expect.stringContaining("absolute REA_UNBLOB_RUNTIME_ROOT"),
    },
  });
  expect(fixture.launches).toEqual([]);
  await fixture.close();
});
