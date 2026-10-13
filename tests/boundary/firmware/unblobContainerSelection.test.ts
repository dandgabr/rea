import { expect, it } from "vitest";
import { firmwareFixture } from "../../fixtures/firmware/provider.js";

it("never falls back to native Unblob for an explicitly selected unavailable container profile", async () => {
  const fixture = await firmwareFixture();
  const outcome = await fixture.service.execute("inspect_firmware_provider", {
    provider_id: "unblob",
    runtime: {
      kind: "container",
      command: "/usr/bin/podman",
      image: `sha256:${"a".repeat(64)}`,
      existing_store_profile: `${fixture.root}/absent-store-profile.json`,
    },
  });
  expect(outcome).toMatchObject({ ok: false });
  expect(fixture.launches).toEqual([]);
});
