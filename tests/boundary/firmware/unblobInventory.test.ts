import { expect, it as test } from "vitest";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  assertFirmwareCleanup,
  firmwareFixture,
} from "../../fixtures/firmware/provider.js";

const it = test.skipIf(process.platform !== "linux");

it("does not attest unchanged plugin attribution when a launched inventory command fails", async () => {
  const fixture = await firmwareFixture("inventory-plugin-doc-failure");
  const plugin = join(fixture.root, "trusted.py");
  await writeFile(plugin, "# original\n");
  const outcome = await fixture.service.execute("inspect_firmware_provider", {
    provider_id: "unblob",
    options: { plugins_path: plugin },
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "ProviderAdapterError",
      capturedOutput: {
        stderr: expect.stringContaining("Documentation generation failed"),
      },
      partialObservation: {
        result: {
          dependency_readiness: "reported_installed",
          engine: {
            trusted_plugins: { recheck: "unverified", attribution: "unknown" },
          },
        },
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("retains normalized dependency observations when subsequent documentation fails", async () => {
  const fixture = await firmwareFixture("inventory-doc-failure");
  const outcome = await fixture.service.execute("inspect_firmware_provider", {
    provider_id: "unblob",
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      partialObservation: {
        result: {
          dependencies: [
            { command: "gzip", reported_installed: true },
            { command: "sasquatch", reported_installed: true },
          ],
          dependency_readiness: "reported_installed",
          format_inventory_coverage: "partial",
        },
        provenance: { raw_result: { dependency_execution: expect.anything() } },
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("refuses inventory plugin drift after retaining native documentation and dependency facts", async () => {
  const fixture = await firmwareFixture("inventory-plugin-drift");
  const plugin = join(fixture.root, "trusted.py");
  await writeFile(plugin, "# original trusted inventory plugin\n");
  const outcome = await fixture.service.execute("inspect_firmware_provider", {
    provider_id: "unblob",
    options: { plugins_path: plugin },
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      partialObservation: {
        result: {
          dependency_readiness: "reported_installed",
          formats: [expect.anything()],
          engine: {
            trusted_plugins: { recheck: "changed", attribution: "unknown" },
          },
        },
        provenance: {
          raw_result: {
            documentation: expect.any(String),
            documentation_execution: expect.anything(),
          },
        },
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("refuses invalid dependency UTF-8 while retaining the measured tool identity and raw output", async () => {
  const fixture = await firmwareFixture("inventory-invalid-utf8");
  const outcome = await fixture.service.execute("inspect_firmware_provider", {
    provider_id: "unblob",
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      capturedOutput: {
        stdout_utf8_valid: false,
        stdout_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
      },
      partialObservation: {
        kind: "firmware",
        result: {
          engine: { version: "26.6.4" },
          dependency_readiness: "unknown",
        },
        provenance: {
          raw_result: {
            version_execution: expect.anything(),
            dependency_execution: expect.anything(),
          },
        },
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it.each(["inventory", "inventory-missing", "inventory-malformed"])(
  "binds native Unblob inventory to the tool, without a fabricated target: %s",
  async (mode) => {
    const fixture = await firmwareFixture(mode);
    const outcome = await fixture.service.execute("inspect_firmware_provider", {
      provider_id: "unblob",
    });
    expect(outcome).toMatchObject({ ok: true });
    if (!outcome.ok) throw outcome.error;
    expect(outcome.value.subject).toBeNull();
    expect(outcome.value.normalized_result).toMatchObject({
      provider_id: "unblob",
      engine: { version: "26.6.4", worker_count: 1 },
      dependency_readiness:
        mode === "inventory"
          ? "reported_installed"
          : mode === "inventory-missing"
            ? "reported_missing"
            : "unknown",
      formats: [{ name: "GZIP", type: "COMPRESSION", fully_supported: true }],
      format_inventory_coverage: "documented_public_handlers",
      installed_plugin_inventory: "unknown",
    });
    expect(fixture.launches).toHaveLength(3);
    expect(fixture.launches[1]?.args).toContain("--show-external-dependencies");
    expect(fixture.launches[2]?.args).toContain("--build-handlers-doc");
    expect(outcome.value.locations).toEqual([]);
    await assertFirmwareCleanup(fixture.launches);
  },
);
