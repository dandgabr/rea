import { expect, it as test } from "vitest";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  assertFirmwareCleanup,
  firmwareFixture,
} from "../../fixtures/firmware/provider.js";

const it = test.skipIf(process.platform !== "linux");

it.each([
  ["inventory-plugin-doc-missing", "ProviderAdapterError", 3],
  ["inventory-plugin-doc-invalid", "AnalysisOutputError", 3],
  ["inventory-plugin-doc-overflow", "AnalysisOutputError", 3],
  ["inventory-plugin-dependency-invalid", "AnalysisOutputError", 2],
])(
  "does not attest an unmeasured inventory phase after successful execution: %s",
  async (mode, tag, launches) => {
    const fixture = await firmwareFixture(String(mode));
    const plugin = join(fixture.root, "trusted.py");
    await writeFile(plugin, "# original\n");
    const outcome = await fixture.service.execute("inspect_firmware_provider", {
      provider_id: "unblob",
      options: { plugins_path: plugin },
    });
    expect(await readFile(plugin, "utf8")).not.toBe("# original\n");
    expect(outcome).toMatchObject({
      ok: false,
      error: {
        _tag: tag,
        cleanupIncomplete: false,
        partialObservation: {
          result: {
            engine: {
              trusted_plugins: {
                recheck: "unverified",
                attribution: "unknown",
              },
            },
            dependency_readiness:
              launches === 2 ? "unknown" : "reported_installed",
          },
          provenance: {
            raw_result: { dependency_execution: { exit_code: 0 } },
          },
        },
      },
    });
    if (outcome.ok) throw new Error("Expected inventory admission failure");
    if (launches === 2)
      expect(outcome.error.capturedOutput).toMatchObject({
        stdout_utf8_valid: false,
        stdout_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
      });
    else
      expect(outcome.error.partialObservation).toMatchObject({
        result: {
          dependencies: [{ command: "gzip" }, { command: "sasquatch" }],
        },
        provenance: {
          raw_result: { documentation_execution: { exit_code: 0 } },
        },
      });
    expect(fixture.launches).toHaveLength(Number(launches));
    await assertFirmwareCleanup(fixture.launches);
  },
);

it("promotes inventory attribution only after both stable plugin postchecks complete", async () => {
  const fixture = await firmwareFixture("inventory");
  const plugin = join(fixture.root, "trusted.py");
  await writeFile(plugin, "# stable\n");
  const outcome = await fixture.service.execute("inspect_firmware_provider", {
    provider_id: "unblob",
    options: { plugins_path: plugin },
  });
  expect(outcome).toMatchObject({
    ok: true,
    value: {
      normalized_result: {
        engine: {
          trusted_plugins: {
            recheck: "unchanged",
            attribution: "pre_and_post_fingerprint",
          },
        },
      },
    },
  });
  expect(fixture.launches).toHaveLength(3);
  expect(await readFile(plugin, "utf8")).toBe("# stable\n");
  await assertFirmwareCleanup(fixture.launches);
});

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
