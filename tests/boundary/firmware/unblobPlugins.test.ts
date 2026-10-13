import { createHash } from "node:crypto";
import { mkdir, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { expect, it as test } from "vitest";
import {
  assertFirmwareCleanup,
  firmwareFixture,
} from "../../fixtures/firmware/provider.js";

const it = test.skipIf(process.platform !== "linux");
it("prevents native Python import caches from mutating a selected trusted plugin tree", async () => {
  const fixture = await firmwareFixture("plugin-bytecode");
  const plugin = join(fixture.root, "plugins");
  await mkdir(plugin);
  await writeFile(join(plugin, "trusted.py"), "# trusted original\n");
  const outcome = await fixture.service.execute("inspect_firmware_regions", {
    provider_id: "unblob",
    path: fixture.path,
    options: { plugins_path: plugin },
  });
  expect(outcome).toMatchObject({
    ok: true,
    value: {
      normalized_result: {
        engine: { trusted_plugins: { recheck: "unchanged" } },
      },
    },
  });
  expect(await readdir(plugin)).toEqual(["trusted.py"]);
  await assertFirmwareCleanup(fixture.launches);
});
it.each(["file", "tree"])(
  "preserves trusted plugin %s identity and custom report evidence",
  async (kind) => {
    const fixture = await firmwareFixture("custom-report");
    const plugin = join(
      fixture.root,
      kind === "file" ? "trusted.py" : "plugins",
    );
    const bytes = "# trusted plugin\n";
    if (kind === "tree") await mkdir(plugin);
    await writeFile(
      kind === "file" ? plugin : join(plugin, "trusted.py"),
      bytes,
    );
    const outcome = await fixture.service.execute("inspect_firmware_regions", {
      provider_id: "unblob",
      path: fixture.path,
      options: { plugins_path: plugin },
    });
    expect(outcome).toMatchObject({ ok: true });
    if (!outcome.ok) throw outcome.error;
    expect(outcome.value.normalized_result).toMatchObject({
      engine: {
        trusted_plugins: {
          selected_path: plugin,
          kind,
          files: [
            {
              relative_path: kind === "file" ? "trusted.py" : "trusted.py",
              sha256: createHash("sha256").update(bytes).digest("hex"),
            },
          ],
          recheck: "unchanged",
        },
      },
      coverage: "partial",
      diagnostics: [
        {
          input_path: "$input",
          report: {
            __typename__: "TrustedFirmwareReport",
            sensitive_password: "firmware-password-observation",
          },
        },
      ],
    });
    expect(fixture.launches[1]?.args).toContain(`--plugins-path=${plugin}`);
    await assertFirmwareCleanup(fixture.launches);
  },
);

it("retains producer facts and marks plugin attribution unknown after a source drift", async () => {
  const fixture = await firmwareFixture("plugin-drift");
  const plugin = join(fixture.root, "trusted.py");
  await writeFile(plugin, "# original\n");
  const outcome = await fixture.service.execute("inspect_firmware_regions", {
    provider_id: "unblob",
    path: fixture.path,
    options: { plugins_path: plugin },
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      reason: expect.stringContaining("plugin identity changed"),
      partialObservation: {
        kind: "firmware",
        result: {
          chunks: [expect.anything()],
          engine: {
            trusted_plugins: { recheck: "changed", attribution: "unknown" },
          },
        },
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});
