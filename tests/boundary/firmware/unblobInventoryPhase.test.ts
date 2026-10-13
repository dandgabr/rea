import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it as test, vi } from "vitest";
import {
  firmwareFixture,
  assertFirmwareCleanup,
} from "../../fixtures/firmware/provider.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";

const fault = vi.hoisted(() => ({
  mode: "off",
  plugin: "",
  documentSeen: false,
  controller: undefined as AbortController | undefined,
  closeBlocked: false,
  reads: 0,
  acquisitions: 0,
  dependenciesNormalized: false,
  prelaunchReads: 0,
  handles: [] as import("node:fs/promises").FileHandle[],
}));

vi.mock("node:fs/promises", async (original) => {
  const filesystem = await original<typeof import("node:fs/promises")>();
  return {
    ...filesystem,
    open: async (...args: Parameters<typeof filesystem.open>) => {
      if (
        fault.mode === "prelaunch-drift" &&
        args[0] === fault.plugin &&
        fault.dependenciesNormalized &&
        ++fault.prelaunchReads === 2
      )
        await filesystem.writeFile(
          fault.plugin,
          "# changed between inventory phases\n",
        );
      const handle = await filesystem.open(...args);
      if (fault.mode === "off") return handle;
      fault.acquisitions++;
      const documentation = String(args[0]).endsWith("/handlers.md");
      if (documentation) fault.documentSeen = true;
      if (documentation || (args[0] === fault.plugin && fault.documentSeen)) {
        const read = handle.read.bind(handle);
        handle.read = async (...readArgs: Parameters<typeof read>) => {
          fault.reads++;
          if (documentation && fault.mode.includes("read-failure"))
            throw new Error("injected owned documentation read failure");
          const observed = await read(...readArgs);
          if (
            (documentation && fault.mode.startsWith("read-cancel")) ||
            (!documentation &&
              (fault.mode === "postcheck-cancel" ||
                fault.mode === "postcheck-deadline"))
          )
            fault.controller?.abort();
          return observed;
        };
      }
      if (
        fault.closeBlocked &&
        (documentation
          ? fault.mode !== "postcheck-close-failure"
          : args[0] === fault.plugin &&
            fault.documentSeen &&
            fault.mode === "postcheck-close-failure")
      ) {
        fault.handles.push(handle);
        const close = handle.close.bind(handle);
        handle.close = async () => {
          if (fault.closeBlocked)
            throw new Error("injected owned documentation close failure");
          await close();
        };
      }
      return handle;
    },
  };
});

vi.mock("../../../src/firmware/UnblobInventory.js", async (original) => {
  const inventory =
    await original<typeof import("../../../src/firmware/UnblobInventory.js")>();
  return {
    ...inventory,
    normalizeUnblobInventory: (
      ...args: Parameters<typeof inventory.normalizeUnblobInventory>
    ) => {
      const result = inventory.normalizeUnblobInventory(...args);
      if (args[1] === "") fault.dependenciesNormalized = true;
      if (fault.mode === "normalization-failure" && args[1] !== "")
        throw new Error("injected after actual documentation normalization");
      return result;
    },
  };
});

const it = test.skipIf(process.platform !== "linux");

it("retains an observed changed prelaunch generation without running the next inventory producer", async () => {
  const fixture = await firmwareFixture("inventory");
  const plugin = join(fixture.root, "trusted.py");
  await writeFile(plugin, "# original\n");
  Object.assign(fault, {
    mode: "prelaunch-drift",
    plugin,
    dependenciesNormalized: false,
    prelaunchReads: 0,
    documentSeen: false,
    closeBlocked: false,
  });
  try {
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
            engine: {
              trusted_plugins: { recheck: "changed", attribution: "unknown" },
            },
          },
        },
      },
    });
    expect(fixture.launches).toHaveLength(2);
    await assertFirmwareCleanup(fixture.launches);
  } finally {
    fault.mode = "off";
    await fixture.close();
  }
});

it.each([
  "read-failure",
  "read-cancel",
  "read-cancel-and-close",
  "close-failure",
  "read-failure-and-close",
  "postcheck-cancel",
  "postcheck-deadline",
  "postcheck-close-failure",
  "normalization-failure",
])(
  "keeps inventory attribution pending through the owned postprocessing failure: %s",
  async (mode) => {
    const fixture = await firmwareFixture("inventory-plugin-drift");
    const plugin = join(fixture.root, "trusted.py");
    await writeFile(plugin, "# original\n");
    const controller = new AbortController();
    const timeout =
      mode === "postcheck-deadline"
        ? vi.spyOn(AbortSignal, "timeout").mockReturnValue(controller.signal)
        : undefined;
    Object.assign(fault, {
      mode,
      plugin,
      documentSeen: false,
      controller,
      closeBlocked: mode.includes("close"),
      reads: 0,
      acquisitions: 0,
      handles: [],
    });
    try {
      const outcome = await fixture.service.execute(
        "inspect_firmware_provider",
        {
          provider_id: "unblob",
          options: { plugins_path: plugin },
        },
        mode === "postcheck-deadline"
          ? undefined
          : { signal: controller.signal },
      );
      const cleanup = mode.includes("close");
      expect(outcome).toMatchObject({
        ok: false,
        error: {
          _tag: cleanup
            ? "ProviderAdapterError"
            : mode.includes("deadline")
              ? "AnalysisTimeoutError"
              : mode.includes("cancel")
                ? "AnalysisCancelledError"
                : "ProviderAdapterError",
          cleanupIncomplete: cleanup,
          partialObservation: {
            result: {
              engine: {
                trusted_plugins: {
                  recheck: "unverified",
                  attribution: "unknown",
                },
              },
              dependency_readiness: "reported_installed",
              dependencies: [
                { command: "gzip", reported_installed: true },
                { command: "sasquatch", reported_installed: true },
              ],
            },
            provenance: {
              raw_result: {
                dependency_execution: { exit_code: 0 },
                documentation_execution: { exit_code: 0 },
              },
            },
          },
        },
      });
      expect(fixture.launches).toHaveLength(3);
      expect(fault.reads).toBeGreaterThan(0);
      if (mode === "read-cancel") expect(fault.reads).toBe(1);
      if (outcome.ok) throw new Error("Expected postprocessing failure");
      if (mode.includes("read-failure"))
        expect(JSON.stringify(projectAnalysisError(outcome.error))).toContain(
          "injected owned documentation read failure",
        );
      if (mode === "normalization-failure")
        expect(JSON.stringify(projectAnalysisError(outcome.error))).toContain(
          "injected after actual documentation normalization",
        );
      if (mode.startsWith("postcheck-"))
        expect(outcome.error.partialObservation).toMatchObject({
          result: { formats: [{ name: "GZIP" }] },
          provenance: { raw_result: { documentation: expect.any(String) } },
        });
      if (cleanup) {
        const staging = fixture.launches.at(-1)?.cwd;
        expect(staging).toBeDefined();
        expect(outcome.error.cleanupResources).toEqual(
          expect.arrayContaining([
            staging,
            mode === "postcheck-close-failure"
              ? plugin
              : `${staging}/handlers.md`,
          ]),
        );
        expect(fault.handles).toHaveLength(1);
        expect((await fault.handles[0]!.stat()).isFile()).toBe(true);
        const acquisitions = fault.acquisitions,
          reads = fault.reads;
        const blocked = await fixture.service.execute(
          "inspect_firmware_provider",
          { provider_id: "unblob", options: { plugins_path: plugin } },
        );
        expect(blocked).toMatchObject({
          ok: false,
          error: { cleanupIncomplete: true },
        });
        await expect(fixture.close()).rejects.toMatchObject({
          cleanupIncomplete: true,
        });
        await expect(access(staging!)).resolves.toBeUndefined();
        expect(fault.handles[0]!.fd).toBeGreaterThanOrEqual(0);
        expect(fault.acquisitions).toBe(acquisitions);
        expect(fault.reads).toBe(reads);
        expect(fixture.launches).toHaveLength(3);
        fault.closeBlocked = false;
        await fixture.close();
        expect(fault.handles[0]!.fd).toBe(-1);
        expect(fault.reads).toBe(reads);
      }
      await assertFirmwareCleanup(fixture.launches);
    } finally {
      fault.closeBlocked = false;
      fault.mode = "off";
      timeout?.mockRestore();
      await fixture.close();
    }
  },
);
