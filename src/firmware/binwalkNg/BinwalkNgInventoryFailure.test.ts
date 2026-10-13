import { expect, it, vi } from "vitest";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
const state = vi.hoisted(() => ({ stdout: "", drift: false }));
vi.mock("./BinwalkNgSandbox.js", () => ({
  prepareBinwalkNgSandbox: async () => ({
    command: { path: "/selected/binwalk", sha256: "a".repeat(64) },
    bubblewrap: { path: "/selected/bwrap", sha256: "a".repeat(64) },
    limiter: { path: "/selected/prlimit", sha256: "a".repeat(64) },
    manifest: { path: "/selected/manifest", sha256: "a".repeat(64) },
    runtime_mounts: [],
    policy_arguments: [],
  }),
}));
vi.mock("./BinwalkNgCommand.js", () => ({
  probeBinwalkNgSandbox: async () => ({ stdout: { text: "binwalk-ng 4.0.0" } }),
  runBinwalkNgCommand: async () => ({
    stdout: { text: state.stdout },
    stderr: { text: "native list stderr" },
    exitCode: 0,
  }),
}));
vi.mock("../FirmwareFiles.js", () => ({
  hashFirmwareFile: async () => (state.drift ? "b".repeat(64) : "a".repeat(64)),
}));
import { inspectBinwalkNgRuntime } from "./BinwalkNgInventory.js";
it("retains independently observed inventory and native raw output on selected runtime drift", async () => {
  state.drift = true;
  state.stdout = [
    "Signature Description".padEnd(35) +
      "Signature Name".padEnd(35) +
      "Extraction Utility",
    "gzip compressed data".padEnd(35) + "gzip".padEnd(35) + "Built-in",
    "Total signatures: 1",
    "Extractable signatures: 1",
  ].join("\n");
  const root = await createTestTempDirectory("rea-ng-inventory-drift-");
  try {
    await inspectBinwalkNgRuntime({
      root,
      runtime: {
        command: "/selected/binwalk",
        bubblewrap: "/selected/bwrap",
        limiter: "/selected/prlimit",
        manifest: "/selected/manifest",
      },
      signal: new AbortController().signal,
      scope: new ArtifactResourceScope(),
      retainCleanup: () => {},
    });
    throw Error("Expected identity drift");
  } catch (cause: unknown) {
    expect(cause).toBeInstanceOf(AnalysisOutputError);
    expect(cause).toMatchObject({
      partialObservation: {
        kind: "firmware",
        result: {
          provider_id: "binwalk-ng",
          formats: [{ name: "gzip" }],
          inventory_coverage: "partial",
          runtime_identity: "changed",
        },
        provenance: {
          raw_result: {
            inventory_execution: { stdout: { text: state.stdout } },
          },
          subject: null,
        },
      },
    });
  }
});
it("retains successful native version/list observations when inventory totals are malformed", async () => {
  state.drift = false;
  state.stdout = "native malformed totals";
  const root = await createTestTempDirectory("rea-ng-inventory-malformed-");
  try {
    await inspectBinwalkNgRuntime({
      root,
      runtime: {
        command: "/selected/binwalk",
        bubblewrap: "/selected/bwrap",
        limiter: "/selected/prlimit",
        manifest: "/selected/manifest",
      },
      signal: new AbortController().signal,
      scope: new ArtifactResourceScope(),
      retainCleanup: () => {},
    });
    throw Error("Expected malformed totals");
  } catch (cause: unknown) {
    expect(cause).toBeInstanceOf(AnalysisOutputError);
    expect(cause).toMatchObject({
      partialObservation: {
        result: {
          provider_id: "binwalk-ng",
          inventory_coverage: "partial",
          runtime_identity: "unknown",
        },
        provenance: {
          raw_result: {
            version_execution: { stdout: { text: "binwalk-ng 4.0.0" } },
            inventory_execution: { stdout: { text: state.stdout } },
          },
          subject: null,
        },
      },
    });
  }
});
