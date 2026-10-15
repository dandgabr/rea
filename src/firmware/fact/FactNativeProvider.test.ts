import { expect, it, vi } from "vitest";
import { FactNativeProvider } from "./FactNativeProvider.js";
import { runFirmwareCommand } from "../FirmwareCommand.js";
import { firmwareCorpusInputs } from "../../domain/corpus/firmwareCorpus.js";
import { TOOL_EFFECTS } from "../../contracts/toolEffects.js";

const nativeInput = {
  interpreter: "/usr/local/bin/python3",
  checkout: "/data/fact-source",
  profile: "source-54aed90b" as const,
  uids: ["a".repeat(64) + "_1"],
  output_directory: "/host/output",
};
const existingContainerRuntime = {
  kind: "podman-existing" as const,
  podman: "/usr/bin/podman",
  container_id: "a".repeat(64),
  image_id: "b".repeat(64),
  existing_store_profile: "/host/store-profile.json",
  staging_parent: "/host/staging",
};
const providerWithLegacyDependencies = (dependencies: object) =>
  new (FactNativeProvider as unknown as new (
    ...args: object[]
  ) => FactNativeProvider)(dependencies);

it("refuses FACT export for every runtime before identity, process, Podman or hardware action", async () => {
  const command = vi.fn<typeof runFirmwareCommand>();
  const observeIdentity = vi.fn();
  const createContainerSession = vi.fn();
  const provider = providerWithLegacyDependencies({
    command,
    observeIdentity,
    createContainerSession,
  });
  try {
    const inputs = [
      firmwareCorpusInputs.export_corpus_firmware.parse(nativeInput),
      firmwareCorpusInputs.export_corpus_firmware.parse({
        ...nativeInput,
        runtime: { kind: "native" },
      }),
      firmwareCorpusInputs.export_corpus_firmware.parse({
        ...nativeInput,
        runtime: existingContainerRuntime,
      }),
    ];
    for (const input of inputs) {
      const result = await provider.execute("export_corpus_firmware", input);
      expect(result).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisCapabilityUnavailableError" },
      });
    }
    expect(command).not.toHaveBeenCalled();
    expect(observeIdentity).not.toHaveBeenCalled();
    expect(createContainerSession).not.toHaveBeenCalled();
    expect(TOOL_EFFECTS.export_corpus_firmware!.mutatesDevice).toBe(false);

    for (const unavailableAction of [
      "import_corpus_firmware",
      "flash_firmware",
      "update_firmware",
      "boot_firmware",
      "emulate_firmware",
      "jtag",
      "uart",
      "glitch",
      "device_control",
    ]) {
      expect(Object.hasOwn(firmwareCorpusInputs, unavailableAction)).toBe(
        false,
      );
      const result = await provider.execute(
        unavailableAction as never,
        {} as never,
      );
      expect(result, unavailableAction).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisCapabilityUnavailableError" },
      });
    }
    expect(command).not.toHaveBeenCalled();
    expect(observeIdentity).not.toHaveBeenCalled();
    expect(createContainerSession).not.toHaveBeenCalled();
  } finally {
    await provider.close();
  }
});

it("does not retain or close dormant native-export resources", async () => {
  const command = vi.fn();
  const observeIdentity = vi.fn();
  const createContainerSession = vi.fn();
  const createOutput = vi.fn();
  const files = { close: vi.fn(async () => undefined) };
  const parser = { close: vi.fn(async () => undefined) };
  const legacyDependencies = {
    command,
    observeIdentity,
    createContainerSession,
    createOutput,
    files,
    parser,
  };
  const provider = providerWithLegacyDependencies(legacyDependencies);
  try {
    const result = await provider.execute(
      "export_corpus_firmware",
      firmwareCorpusInputs.export_corpus_firmware.parse(nativeInput),
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCapabilityUnavailableError" },
    });
  } finally {
    await provider.close();
  }
  expect(command).not.toHaveBeenCalled();
  expect(observeIdentity).not.toHaveBeenCalled();
  expect(createContainerSession).not.toHaveBeenCalled();
  expect(createOutput).not.toHaveBeenCalled();
  expect(files.close).not.toHaveBeenCalled();
  expect(parser.close).not.toHaveBeenCalled();
});
