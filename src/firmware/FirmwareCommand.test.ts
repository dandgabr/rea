import { chmod, mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it as test } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  resolveFirmwareCommand,
  runFirmwareCommand,
} from "./FirmwareCommand.js";
import { spawnOwnedProviderProcess } from "../process/ProviderProcess.js";

const it = test.skipIf(process.platform !== "linux");

it("preserves a caller-selected executable invocation path separately from resolved identity", async () => {
  const root = await createTestTempDirectory("rea-firmware-invocation-");
  const runtimeRoot = join(root, "runtime");
  const binDirectory = join(runtimeRoot, "usr", "local", "bin");
  await mkdir(binDirectory, { recursive: true });
  const actual = await executableFixture(binDirectory, "actual-tool");
  const python = await executableFixture(binDirectory, "python3");
  const selected = join(binDirectory, "selected-entrypoint");
  await symlink("actual-tool", selected);
  const admitted = await resolveFirmwareCommand(
    {
      REA_UNBLOB_COMMAND: selected,
      REA_UNBLOB_RUNTIME_ROOT: runtimeRoot,
    },
    "unblob",
    "inspect_firmware_regions",
  );
  expect(admitted.command).toBe(selected);
  expect(admitted).toMatchObject({
    resolvedCommand: actual,
    rootDirectory: runtimeRoot,
    sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
  });
  expect(python).toContain(runtimeRoot);
});

test("names the host and tool requirement of an unconfigured engine", async () => {
  const refusal: unknown = await resolveFirmwareCommand(
    {},
    "binwalk",
    "inspect_firmware_regions",
  ).catch((cause: unknown) => cause);

  expect(refusal).toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
  });
  if (!(refusal instanceof AnalysisCapabilityUnavailableError))
    throw new Error("Expected a capability refusal");
  expect(projectAnalysisError(refusal)).toMatchObject({
    code: "capability_unavailable",
    message: refusal.reason,
    remediation: { action: refusal.reason },
  });
  expect(refusal.reason).toContain("REA_BINWALK_COMMAND");
});

it("rejects a directory configured as the firmware engine executable", async () => {
  const root = await createTestTempDirectory("rea-firmware-command-");
  const command = join(root, "binwalk");
  const limiter = await executableFixture(root, "prlimit");
  await mkdir(command);

  await expect(
    resolveFirmwareCommand(
      {
        REA_BINWALK_COMMAND: command,
        REA_FIRMWARE_PRLIMIT_COMMAND: limiter,
      },
      "binwalk",
      "inspect_firmware_regions",
    ),
  ).rejects.toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
    reason: expect.stringContaining(command),
  });
});

it("classifies an unusable firmware engine as an unavailable capability", async () => {
  const root = await createTestTempDirectory("rea-firmware-command-");
  const command = join(root, "binwalk");
  const limiter = await executableFixture(root, "prlimit");
  await writeFile(command, "not executable", { mode: 0o600 });

  await expect(
    resolveFirmwareCommand(
      {
        REA_BINWALK_COMMAND: command,
        REA_FIRMWARE_PRLIMIT_COMMAND: limiter,
      },
      "binwalk",
      "inspect_firmware_regions",
    ),
  ).rejects.toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
    reason: expect.stringContaining(command),
  });
});

it("rejects a directory configured as the resource limiter executable", async () => {
  const root = await createTestTempDirectory("rea-firmware-limiter-");
  const command = await executableFixture(root, "binwalk");
  const limiter = join(root, "prlimit");
  await mkdir(limiter);

  await expect(
    resolveFirmwareCommand(
      {
        REA_BINWALK_COMMAND: command,
        REA_FIRMWARE_PRLIMIT_COMMAND: limiter,
      },
      "binwalk",
      "inspect_firmware_regions",
    ),
  ).rejects.toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
    reason: expect.stringContaining(limiter),
  });
});

it("does not describe consumed binary protocol stdout as an empty text capture", async () => {
  const root = await createTestTempDirectory("rea-firmware-consumer-output-");
  const command = await executableFixture(
    root,
    "protocol-tool",
    "#!/bin/sh\nprintf '\\377\\000frame'\n",
  );
  const controller = new AbortController();
  let consumed = 0;
  const failure = await runFirmwareCommand({
    engine: "unblob",
    operation: "extract_firmware",
    command,
    limiter: "/usr/bin/prlimit",
    args: [],
    cwd: root,
    environment: {},
    signal: controller.signal,
    retainCleanup: () => {
      throw new Error("unexpected incomplete cleanup");
    },
    consumeStdout: async (stream) => {
      for await (const chunk of stream)
        consumed += Buffer.from(chunk).byteLength;
      throw new AnalysisProtocolError("extract_firmware");
    },
  }).catch((cause: unknown) => cause);

  expect(consumed).toBeGreaterThan(0);
  expect(failure).toBeInstanceOf(AnalysisProtocolError);
  const captured = (failure as AnalysisProtocolError).capturedOutput;
  expect(captured).toMatchObject({ stdout: "", stderr: "" });
  expect(captured).not.toHaveProperty("stdout_bytes");
  expect(captured).not.toHaveProperty("stdout_observed_bytes");
  expect(captured).not.toHaveProperty("stdout_utf8_valid");
  expect(captured).not.toHaveProperty("stdout_sha256");
});

it("labels launcher diagnostics as transport capture when stdout is consumed as a protocol", async () => {
  const root = await createTestTempDirectory("rea-firmware-transport-capture-");
  const command = await executableFixture(
    root,
    "protocol-tool",
    "#!/bin/sh\nprintf 'frame'\n",
  );
  const result = await runFirmwareCommand({
    engine: "unblob",
    operation: "extract_firmware",
    command,
    limiter: "/usr/bin/prlimit",
    args: ["--extract"],
    cwd: root,
    environment: {},
    signal: new AbortController().signal,
    retainCleanup: () => {
      throw new Error("unexpected incomplete cleanup");
    },
    consumeStdout: async (stream) => {
      let bytes = 0;
      for await (const chunk of stream) bytes += Buffer.from(chunk).byteLength;
      return { bytes };
    },
  });

  expect(result).toHaveProperty("transport_capture");
  expect(result).not.toHaveProperty("captured_output");
  expect(result.stdoutResult).toEqual({ bytes: 5 });
});

it("rejects incomplete supervisor output even without a diagnostic truncation event", async () => {
  const root = await createTestTempDirectory("rea-firmware-incomplete-output-");
  const command = await executableFixture(
    root,
    "partial-tool",
    "#!/bin/sh\nprintf '{\\\"partial\\\":true}'\n",
  );
  const controller = new AbortController();
  const failure = await runFirmwareCommand({
    engine: "unblob",
    operation: "inspect_firmware_regions",
    command,
    limiter: "/usr/bin/prlimit",
    args: [],
    cwd: root,
    environment: {},
    signal: controller.signal,
    retainCleanup: () => {
      throw new Error("unexpected incomplete cleanup");
    },
    launcher: async (options) => {
      const spawned = await spawnOwnedProviderProcess(options);
      Object.defineProperty(spawned.process, "outputIncomplete", {
        configurable: true,
        get: () => true,
      });
      return spawned;
    },
  }).catch((cause: unknown) => cause);

  expect(failure).toMatchObject({
    _tag: "AnalysisOutputError",
    reason: expect.stringContaining("incomplete"),
  });
});

const executableFixture = async (
  root: string,
  name: string,
  contents = "#!/bin/sh\n",
) => {
  const path = join(root, name);
  await writeFile(path, contents);
  await chmod(path, 0o700);
  return path;
};
