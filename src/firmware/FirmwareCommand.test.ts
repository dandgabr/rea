import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";

import { expect, it as test, vi } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { FirmwareFileAccess } from "./FirmwareFiles.js";
import {
  resolveFirmwareCommand,
  runFirmwareCommand,
} from "./FirmwareCommand.js";

const it = test.skipIf(process.platform !== "linux");

test.each(["success", "command-failure", "cleanup-failure"] as const)(
  "observes cancellation during final stop without erasing %s",
  async (outcome) => {
    const controller = new AbortController();
    const reason = new Error("cancel during final stop");
    const child = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      exitCode: null,
      signalCode: null,
      kill: () => false,
    });
    const retained: unknown[] = [];
    const failure: unknown = await runFirmwareCommand({
      engine: "podman",
      operation: "firmware_container_runtime",
      command: "/unused",
      limiter: "/unused",
      args: [],
      cwd: "/tmp",
      environment: {},
      signal: controller.signal,
      limitProfile: "container-transport",
      retainCleanup: (owner) => retained.push(owner),
      launcher: async () => {
        setImmediate(() => {
          child.stdout.end("producer bytes");
          child.emit("exit", outcome === "command-failure" ? 1 : 0, null);
          child.emit("close", outcome === "command-failure" ? 1 : 0, null);
        });
        return {
          process: child,
          ownership: { runId: "test", leaderPid: 123, processGroupId: 123 },
          cleanup: async () => {
            controller.abort(reason);
            return outcome === "cleanup-failure"
              ? { cleaned: false, reason: "retained direct client" }
              : { cleaned: true, signaled: false };
          },
        };
      },
    }).catch((cause: unknown) => cause);
    expect(controller.signal.aborted).toBe(true);
    if (outcome === "success") {
      expect(failure).toBeInstanceOf(AnalysisCancelledError);
      expect(failure).toMatchObject({ cause: reason });
    } else if (outcome === "command-failure") {
      expect(failure).toMatchObject({
        _tag: "ProviderAdapterError",
        cleanupIncomplete: false,
        diagnostics: { exit_code: 1 },
      });
    } else {
      expect(failure).toMatchObject({
        cleanupIncomplete: true,
        diagnostics: { primary_error: { code: "cancelled" } },
      });
      expect(retained).toHaveLength(1);
    }
    expect(failure).toMatchObject({
      capturedOutput: { stdout: "producer bytes", stdout_bytes: 14 },
    });
  },
);

test("keeps pre-launch firmware cancellation in the tagged error algebra", async () => {
  const controller = new AbortController();
  const reason = new Error("caller stopped");
  controller.abort(reason);
  const launcher = vi.fn();

  const failure: unknown = await runFirmwareCommand({
    engine: "binwalk",
    operation: "inspect_firmware_regions",
    command: "/bin/true",
    limiter: "/usr/bin/prlimit",
    args: [],
    cwd: "/tmp",
    environment: {},
    signal: controller.signal,
    launcher,
    retainCleanup: () => {},
  }).catch((cause: unknown) => cause);

  expect(failure).toBeInstanceOf(AnalysisCancelledError);
  expect(failure).toMatchObject({ cause: reason });
  expect(launcher).not.toHaveBeenCalled();
});

test("names the host and tool requirement of an unconfigured engine", async () => {
  const refusal: unknown = await resolveFirmwareCommand(
    {},
    "binwalk",
    "inspect_firmware_regions",
    new FirmwareFileAccess(),
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
      new FirmwareFileAccess(),
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
      new FirmwareFileAccess(),
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
      new FirmwareFileAccess(),
    ),
  ).rejects.toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
    reason: expect.stringContaining(limiter),
  });
});

const executableFixture = async (root: string, name: string) => {
  const path = join(root, name);
  await writeFile(path, "#!/bin/sh\n");
  await chmod(path, 0o700);
  return path;
};
