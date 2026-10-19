import { chmod, mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { PassThrough, type Readable } from "node:stream";

import { expect, it as test } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
  AnalysisCancelledError,
} from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { FirmwareFileAccess } from "./FirmwareFiles.js";
import {
  resolveFirmwareCommand,
  runFirmwareCommand,
} from "./FirmwareCommand.js";
import { spawnOwnedProviderProcess } from "../process/ProviderProcess.js";
import type { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import { readUnblobSystemdFrames } from "./UnblobSystemdProtocol.js";

const it = test.skipIf(process.platform !== "linux");

test.each(["timeout", "caller"] as const)(
  "preserves the first %s interruption when the other signal aborts during stop",
  async (first) => {
    const caller = new AbortController();
    const deadline = new AbortController();
    const timeoutReason = new DOMException("initial deadline", "TimeoutError");
    const callerReason = Error("caller interruption");
    const originalTimeout = AbortSignal.timeout;
    AbortSignal.timeout = () => deadline.signal;
    const child = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      exitCode: null,
      signalCode: null,
      kill: () => false,
    });
    try {
      const failure = await runFirmwareCommand({
        engine: "unblob",
        operation: "extract_firmware",
        command: "/unused",
        limiter: "/unused",
        args: [],
        cwd: "/tmp",
        environment: {},
        signal: caller.signal,
        retainCleanup: () => {},
        launcher: async () => {
          setImmediate(() => {
            child.emit("exit", 0, null);
            child.emit("close", 0, null);
            if (first === "timeout") deadline.abort(timeoutReason);
            else caller.abort(callerReason);
          });
          return {
            process: child,
            ownership: {
              runId: "first-interruption",
              leaderPid: 123,
              processGroupId: 123,
            },
            cleanup: async () => {
              if (first === "timeout") caller.abort(callerReason);
              else deadline.abort(timeoutReason);
              return { cleaned: true, signaled: false };
            },
          };
        },
        consumeStdout: async (stream, signal) => {
          for await (const _frame of readUnblobSystemdFrames(stream, {
            maxBytes: 100,
            maxEntries: 8,
            signal,
          })) {
            /* Consume the production protocol. */
          }
        },
      }).catch((cause: unknown) => cause);
      expect(failure).toMatchObject({
        _tag:
          first === "timeout"
            ? "AnalysisTimeoutError"
            : "AnalysisCancelledError",
        cause: first === "timeout" ? timeoutReason : callerReason,
      });
    } finally {
      AbortSignal.timeout = originalTimeout;
      child.stdout.destroy();
      child.stderr.destroy();
    }
  },
);

test.each([false, true])(
  "retains incomplete cleanup while cancelling an empty framed stream (close reported=%s)",
  async (closed) => {
    const controller = new AbortController();
    const reason = Error("caller stopped while awaiting frame header");
    const child = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      exitCode: null,
      signalCode: null,
      kill: () => false,
    });
    let allowCleanup = false;
    let cleanupCalls = 0;
    let retained: ProviderProcessSupervisor | undefined;
    const pending = runFirmwareCommand({
      engine: "unblob",
      operation: "extract_firmware",
      command: "/unused",
      limiter: "/unused",
      args: [],
      cwd: "/tmp",
      environment: {},
      signal: controller.signal,
      launcher: async () => ({
        process: child,
        ownership: { runId: "test", leaderPid: 123, processGroupId: 123 },
        cleanup: async () => {
          cleanupCalls++;
          return allowCleanup
            ? { cleaned: true, signaled: false }
            : { cleaned: false, reason: "service cleanup remains pending" };
        },
      }),
      retainCleanup: (owner) => {
        retained = owner;
      },
      consumeStdout: async (stream, protocolSignal) => {
        for await (const _frame of readUnblobSystemdFrames(stream, {
          maxBytes: 100,
          maxEntries: 8,
          signal: protocolSignal,
        })) {
          /* Consume frames at the production boundary. */
        }
      },
    }).catch((cause: unknown) => cause);
    try {
      await new Promise<void>((resolve) => setImmediate(resolve));
      if (closed) child.emit("close", 0, null);
      controller.abort(reason);
      const failure = await Promise.race([
        pending,
        new Promise((resolve) => setTimeout(() => resolve("pending"), 500)),
      ]);
      expect(failure).toMatchObject({
        cleanupIncomplete: true,
        diagnostics: { primary_error: { code: "cancelled" } },
        cleanupPrimary: { cause: reason },
      });
      expect(retained).toBeDefined();
      expect(cleanupCalls).toBe(1);
      expect(child.stdout.destroyed).toBe(false);
      expect(child.stdout.isPaused()).toBe(true);
      expect(() =>
        child.stdout.emit("error", Error("late retained pipe failure")),
      ).not.toThrow();
      expect(retained?.snapshot().outputIncomplete).toBe(true);
      allowCleanup = true;
      child.stdout.end();
      child.stderr.end();
      child.emit("exit", 0, null);
      child.emit("close", 0, null);
      expect(await retained?.stop()).toMatchObject({
        status: "verified-cleanup",
      });
    } finally {
      allowCleanup = true;
      child.stdout.end();
      child.stderr.end();
      child.emit("exit", 0, null);
      child.emit("close", 0, null);
      await pending;
      await retained?.stop();
      child.stdout.destroy();
      child.stderr.destroy();
    }
  },
);

test.each([
  "success",
  "command-failure",
  "cleanup-failure",
  "protocol-failure",
] as const)(
  "observes final stop cancellation while preserving %s",
  async (outcome) => {
    const controller = new AbortController();
    const reason = Error("cancel during stop");
    const child = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      exitCode: null,
      signalCode: null,
      kill: () => false,
    });
    const failure = await runFirmwareCommand({
      engine: "unblob",
      operation: "extract_firmware",
      command: "/unused",
      limiter: "/unused",
      args: [],
      cwd: "/tmp",
      environment: {},
      signal: controller.signal,
      retainCleanup: () => {},
      ...(outcome === "protocol-failure"
        ? {
            consumeStdout: async (
              stream: Readable,
              protocolSignal: AbortSignal,
            ) => {
              for await (const _frame of readUnblobSystemdFrames(stream, {
                maxBytes: 100,
                maxEntries: 8,
                signal: protocolSignal,
              })) {
                /* Decode the malformed producer. */
              }
            },
          }
        : {}),
      launcher: async () => {
        setImmediate(() => {
          child.stdout.end(
            outcome === "protocol-failure"
              ? Buffer.alloc(40)
              : "producer evidence",
          );
          child.emit("exit", outcome === "command-failure" ? 2 : 0, null);
          child.emit("close", outcome === "command-failure" ? 2 : 0, null);
        });
        return {
          process: child,
          ownership: { runId: "test", leaderPid: 123, processGroupId: 123 },
          cleanup: async () => {
            controller.abort(reason);
            return outcome === "cleanup-failure"
              ? { cleaned: false, reason: "service pending" }
              : { cleaned: true, signaled: false };
          },
        };
      },
    }).catch((cause: unknown) => cause);
    if (outcome === "success")
      expect(failure).toBeInstanceOf(AnalysisCancelledError);
    else if (outcome === "command-failure")
      expect(failure).toMatchObject({
        _tag: "ProviderAdapterError",
        diagnostics: { exit_code: 2 },
      });
    else if (outcome === "protocol-failure")
      expect(failure).toMatchObject({
        _tag: "AnalysisOutputError",
        reason: expect.stringContaining("invalid header"),
      });
    else
      expect(failure).toMatchObject({
        cleanupIncomplete: true,
        diagnostics: { primary_error: { code: "cancelled" } },
      });
    expect(failure).toMatchObject({
      capturedOutput: {
        stdout: outcome === "protocol-failure" ? "" : "producer evidence",
      },
    });
  },
);

test("cleans the owned process when a protocol consumer throws before returning its promise", async () => {
  const primary = new AnalysisProtocolError("synchronous protocol refusal");
  const child = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    exitCode: null,
    signalCode: null,
    kill: () => false,
  });
  let cleanups = 0;
  const failure = await runFirmwareCommand({
    engine: "unblob",
    operation: "extract_firmware",
    command: "/unused",
    limiter: "/unused",
    args: [],
    cwd: "/tmp",
    environment: {},
    signal: new AbortController().signal,
    retainCleanup: () => {},
    consumeStdout: () => {
      throw primary;
    },
    launcher: async () => {
      setImmediate(() => {
        child.stdout.end();
        child.stderr.end();
        child.emit("exit", 0, null);
        child.emit("close", 0, null);
      });
      return {
        process: child,
        ownership: { runId: "test", leaderPid: 123, processGroupId: 123 },
        cleanup: async () => {
          cleanups++;
          return { cleaned: true, signaled: false };
        },
      };
    },
  }).catch((cause: unknown) => cause);
  expect(failure).toBe(primary);
  expect(cleanups).toBe(1);
});

it("preserves a caller-selected executable invocation path separately from resolved identity", async () => {
  const root = await createTestTempDirectory("rea-firmware-invocation-");
  const runtimeRoot = join(root, "runtime");
  const binDirectory = join(runtimeRoot, "usr", "local", "bin");
  await mkdir(binDirectory, { recursive: true });
  const actual = await executableFixture(binDirectory, "actual-tool");
  const python = await executableFixture(binDirectory, "python3");
  const files = new FirmwareFileAccess();
  const selected = join(binDirectory, "selected-entrypoint");
  await symlink("actual-tool", selected);
  const admitted = await resolveFirmwareCommand(
    {
      REA_UNBLOB_COMMAND: selected,
      REA_UNBLOB_RUNTIME_ROOT: runtimeRoot,
    },
    "unblob",
    "inspect_firmware_regions",
    files,
  );
  expect(admitted.command).toBe(selected);
  expect(admitted).toMatchObject({
    resolvedCommand: actual,
    rootDirectory: runtimeRoot,
    sha256: expect.stringMatching(/^[a-f0-9]{64}$/),
  });
  expect(python).toContain(runtimeRoot);
  await files.close();
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
