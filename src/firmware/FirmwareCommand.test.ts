import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { chmod, mkdir, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, vi, it as test } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  resolveFirmwareCommand,
  runFirmwareCommand,
} from "./FirmwareCommand.js";
import { createHash } from "node:crypto";
import { writeFile as writeProtocolFixture } from "node:fs/promises";
import { createHash as hashProtocol } from "node:crypto";
import { SafeOutputTree } from "../artifacts/SafeOutputTree.js";
import { consumeBinwalkNgTransfer } from "./binwalkNg/BinwalkNgTransfer.js";
import { FirmwareFileAccess } from "./FirmwareFiles.js";

import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";

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

const it = test.skipIf(process.platform !== "linux");

it("streams binary protocol stdout without retaining it in diagnostic capture", async () => {
  const root = await createTestTempDirectory("rea-firmware-protocol-");
  const script = join(root, "protocol.py");
  const payload = Buffer.alloc(2 * 1024 * 1024, 0xa5);
  await writeProtocolFixture(
    script,
    `import sys\nsys.stdout.buffer.write(bytes([0xa5]) * (2 * 1024 * 1024))\n`,
  );
  let bytes = 0;
  const hash = hashProtocol("sha256");
  const result = await runFirmwareCommand({
    engine: "fixture",
    operation: "carve_firmware",
    command: "/usr/bin/python3",
    limiter: "/usr/bin/prlimit",
    args: [script],
    cwd: root,
    environment: { PATH: "/usr/bin:/bin" },
    signal: AbortSignal.timeout(5_000),
    protocolStdout: async (stdout) => {
      for await (const chunk of stdout) {
        const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        bytes += data.length;
        hash.update(data);
      }
    },
    retainCleanup: (supervisor) => {
      throw new Error(
        `Unexpected retained process: ${supervisor.snapshot().exitCode}`,
      );
    },
  });
  expect(bytes).toBe(payload.length);
  expect(hash.digest("hex")).toBe(
    hashProtocol("sha256").update(payload).digest("hex"),
  );
  expect(result.stdout).toMatchObject({ text: "", bytes: 0, observedBytes: 0 });
  expect(result.captured_output).toMatchObject({
    stdout: "",
    stdout_capture: "protocol",
    stdout_observed_bytes: payload.byteLength,
  });
  expect(result.captured_output).not.toHaveProperty("stdout_bytes");
  expect(result.captured_output).not.toHaveProperty("stdout_utf8_valid");
  expect(result.captured_output).not.toHaveProperty("stdout_sha256");
});

it("preserves stderr as structured diagnostics when a framed protocol fails", async () => {
  const root = await createTestTempDirectory("rea-firmware-protocol-failure-");
  const stderr = "native protocol diagnostic";
  const script = join(root, "failure.py");
  await writeFile(
    script,
    `import sys,time\nsys.stderr.write(${JSON.stringify(stderr)})\nsys.stderr.flush()\nsys.stdout.buffer.write(b'X'*(2*1024*1024))\nsys.stdout.flush()\ntime.sleep(20)\n`,
  );
  let protocolBytesRead = 0;
  const failure: unknown = await runFirmwareCommand({
    engine: "fixture",
    operation: "inspect_firmware_entropy",
    command: "/usr/bin/python3",
    limiter: "/usr/bin/prlimit",
    args: [script],
    cwd: root,
    environment: { PATH: "/usr/bin:/bin" },
    signal: AbortSignal.timeout(5000),
    protocolStdout: async (stdout) => {
      const first = await stdout[Symbol.asyncIterator]().next();
      if (first.done) throw new Error("protocol producer emitted no bytes");
      protocolBytesRead = Buffer.isBuffer(first.value)
        ? first.value.byteLength
        : Buffer.byteLength(first.value);
      throw new Error("malformed protocol frame");
    },
    retainCleanup: () => {
      throw new Error("Unexpected retained process");
    },
  }).catch((cause: unknown) => cause);

  expect(failure).toMatchObject({
    _tag: "ProviderAdapterError",
    diagnostics: {
      reason: expect.stringContaining("malformed protocol frame"),
      stderr,
    },
    capturedOutput: {
      stderr,
      stdout_capture: "protocol",
      stdout_observed_bytes: expect.any(Number),
    },
  });
  expect(protocolBytesRead).toBeGreaterThan(0);
  expect(
    (failure as { capturedOutput?: { stdout_observed_bytes?: number } })
      .capturedOutput?.stdout_observed_bytes,
  ).toBeGreaterThanOrEqual(protocolBytesRead);
});

it("refuses incomplete process output before accepting a valid-looking result", async () => {
  const root = await createTestTempDirectory("rea-firmware-incomplete-output-");
  const script = join(root, "valid-prefix.py");
  await writeFile(script, "import os; os.write(1, b'{\\\"ready\\\":true}')");
  const failure = await runFirmwareCommand({
    engine: "fixture",
    operation: "firmware_container_runtime",
    command: "/usr/bin/python3",
    limiter: "/usr/bin/prlimit",
    args: [script],
    cwd: root,
    environment: { PATH: "/usr/bin:/bin" },
    signal: AbortSignal.timeout(5_000),
    launcher: async (options) => {
      const spawned = await spawnOwnedProviderProcess(options);
      Object.defineProperty(spawned.process, "outputIncomplete", {
        configurable: true,
        value: true,
      });
      return spawned;
    },
    retainCleanup: () => {
      throw new Error("unexpected incomplete cleanup");
    },
  }).catch((cause: unknown) => cause);

  expect(failure).toMatchObject({
    _tag: "AnalysisOutputError",
    capturedOutput: { stdout: '{"ready":true}', truncated: true },
  });
});

it("refuses a fully parsed Binwalk transfer when the producer reports incomplete output", async () => {
  const root = await createTestTempDirectory(
    "rea-firmware-incomplete-protocol-",
  );
  const output = join(root, "output");
  const script = join(root, "valid-transfer.py");
  const header = Buffer.from('{"type":"end","files":0,"bytes":0}');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(header.byteLength);
  const transfer = Buffer.concat([Buffer.from("REABWNG1"), length, header]);
  await writeProtocolFixture(
    script,
    `import base64,os\nos.write(1,base64.b64decode(${JSON.stringify(transfer.toString("base64"))}))\n`,
  );
  const tree = await SafeOutputTree.create(output);
  let transferParsed = false;
  let outputIncomplete = false;
  try {
    const failure = await runFirmwareCommand({
      engine: "binwalk-ng",
      operation: "extract_firmware",
      command: "/usr/bin/python3",
      limiter: "/usr/bin/prlimit",
      args: [script],
      cwd: root,
      environment: { PATH: "/usr/bin:/bin" },
      signal: AbortSignal.timeout(5_000),
      launcher: async (options) => {
        const spawned = await spawnOwnedProviderProcess(options);
        Object.defineProperty(spawned.process, "outputIncomplete", {
          configurable: true,
          get: () => outputIncomplete,
        });
        return spawned;
      },
      protocolStdout: async (stdout) => {
        await consumeBinwalkNgTransfer(stdout, tree, {
          maxBytes: 1,
          maxFiles: 1,
          maxEntries: 1,
          signal: AbortSignal.timeout(5_000),
        });
        transferParsed = true;
        outputIncomplete = true;
      },
      retainCleanup: () => {
        throw new Error("unexpected incomplete cleanup");
      },
    }).catch((cause: unknown) => cause);

    expect(failure).toMatchObject({
      _tag: "AnalysisOutputError",
      capturedOutput: {
        stdout_capture: "protocol",
        stdout_observed_bytes: transfer.byteLength,
        truncated: true,
      },
    });
    expect(transferParsed).toBe(true);
  } finally {
    await tree.rollback();
  }
});

it("retains bounded actual command bytes and malformed UTF-8 on cancellation after native output", async () => {
  const root = await createTestTempDirectory("rea-firmware-captured-");
  const marker = join(root, "started");
  const script = join(root, "producer.py");
  await writeFile(
    script,
    `import os,time,sys\nprint("native-ack-rootUID",flush=True)\nsys.stderr.buffer.write(b"\\xffnative-partial")\nsys.stderr.buffer.flush()\nopen(${JSON.stringify(marker)},"w").write(str(os.getpid()))\ntime.sleep(20)\n`,
  );
  const controller = new AbortController();
  const running = runFirmwareCommand({
    engine: "fixture",
    operation: "import_corpus_firmware",
    command: "/usr/bin/python3",
    limiter: "/usr/bin/prlimit",
    args: [script],
    cwd: root,
    environment: { PATH: "/usr/bin:/bin" },
    signal: controller.signal,
    retainCleanup: () => {
      throw Error("Unexpected unresolved cleanup");
    },
  }).catch((cause: unknown) => cause);
  let pid: number | undefined;
  for (let attempt = 0; attempt < 500; attempt++) {
    try {
      pid = Number(await readFile(marker, "utf8"));
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
  controller.abort();
  const failure = await running;
  expect(pid).toBeGreaterThan(0);
  expect(failure).toMatchObject({
    _tag: "AnalysisCancelledError",
    capturedOutput: {
      stdout: "native-ack-rootUID\n",
      stdout_bytes: 19,
      stderr_bytes: 15,
      stderr_utf8_valid: false,
      command: "/usr/bin/python3",
      arguments: [script],
    },
  });
  expect(() => process.kill(pid!, 0)).toThrow();
  expect(JSON.parse(JSON.stringify(failure))).toMatchObject({
    capturedOutput: {
      stdout: "native-ack-rootUID\n",
      stderr_utf8_valid: false,
    },
  });
}, 15000);

it("retains the same output-growth failure with useful command acknowledgements after owned cleanup", async () => {
  const root = await createTestTempDirectory("rea-firmware-growth-");
  const output = join(root, "output");
  await mkdir(output);
  const script = join(root, "producer.py");
  await writeFile(
    script,
    `import time\nprint("native-partial-ack",flush=True)\nopen(${JSON.stringify(join(output, "archive.zip"))},"wb").write(b"x"*384)\nopen(${JSON.stringify(join(output, "another.zip"))},"wb").write(b"x"*384)\ntime.sleep(20)\n`,
  );
  const failure: unknown = await runFirmwareCommand({
    engine: "fixture",
    operation: "export_corpus_firmware",
    command: "/usr/bin/python3",
    limiter: "/usr/bin/prlimit",
    args: [script],
    cwd: root,
    environment: { PATH: "/usr/bin:/bin" },
    signal: AbortSignal.timeout(3000),
    outputBudget: { root: output, bytes: 512, entries: 10 },
    retainCleanup: () => {
      throw Error("Unexpected unresolved cleanup");
    },
  }).catch((cause: unknown) => cause);
  expect(failure).toMatchObject({
    _tag: "AnalysisOutputError",
    capturedOutput: {
      stdout: "native-partial-ack\n",
      command: "/usr/bin/python3",
      arguments: [script],
      stdout_utf8_valid: true,
    },
  });
}, 5000);

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
  const files = new FirmwareFileAccess();

  try {
    await expect(
      resolveFirmwareCommand(
        {
          REA_BINWALK_COMMAND: command,
          REA_FIRMWARE_PRLIMIT_COMMAND: limiter,
        },
        "binwalk",
        "inspect_firmware_regions",
        files,
      ),
    ).rejects.toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      reason: expect.stringContaining(command),
    });
  } finally {
    await files.close();
  }
});

it("classifies an unusable firmware engine as an unavailable capability", async () => {
  const root = await createTestTempDirectory("rea-firmware-command-");
  const command = join(root, "binwalk");
  const limiter = await executableFixture(root, "prlimit");
  await writeFile(command, "not executable", { mode: 0o600 });
  const files = new FirmwareFileAccess();

  try {
    await expect(
      resolveFirmwareCommand(
        {
          REA_BINWALK_COMMAND: command,
          REA_FIRMWARE_PRLIMIT_COMMAND: limiter,
        },
        "binwalk",
        "inspect_firmware_regions",
        files,
      ),
    ).rejects.toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      reason: expect.stringContaining(command),
    });
  } finally {
    await files.close();
  }
});

it("rejects a directory configured as the resource limiter executable", async () => {
  const root = await createTestTempDirectory("rea-firmware-limiter-");
  const command = await executableFixture(root, "binwalk");
  const limiter = join(root, "prlimit");
  await mkdir(limiter);
  const files = new FirmwareFileAccess();

  try {
    await expect(
      resolveFirmwareCommand(
        {
          REA_BINWALK_COMMAND: command,
          REA_FIRMWARE_PRLIMIT_COMMAND: limiter,
        },
        "binwalk",
        "inspect_firmware_regions",
        files,
      ),
    ).rejects.toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      reason: expect.stringContaining(limiter),
    });
  } finally {
    await files.close();
  }
});

const executableFixture = async (root: string, name: string) => {
  const path = join(root, name);
  await writeFile(path, "#!/bin/sh\n");
  await chmod(path, 0o700);
  return path;
};

it("retains exact raw provenance at the diagnostic cap, including malformed bytes and cleanup uncertainty", async () => {
  const root = await createTestTempDirectory("rea-firmware-diagnostic-cap-");
  const originalBudget = FIRMWARE_LIMITS.diagnosticBytes;
  const policy = FIRMWARE_LIMITS as { diagnosticBytes: number };
  const raw = Buffer.concat([
    Buffer.from("abc"),
    Buffer.from([255]),
    Buffer.alloc(20, 122),
  ]);
  try {
    policy.diagnosticBytes = 8;
    for (const cleanupUncertain of [false, true]) {
      const marker = join(root, cleanupUncertain ? "uncertain-pid" : "pid");
      const code = `import os,time\nopen(${JSON.stringify(marker)},"w").write(str(os.getpid()))\nos.write(1,b"abc"+bytes([255])+b"z"*20)\ntime.sleep(20)\n`;
      let retained: ProviderProcessSupervisor | undefined;
      const stop = ProviderProcessSupervisor.prototype.stop;
      const stopFault = cleanupUncertain
        ? vi
            .spyOn(ProviderProcessSupervisor.prototype, "stop")
            .mockImplementationOnce(async function (
              this: ProviderProcessSupervisor,
            ) {
              await stop.call(this);
              return {
                status: "incomplete" as const,
                reason: "injected cleanup uncertainty after supervised stop",
              };
            })
        : undefined;
      try {
        const failure: unknown = await runFirmwareCommand({
          engine: "fixture",
          operation: "export_corpus_firmware",
          command: "/usr/bin/python3",
          limiter: "/usr/bin/prlimit",
          args: ["-c", code],
          cwd: root,
          environment: { PATH: "/usr/bin:/bin" },
          signal: AbortSignal.timeout(3000),
          retainCleanup: (owner) => {
            retained = owner;
          },
        }).catch((cause: unknown) => cause);
        const rich = {
          stdout: raw.subarray(0, 8).toString("utf8"),
          stdout_bytes: 8,
          stdout_observed_bytes: 24,
          stdout_utf8_valid: false,
          command: "/usr/bin/python3",
          arguments: ["-c", code],
          resource_limiter: "/usr/bin/prlimit",
          truncated: true,
        };
        if (cleanupUncertain) {
          expect(failure).toMatchObject({
            _tag: "ProviderAdapterError",
            diagnostics: {
              primary_error: {
                code: "unreadable_output",
                details: { captured_output: rich },
              },
              captured_output: rich,
            },
          });
          expect(retained).toBeDefined();
        } else
          expect(failure).toMatchObject({
            _tag: "AnalysisOutputError",
            reason: expect.stringContaining("8-byte capture budget"),
            capturedOutput: rich,
          });
        const pid = Number(await readFile(marker, "utf8"));
        expect(() => process.kill(pid, 0)).toThrow();
      } finally {
        stopFault?.mockRestore();
        if (retained) await retained.stop();
      }
    }
    const control = await runFirmwareCommand({
      engine: "fixture",
      operation: "export_corpus_firmware",
      command: "/usr/bin/python3",
      limiter: "/usr/bin/prlimit",
      args: ["-c", "import os;os.write(1,b'abcdefgh')"],
      cwd: root,
      environment: { PATH: "/usr/bin:/bin" },
      signal: AbortSignal.timeout(3000),
      retainCleanup: () => {
        throw Error("Unexpected positive cleanup uncertainty");
      },
    });
    expect(control.stdout).toMatchObject({
      text: "abcdefgh",
      bytes: 8,
      observedBytes: 8,
    });
  } finally {
    policy.diagnosticBytes = originalBudget;
  }
}, 10000);

test("keeps the first authoritative capture when later text and byte identities differ", () => {
  const original = {
    stdout: "authoritative original",
    stderr: "",
    truncated: true,
  };
  const failure = new AnalysisOutputError("fixture", "original reason", {
    capturedOutput: original,
  });
  expect(
    failure.retainCapturedOutput({
      stdout: "different settled text",
      stderr: "",
      truncated: true,
      stdout_bytes: 99,
      stdout_sha256: "a".repeat(64),
      stdout_utf8_valid: false,
    }),
  ).toBe(failure);
  expect(failure.capturedOutput).toEqual(original);
  expect(failure.reason).toBe("original reason");
});

it("hashes only exact UTF-8 command output and omits digests for malformed bytes", async () => {
  const root = await createTestTempDirectory("rea-firmware-output-digest-");
  const cases = [
    { bytes: Buffer.from("\ufeffsource-é😀"), valid: true },
    { bytes: Buffer.from([0x61, 0xff, 0x62]), valid: false },
  ] as const;

  for (const { bytes, valid } of cases) {
    const script = join(root, valid ? "valid-output.py" : "invalid-output.py");
    const base64 = bytes.toString("base64");
    await writeFile(
      script,
      `import base64,os,sys\nos.write(1,base64.b64decode(${JSON.stringify(base64)}))\nsys.exit(1)\n`,
    );
    const failure = await runFirmwareCommand({
      engine: "fixture",
      operation: "inspect_firmware_entropy",
      command: "/usr/bin/python3",
      limiter: "/usr/bin/prlimit",
      args: [script],
      cwd: root,
      environment: { PATH: "/usr/bin:/bin" },
      signal: AbortSignal.timeout(10_000),
      retainCleanup: () => {
        throw new Error("unexpected incomplete cleanup");
      },
    }).catch((cause: unknown) => cause);

    const captured = (failure as { capturedOutput?: Record<string, unknown> })
      .capturedOutput;
    expect(failure).toMatchObject({ _tag: "ProviderAdapterError" });
    expect(captured).toMatchObject({
      stdout: bytes.toString("utf8"),
      stdout_capture: "diagnostic",
      stdout_bytes: bytes.byteLength,
      stdout_observed_bytes: bytes.byteLength,
      stdout_utf8_valid: valid,
    });
    if (valid)
      expect(captured?.stdout_sha256).toBe(
        createHash("sha256").update(bytes).digest("hex"),
      );
    else expect(captured).not.toHaveProperty("stdout_sha256");
  }
}, 20000);

test("settles protocol consumption when producer stdout closes before end", async () => {
  const child = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    exitCode: null,
    signalCode: null,
    kill: () => false,
  });
  let consumed: import("node:stream").Readable | undefined;
  const pending = runFirmwareCommand({
    engine: "fixture",
    operation: "carve_firmware",
    command: "/unused",
    limiter: "/unused",
    args: [],
    cwd: "/tmp",
    environment: {},
    signal: new AbortController().signal,
    limitProfile: "container-transport",
    retainCleanup: () => {
      throw Error("Unexpected retained process");
    },
    launcher: async (options) => {
      setImmediate(() => {
        child.stdout.write("partial frame");
        child.stdout.destroy();
        child.stderr.end("producer diagnostic");
        child.emit("exit", 0, null);
        child.emit("close", 0, null);
      });
      return {
        process: child,
        ownership: {
          runId: options.runId,
          leaderPid: 123,
          processGroupId: 123,
        },
        cleanup: async () => ({ cleaned: true, signaled: false }),
      };
    },
    protocolStdout: async (stdout) => {
      consumed = stdout;
      for await (const _chunk of stdout) {
        /* Drain until physical completion or failure. */
      }
    },
  }).catch((cause: unknown) => cause);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let failure: unknown;
  try {
    failure = await Promise.race([
      pending,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve("protocol still pending"), 500);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    consumed?.destroy();
    await pending;
  }
  expect(failure).toMatchObject({
    _tag: "ProviderAdapterError",
    capturedOutput: {
      stderr: "producer diagnostic",
      stdout_capture: "protocol",
    },
  });
});

test("preserves an exact file cleanup lease thrown by the protocol consumer", async () => {
  const root = await createTestTempDirectory("rea-protocol-file-owner-");
  const path = join(root, "report.bin");
  await writeFile(path, "report bytes");
  const files = new FirmwareFileAccess();
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(Error("consumer descriptor close refused"));
  const child = Object.assign(new EventEmitter(), {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    exitCode: null,
    signalCode: null,
    kill: () => false,
  });
  try {
    const failure = await runFirmwareCommand({
      engine: "fixture",
      operation: "carve_firmware",
      command: "/unused",
      limiter: "/unused",
      args: [],
      cwd: root,
      environment: {},
      signal: new AbortController().signal,
      limitProfile: "container-transport",
      retainCleanup: () => {
        throw Error("Unexpected retained process");
      },
      launcher: async (options) => {
        setImmediate(() => {
          child.stdout.end();
          child.stderr.end();
          child.emit("exit", 0, null);
          child.emit("close", 0, null);
        });
        return {
          process: child,
          ownership: {
            runId: options.runId,
            leaderPid: 123,
            processGroupId: 123,
          },
          cleanup: async () => ({ cleaned: true, signaled: false }),
        };
      },
      protocolStdout: async () => {
        await files.hash(path);
      },
    }).catch((cause: unknown) => cause);
    expect(failure).toMatchObject({
      cleanupIncomplete: true,
      cleanupResources: [path],
      operation: "carve_firmware",
    });
    await files.retryCleanup();
    expect(failure).toMatchObject({
      cleanupIncomplete: false,
      cleanupResources: [],
    });
  } finally {
    await files.close();
    close.mockRestore();
  }
});
