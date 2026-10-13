import { chmod, mkdir, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it as test } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  resolveFirmwareCommand,
  runFirmwareCommand,
} from "./FirmwareCommand.js";
import { createHash } from "node:crypto";

const it = test.skipIf(process.platform !== "linux");

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
  for (let attempt = 0; attempt < 100; attempt++) {
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
      stderr_sha256: createHash("sha256")
        .update(
          Buffer.concat([Buffer.from([0xff]), Buffer.from("native-partial")]),
        )
        .digest("hex"),
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
}, 5000);

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

const executableFixture = async (root: string, name: string) => {
  const path = join(root, name);
  await writeFile(path, "#!/bin/sh\n");
  await chmod(path, 0o700);
  return path;
};
