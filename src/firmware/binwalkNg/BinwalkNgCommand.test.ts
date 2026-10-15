import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { assertFirmwareOutputBounds } from "../FirmwareCommand.js";
import { runFirmwareCommand } from "../FirmwareCommand.js";
import { cleanupOwnedProcessGroup } from "../../process/ProcessOwnership.js";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";

it("accepts absent/growing private reports within budget and rejects actual overflow before parsing", async () => {
  const root = await createTestTempDirectory("rea-ng-growth-");
  const path = join(root, "report.json");
  const bounds = [{ path, maxBytes: 8 }];
  await expect(
    assertFirmwareOutputBounds(bounds, "inspect_firmware_entropy"),
  ).resolves.toBeUndefined();
  await writeFile(path, "12345678");
  await expect(
    assertFirmwareOutputBounds(bounds, "inspect_firmware_entropy"),
  ).resolves.toBeUndefined();
  await writeFile(path, "123456789");
  await expect(
    assertFirmwareOutputBounds(bounds, "inspect_firmware_entropy"),
  ).rejects.toMatchObject({
    _tag: "AnalysisOutputError",
    reason: expect.stringContaining("exceeded 8 bytes"),
  });
});

it("probes the exact selected policy and preserves owned-run identity after clearing ambient environment", async () => {
  const root = await createTestTempDirectory("rea-ng-command-");
  const input = join(root, "input.bin");
  const work = join(root, "work");
  const manifest = join(root, "runtime.json");
  await writeFile(input, "input");
  await mkdir(work);
  await writeFile(
    manifest,
    JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts: [] }),
  );
  const sandbox = await prepareBinwalkNgSandbox({
    command: "/usr/bin/true",
    bubblewrap: "/usr/bin/true",
    limiter: "/usr/bin/prlimit",
    systemdRun: "/usr/bin/true",
    manifest,
    inputPath: input,
    workRoot: work,
  });
  const launches: OwnedProviderProcessSpawnOptions[] = [];
  const context = {
    sandbox,
    operation: "inspect_firmware_regions",
    signal: new AbortController().signal,
    maxOutputBytes: 256 * 1024 * 1024,
    maxOutputFiles: 10000,
    retainCleanup: () => {},
    launcher: async (options: OwnedProviderProcessSpawnOptions) => {
      launches.push(options);
      return spawnOwnedProviderProcess({
        ...options,
        command: "/usr/bin/printf",
        expectedCommand: null,
        arguments: ["%s\n", "binwalk-ng 4.0.0"],
      });
    },
  };
  const result = await probeBinwalkNgSandbox(context);
  expect(result.stdout.text.trim()).toBe("binwalk-ng 4.0.0");
  expect(launches[0]?.hostEnvironment).toEqual({});
  expect(launches[0]?.arguments.join(" ")).toContain(
    sandbox.policy_arguments.join(" "),
  );
  expect(launches[0]?.arguments).toContain("REA_PROCESS_RUN_ID");
  expect(launches[0]?.arguments).toContain(launches[0]?.runId);
});

it("fails named unavailable after a denied sandbox probe without an unconfined retry", async () => {
  const root = await createTestTempDirectory("rea-ng-denied-");
  const path = join(root, "input.bin");
  const work = join(root, "work");
  const manifest = join(root, "runtime.json");
  await writeFile(path, "input");
  await mkdir(work);
  await writeFile(
    manifest,
    JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts: [] }),
  );
  const sandbox = await prepareBinwalkNgSandbox({
    command: "/usr/bin/true",
    bubblewrap: "/usr/bin/false",
    limiter: "/usr/bin/prlimit",
    systemdRun: "/usr/bin/true",
    manifest,
    inputPath: path,
    workRoot: work,
  });
  let launches = 0;
  await expect(
    probeBinwalkNgSandbox({
      sandbox,
      operation: "extract_firmware",
      signal: new AbortController().signal,
      maxOutputBytes: 256 * 1024 * 1024,
      maxOutputFiles: 10000,
      retainCleanup: () => {},
      launcher: async (options) => {
        launches++;
        return spawnOwnedProviderProcess(options);
      },
    }),
  ).rejects.toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
    providerId: "binwalk-ng",
    reason: expect.stringContaining("exact bubblewrap policy"),
  });
  expect(launches).toBe(1);
});

it("retains the supervisor and owning operation when cleanup fails, then permits a verified retry", async () => {
  const root = await createTestTempDirectory("rea-ng-command-cleanup-");
  let pending: ProviderProcessSupervisor | undefined;
  let fail = true;
  try {
    await expect(
      runFirmwareCommand({
        engine: "binwalk-ng",
        operation: "carve_firmware",
        command: "/usr/bin/true",
        limiter: "/usr/bin/prlimit",
        args: [],
        cwd: root,
        environment: {},
        signal: new AbortController().signal,
        retainCleanup: (supervisor) => {
          pending = supervisor;
        },
        launcher: async (options) => {
          const spawned = await spawnOwnedProviderProcess(options);
          return {
            ...spawned,
            cleanup: async () => {
              if (fail) throw new Error("injected owned cleanup failure");
              return cleanupOwnedProcessGroup(spawned.ownership);
            },
          };
        },
      }),
    ).rejects.toMatchObject({
      cleanupIncomplete: true,
      operation: "carve_firmware",
      cleanupResources: expect.arrayContaining([root]),
    });
    expect(pending).toBeDefined();
  } finally {
    fail = false;
    expect((await pending?.stop())?.status).not.toBe("incomplete");
  }
});

import { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";
import { probeBinwalkNgSandbox } from "./BinwalkNgCommand.js";
import {
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
} from "../../process/ProviderProcess.js";
