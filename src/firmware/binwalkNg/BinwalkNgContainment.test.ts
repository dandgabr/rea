import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, open, readFile, writeFile } from "node:fs/promises";
import { existsSync, lstatSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";
import { runBinwalkNgCommand } from "./BinwalkNgCommand.js";
import { FirmwareFileAccess } from "../FirmwareFiles.js";

const prepareWithFileOwner = async (
  input: Omit<Parameters<typeof prepareBinwalkNgSandbox>[0], "files">,
) => {
  const files = new FirmwareFileAccess();
  try {
    return await prepareBinwalkNgSandbox({ ...input, files });
  } finally {
    await files.close();
  }
};

const bubblewrap = process.env.REA_TEST_BWRAP_COMMAND ?? "/usr/bin/bwrap";
const limiter = process.env.REA_TEST_PRLIMIT_COMMAND ?? "/usr/bin/prlimit";
const compiler = process.env.REA_TEST_C_COMPILER ?? "/usr/bin/cc";
const runtimeLibraries = [
  ["/lib64/libc.so.6", "/lib64/libc.so.6"],
  ["/lib64/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"],
] as const;
const deviceCanary = ["/dev/kvm", "/dev/mem", "/dev/sda"].find((path) => {
  try {
    const metadata = lstatSync(path);
    return metadata.isCharacterDevice() || metadata.isBlockDevice();
  } catch {
    return false;
  }
});
it.runIf(
  existsSync(bubblewrap) &&
    existsSync(limiter) &&
    existsSync(compiler) &&
    runtimeLibraries.every(([source]) => existsSync(source)) &&
    deviceCanary !== undefined &&
    process.platform === "linux",
)(
  "proves real policy denies host files and device nodes, input writes, inherited descriptors, ambient environment and host network for leader and descendant",
  async () => {
    if (deviceCanary === undefined)
      throw new Error("Missing explicit real-policy prerequisites");
    const canaryMetadata = lstatSync(deviceCanary);
    expect(
      canaryMetadata.isCharacterDevice() || canaryMetadata.isBlockDevice(),
    ).toBe(true);
    const root = await createTestTempDirectory("rea-ng-containment-");
    const command = join(root, "probe");
    await promisify(execFile)(compiler, [
      fileURLToPath(
        new URL(
          "../../../tests/fixtures/firmware/binwalkNgContainment.c",
          import.meta.url,
        ),
      ),
      "-o",
      command,
    ]);
    const canary = join(root, "host-canary"),
      input = join(root, "input.bin"),
      work = join(root, "work");
    await writeFile(canary, "host-only");
    await writeFile(input, "immutable input");
    await mkdir(work);
    const manifest = join(root, "runtime.json");
    await writeFile(
      manifest,
      JSON.stringify({
        profile: "binwalk-ng-4.0.0",
        mounts: runtimeLibraries.map(([source, destination]) => ({
          source: realpathSync(source),
          destination,
          kind: "library",
        })),
      }),
    );
    const descriptor = await open(canary, "r");
    const server = createServer((socket) => socket.end("host network"));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("Expected a loopback port");
    const sandbox = await prepareWithFileOwner({
      command,
      bubblewrap,
      limiter,
      systemdRun:
        process.env.REA_TEST_SYSTEMD_RUN_COMMAND ?? "/usr/bin/systemd-run",
      manifest,
      inputPath: input,
      workRoot: work,
    });
    const previous = process.env.REA_TEST_AMBIENT_CANARY;
    process.env.REA_TEST_AMBIENT_CANARY = "ambient-parent-only";
    try {
      const result = await runBinwalkNgCommand(
        {
          sandbox,
          operation: "extract_firmware",
          signal: AbortSignal.timeout(120000),
          maxOutputBytes: 1024 * 1024,
          maxOutputFiles: 100,
          retainCleanup: () => {
            throw new Error("Real containment process cleanup was incomplete");
          },
        },
        [
          canary,
          sandbox.input_path,
          String(address.port),
          String(descriptor.fd),
          deviceCanary,
        ],
      );
      const control =
        "host_denied=1 device_denied=1 input_readable=1 input_write_denied=1 work_writable=1 inherited_denied=1 ambient_denied=1 network_denied=1";
      expect(result.stdout.text.trim().split("\n")).toEqual([control, control]);
      expect(await readFile(input, "utf8")).toBe("immutable input");
    } finally {
      if (previous === undefined) delete process.env.REA_TEST_AMBIENT_CANARY;
      else process.env.REA_TEST_AMBIENT_CANARY = previous;
      await descriptor.close();
      await new Promise<void>((resolve, reject) =>
        server.close((error) =>
          error === undefined ? resolve() : reject(error),
        ),
      );
    }
  },
  120000,
);
