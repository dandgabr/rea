import { randomUUID } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { access, mkdir, readlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import {
  buildUnblobSystemdInvocation,
  spawnUnblobSystemdProcess,
} from "./UnblobSystemd.js";

const execFileAsync = promisify(execFile);

it("builds a fixed isolated scan unit with read-only input and private report files", async () => {
  const workspace = await createTestTempDirectory("rea-unblob-systemd-");
  const root = join(workspace, "runtime-root");
  const privateWorkspace = join(workspace, "operation");
  await mkdir(join(root, "usr", "local", "bin"), { recursive: true });
  await mkdir(join(root, "usr", "bin"), { recursive: true });
  await mkdir(privateWorkspace);
  const executable = join(root, "usr", "bin", "unblob");
  const python = join(root, "usr", "local", "bin", "python3");
  const input = join(privateWorkspace, "input.bin");
  const report = join(privateWorkspace, "report.json");
  const log = join(privateWorkspace, "unblob.log");
  await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await writeFile(python, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await writeFile(input, "immutable input");

  const invocation = await buildUnblobSystemdInvocation(
    { rootDirectory: root, executable, inputPath: input },
    ["--skip-extraction", "--force", "--report", report, "--log", log, input],
    privateWorkspace,
  );

  expect(invocation.arguments).toContain("--user");
  expect(invocation.arguments).toContain("--property=PrivateNetwork=yes");
  expect(invocation.arguments).toContain("--property=PrivateDevices=yes");
  expect(invocation.arguments).toContain("--property=PrivatePIDs=yes");
  expect(invocation.arguments).toContain("--property=TimeoutStopSec=2s");
  expect(invocation.arguments).toContain("--property=SendSIGKILL=yes");
  expect(invocation.arguments).toContain(
    "--property=UnsetEnvironment=LD_PRELOAD",
  );
  expect(invocation.arguments).toContain(
    "--property=UnsetEnvironment=LD_AUDIT",
  );
  expect(invocation.arguments).toContain(
    "--property=UnsetEnvironment=LD_LIBRARY_PATH",
  );
  expect(invocation.arguments).toContain(
    "--property=UnsetEnvironment=LD_DEBUG_OUTPUT",
  );
  expect(invocation.arguments).toContain(
    "--property=UnsetEnvironment=LD_TRACE_PRELINKING",
  );
  expect(invocation.arguments).toContain(
    "--property=UnsetEnvironment=GCONV_PATH",
  );
  expect(invocation.arguments).toContain(
    "--property=UnsetEnvironment=PYTHONPATH",
  );
  expect(invocation.arguments).toContain("-I");
  expect(invocation.arguments).toContain("-S");
  const separator = invocation.arguments.indexOf("--");
  expect(invocation.arguments.slice(separator + 1, separator + 4)).toEqual([
    "/usr/local/bin/python3",
    "-I",
    "-S",
  ]);
  const gateConfig = JSON.parse(
    invocation.arguments.find((value) =>
      value.startsWith('{"host_pid_namespace"'),
    )!,
  ) as { host_pid_namespace: string };
  expect(gateConfig.host_pid_namespace).toMatch(/^pid:\[\d+\]$/u);
  expect(invocation.arguments).toContain("--property=MemoryMax=1073741824");
  expect(invocation.arguments).toContain(
    "--property=TemporaryFileSystem=/tmp:mode=1777,size=67108864,nr_inodes=512",
  );
  expect(invocation.arguments).toContain(`--property=RootDirectory=${root}`);
  expect(invocation.arguments).toContain(
    `--property=BindReadOnlyPaths=${input}:/tmp/rea-input`,
  );
  expect(invocation.arguments).toContain(
    `--property=BindPaths=${report}:/tmp/rea-report.json`,
  );
  expect(invocation.arguments).not.toContain(
    `--property=BindPaths=${log}:/tmp/rea-unblob.log`,
  );
  expect(invocation.guestArguments).toEqual([
    "--skip-extraction",
    "--force",
    "--report",
    "/tmp/rea-report.json",
    "--log",
    "/tmp/rea-unblob.log",
    "/tmp/rea-input",
  ]);
  expect(invocation.unit).toMatch(/^rea-unblob-[0-9a-f-]+$/u);
});

it("refuses an input outside its private workspace and executable outside the rootfs", async () => {
  const workspace = await createTestTempDirectory("rea-unblob-systemd-");
  const root = join(workspace, "runtime-root");
  await mkdir(root);
  const executable = join(workspace, "outside");
  const python = join(root, "python3");
  const input = join(workspace, "input.bin");
  await writeFile(executable, "x", { mode: 0o700 });
  await writeFile(python, "x", { mode: 0o700 });
  await writeFile(input, "x");
  await expect(
    buildUnblobSystemdInvocation(
      {
        rootDirectory: root,
        executable,
        pythonExecutable: python,
        inputPath: input,
      },
      [input],
      join(workspace, "other"),
    ),
  ).rejects.toThrow(/inside its admitted runtime root/u);

  const inside = join(root, "unblob");
  await writeFile(inside, "x", { mode: 0o700 });
  await expect(
    buildUnblobSystemdInvocation(
      {
        rootDirectory: root,
        executable: inside,
        pythonExecutable: python,
        inputPath: input,
      },
      [input],
      join(workspace, "other"),
    ),
  ).rejects.toThrow(/private firmware workspace/u);
});

it("bounds inherited systemd manager environment properties before unit launch", async () => {
  const workspace = await createTestTempDirectory("rea-unblob-systemd-env-");
  const root = join(workspace, "runtime-root");
  await mkdir(join(root, "bin"), { recursive: true });
  const executable = join(root, "bin", "unblob");
  const python = join(root, "bin", "python3");
  await writeFile(executable, "x", { mode: 0o700 });
  await writeFile(python, "x", { mode: 0o700 });

  await expect(
    buildUnblobSystemdInvocation(
      { rootDirectory: root, executable, pythonExecutable: python },
      ["--version"],
      workspace,
      `rea-firmware-${randomUUID()}`,
      Array.from({ length: 257 }, (_, index) => `REA_TEST_${index}`),
    ),
  ).rejects.toThrow(/manager environment exceeds/u);
});

it("admits extraction only to the fixed private directory and encodes caller budgets", async () => {
  const workspace = await createTestTempDirectory(
    "rea-unblob-systemd-extract-",
  );
  const root = join(workspace, "runtime-root");
  const operation = join(workspace, "operation");
  await mkdir(join(root, "bin"), { recursive: true });
  await mkdir(operation);
  const executable = join(root, "bin", "unblob");
  const python = join(root, "bin", "python3");
  const input = join(operation, "input.bin");
  const report = join(operation, "report.json");
  await writeFile(executable, "x", { mode: 0o700 });
  await writeFile(python, "x", { mode: 0o700 });
  await writeFile(input, "x");
  const invocation = await buildUnblobSystemdInvocation(
    {
      rootDirectory: root,
      executable,
      pythonExecutable: python,
      inputPath: input,
      extractionBudget: { bytes: 4096, entries: 12 },
    },
    ["--extract-dir", join(operation, "extracted"), "--report", report, input],
    operation,
  );
  expect(invocation.guestArguments).toEqual([
    "--extract-dir",
    "/tmp/rea-extracted",
    "--report",
    "/tmp/rea-report.json",
    "/tmp/rea-input",
  ]);
  const configArgument = invocation.arguments.find((value) =>
    value.startsWith('{"host_pid_namespace"'),
  );
  expect(JSON.parse(configArgument!)).toMatchObject({
    max_bytes: 4096,
    max_entries: 12,
    tmpfs_bytes: 8392704,
  });
  await expect(
    buildUnblobSystemdInvocation(
      { rootDirectory: root, executable, pythonExecutable: python },
      ["--extract-dir", "/tmp/attacker-output"],
      operation,
    ),
  ).rejects.toThrow(/escapes its private workspace/u);
});

it.skipIf(process.env.REA_RUN_USER_SYSTEMD !== "1")(
  "proves live PID isolation, sentinel invisibility, and pre-bootstrap loader scrubbing",
  async () => {
    const workspace = await createTestTempDirectory(
      "rea-unblob-systemd-probe-",
    );
    const canaryDirectory = join(workspace, "python-path");
    await mkdir(canaryDirectory);
    const loaderCanary = join(workspace, "loader-ran");
    const siteCanary = join(workspace, "site-ran");
    const source = join(workspace, "loader.c");
    const preload = join(workspace, "hostile.so");
    await writeFile(
      source,
      `#include <fcntl.h>\n#include <unistd.h>\n__attribute__((constructor)) static void probe(void) { int fd = open("${loaderCanary}", O_CREAT | O_WRONLY, 0600); if (fd >= 0) { write(fd, "x", 1); close(fd); } }\n`,
    );
    await writeFile(
      join(canaryDirectory, "sitecustomize.py"),
      `from pathlib import Path\nPath(${JSON.stringify(siteCanary)}).write_text("loaded")\n`,
    );
    await execFileAsync("/usr/bin/cc", [
      "-shared",
      "-fPIC",
      "-o",
      preload,
      source,
    ]);

    const sentinel = spawn("/usr/bin/sleep", ["60"], { stdio: "ignore" });
    if (sentinel.pid === undefined)
      throw new Error("Could not start owned host sentinel");
    try {
      const hostNamespace = await readlink("/proc/self/ns/pid");
      const unit = `rea-unblob-probe-${randomUUID()}.service`;
      const script = [
        "import errno, os, sys",
        "host, pid = sys.argv[1], int(sys.argv[2])",
        "assert os.readlink('/proc/self/ns/pid') != host",
        "assert not os.path.exists('/proc/' + str(pid))",
        "try:",
        "    os.kill(pid, 0)",
        "except ProcessLookupError:",
        "    pass",
        "else:",
        "    raise AssertionError('host sentinel is signal-addressable')",
        "assert 'PYTHONPATH' not in os.environ",
        "assert 'LD_PRELOAD' not in os.environ",
        "assert sys.flags.isolated and sys.flags.no_site",
        "print('pid namespace isolated; sentinel invisible; startup/loader variables unset')",
      ].join("\n");
      const { stdout } = await execFileAsync(
        "/usr/bin/systemd-run",
        [
          "--user",
          "--quiet",
          "--wait",
          "--collect",
          "--pipe",
          `--unit=${unit}`,
          "--property=PrivatePIDs=yes",
          "--property=PrivateNetwork=yes",
          "--property=PrivateDevices=yes",
          `--property=Environment=PYTHONPATH=${canaryDirectory}`,
          `--property=Environment=LD_PRELOAD=${preload}`,
          "--property=UnsetEnvironment=PYTHONPATH",
          "--property=UnsetEnvironment=LD_PRELOAD",
          "--property=UnsetEnvironment=LD_AUDIT",
          "--property=NoNewPrivileges=yes",
          "--",
          "/usr/bin/python3",
          "-I",
          "-S",
          "-c",
          script,
          hostNamespace,
          String(sentinel.pid),
        ],
        { encoding: "utf8", timeout: 10_000 },
      );
      expect(stdout).toContain("pid namespace isolated; sentinel invisible");
      await expect(access(loaderCanary)).rejects.toMatchObject({
        code: "ENOENT",
      });
      await expect(access(siteCanary)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      sentinel.kill("SIGTERM");
    }
  },
  15_000,
);

it.skipIf(process.env.REA_UNBLOB_ACCEPTANCE_ROOT === undefined)(
  "runs pinned Unblob under the exact transient service and verifies cleanup/profile",
  async () => {
    const root = process.env.REA_UNBLOB_ACCEPTANCE_ROOT!;
    const workspace = await createTestTempDirectory("rea-unblob-systemd-live-");
    const spawned = await spawnUnblobSystemdProcess(
      {
        rootDirectory: root,
        executable: join(root, "usr", "local", "bin", "unblob"),
      },
      ["--version"],
      {
        command: "/usr/bin/systemd-run",
        arguments: [],
        expectedCommand: "/usr/bin/systemd-run",
        runId: `rea-firmware-${randomUUID()}`,
        cwd: workspace,
      },
    );
    const supervisor = new ProviderProcessSupervisor(
      { ...spawned, ownsProcessLifetime: true },
      {
        maxDiagnosticBytes: 4096,
      },
    );
    await supervisor.waitForOutputClose(5000);
    expect(supervisor.snapshot()).toMatchObject({
      exitCode: 0,
      stdout: { text: "26.6.4\n" },
      stderr: { text: "" },
    });
    const stopped = await supervisor.stop();
    expect(stopped).toEqual({ status: "verified-cleanup" });
  },
);

it.skipIf(process.env.REA_UNBLOB_ACCEPTANCE_ROOT === undefined)(
  "fails closed when systemd ignores the required private PID namespace",
  async () => {
    const root = process.env.REA_UNBLOB_ACCEPTANCE_ROOT!;
    const workspace = await createTestTempDirectory(
      "rea-unblob-systemd-no-pidns-",
    );
    const runId = `rea-firmware-${randomUUID()}`;
    const invocation = await buildUnblobSystemdInvocation(
      {
        rootDirectory: root,
        executable: join(root, "usr", "local", "bin", "unblob"),
      },
      ["--version"],
      workspace,
      runId,
    );
    const argumentsWithoutPidNamespace = invocation.arguments.map((argument) =>
      argument === "--property=PrivatePIDs=yes"
        ? "--property=PrivatePIDs=no"
        : argument,
    );
    const gateBinding = invocation.arguments.find((argument) =>
      argument.startsWith("--property=BindReadOnlyPaths="),
    );
    const gatePath = gateBinding
      ?.slice("--property=BindReadOnlyPaths=".length)
      .split(":")[0];
    try {
      let failure: { code?: number; stderr?: string } | undefined;
      try {
        await execFileAsync(
          "/usr/bin/systemd-run",
          argumentsWithoutPidNamespace,
          {
            encoding: "utf8",
            timeout: 10_000,
          },
        );
      } catch (cause: unknown) {
        failure = cause as { code?: number; stderr?: string };
      }
      expect(failure?.code).toBe(125);
      expect(failure?.stderr).toContain(
        "PrivatePIDs is unavailable or was not applied",
      );
    } finally {
      if (gatePath !== undefined) await unlink(gatePath).catch(() => undefined);
    }
  },
  15_000,
);

it.skipIf(process.env.REA_UNBLOB_ACCEPTANCE_ROOT === undefined)(
  "drops arbitrary late manager environment values before executing the provider",
  async () => {
    const root = process.env.REA_UNBLOB_ACCEPTANCE_ROOT!;
    const workspace = await createTestTempDirectory("rea-unblob-systemd-env-");
    const runId = `rea-firmware-${randomUUID()}`;
    const invocation = await buildUnblobSystemdInvocation(
      { rootDirectory: root, executable: join(root, "usr", "bin", "env") },
      [],
      workspace,
      runId,
    );
    const separator = invocation.arguments.indexOf("--");
    const argumentsWithLateVariable = [
      ...invocation.arguments.slice(0, separator),
      "--property=Environment=REA_TEST_LATE_VALUE=must-not-reach-provider",
      ...invocation.arguments.slice(separator),
    ];
    const { stdout } = await execFileAsync(
      "/usr/bin/systemd-run",
      argumentsWithLateVariable,
      { encoding: "utf8", timeout: 10_000 },
    );
    const environmentNames = stdout
      .trim()
      .split("\n")
      .map((entry) => entry.slice(0, entry.indexOf("=")))
      .sort();
    expect(environmentNames).toEqual(["PATH", "REA_PROCESS_RUN_ID", "TMPDIR"]);
  },
  15_000,
);

it.skipIf(process.env.REA_UNBLOB_ACCEPTANCE_ROOT === undefined)(
  "stops the exact systemd unit on cancellation and proves its cgroup is gone",
  async () => {
    const root = process.env.REA_UNBLOB_ACCEPTANCE_ROOT!;
    const workspace = await createTestTempDirectory(
      "rea-unblob-systemd-cancel-",
    );
    const runId = `rea-firmware-${randomUUID()}`;
    const profile = {
      rootDirectory: root,
      executable: join(root, "bin", "sleep"),
    };
    const spawned = await spawnUnblobSystemdProcess(profile, ["60"], {
      command: "/usr/bin/systemd-run",
      arguments: [],
      expectedCommand: "/usr/bin/systemd-run",
      runId,
      cwd: workspace,
    });
    const supervisor = new ProviderProcessSupervisor(
      { ...spawned, ownsProcessLifetime: true },
      { maxDiagnosticBytes: 4096 },
    );
    expect(await supervisor.waitForOutputClose(100)).toBe(false);
    const stopped = await supervisor.stop();
    expect(stopped).toEqual({ status: "verified-cleanup" });
    const { stdout: appCgroup } = await execFileAsync("/usr/bin/systemctl", [
      "--user",
      "show",
      "app.slice",
      "--property=ControlGroup",
      "--value",
    ]);
    const unit = `rea-unblob-${runId.slice("rea-firmware-".length)}`;
    const exact = join("/sys/fs/cgroup", appCgroup.trim(), `${unit}.service`);
    await expect(access(exact)).rejects.toMatchObject({ code: "ENOENT" });
  },
  15_000,
);
