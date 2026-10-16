import { createHash, randomUUID } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import {
  access,
  chmod,
  mkdir,
  readFile,
  readlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { ProviderProcessSupervisor } from "../process/ProviderProcess.js";
import {
  auditUnblobRuntimeStartupFiles,
  assertUnblobRuntimeAdmissionQueueBound,
  assertUnblobRuntimeNodeBudget,
  buildUnblobSystemdInvocation,
  spawnUnblobSystemdProcess,
} from "./UnblobSystemd.js";

const execFileAsync = promisify(execFile);
const protectedRuntimeProfile = {
  rootDirectory: "/",
  executable: "/usr/bin/env",
  pythonExecutable: "/usr/bin/python3",
};

it.each([0o700, 0o555])(
  "refuses a caller-owned runtime root even with mode %s",
  async (mode) => {
    const workspace = await createTestTempDirectory(
      "rea-unblob-mutable-runtime-",
    );
    const root = join(workspace, "runtime-root");
    await mkdir(join(root, "usr/local/bin"), { recursive: true });
    const executable = join(root, "usr/local/bin/unblob");
    const python = join(root, "usr/local/bin/python3");
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await writeFile(python, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await chmod(root, mode);

    await expect(
      buildUnblobSystemdInvocation(
        { rootDirectory: root, executable, pythonExecutable: python },
        ["--version"],
        workspace,
      ),
    ).rejects.toThrow(/Python runtime is mutable or unverifiable/u);
    await chmod(root, 0o700);
  },
);

it("rejects Python interpreters outside the supported system prefixes", async () => {
  const workspace = await createTestTempDirectory(
    "rea-unblob-custom-python-prefix-",
  );
  const root = join(workspace, "runtime-root");
  const executable = join(root, "usr/local/bin/unblob");
  const python = join(root, "opt/python/bin/python3");
  await mkdir(join(root, "usr/local/bin"), { recursive: true });
  await mkdir(join(root, "opt/python/bin"), { recursive: true });
  await writeFile(executable, "x", { mode: 0o700 });
  await writeFile(python, "x", { mode: 0o700 });

  await expect(
    buildUnblobSystemdInvocation(
      { rootDirectory: root, executable, pythonExecutable: python },
      ["--version"],
      workspace,
    ),
  ).rejects.toThrow(/supported system prefix/u);
});

it("bounds queued runtime nodes before admitting a large single directory", () => {
  expect(() => assertUnblobRuntimeAdmissionQueueBound(0, 100_000, 1)).toThrow(
    /bounded admission scan/u,
  );
  expect(() =>
    assertUnblobRuntimeAdmissionQueueBound(0, 99_999, 1),
  ).not.toThrow();
});

it("bounds the root-level runtime library scan before queuing candidates", () => {
  expect(() => assertUnblobRuntimeNodeBudget(100_000)).toThrow(
    /bounded admission scan/u,
  );
  expect(assertUnblobRuntimeNodeBudget(99_999)).toBe(100_000);
});

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
    { ...protectedRuntimeProfile, inputPath: input },
    ["--skip-extraction", "--force", "--report", report, "--log", log, input],
    privateWorkspace,
  );

  expect(invocation.arguments).toContain("--user");
  expect(invocation.arguments).toContain("--property=PrivateNetwork=yes");
  expect(invocation.arguments).toContain("--property=PrivateDevices=yes");
  expect(invocation.arguments).toContain("--property=PrivatePIDs=yes");
  expect(invocation.arguments).toContain("--property=PrivateIPC=yes");
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
    "/usr/bin/python3.14",
    "-I",
    "-S",
  ]);
  const gateConfig = JSON.parse(
    invocation.arguments.find((value) =>
      value.startsWith('{"host_pid_namespace"'),
    )!,
  ) as { host_pid_namespace: string; host_ipc_namespace: string };
  expect(gateConfig.host_pid_namespace).toMatch(/^pid:\[\d+\]$/u);
  expect(gateConfig.host_ipc_namespace).toMatch(/^ipc:\[\d+\]$/u);
  expect(invocation.arguments).toContain("--property=MemoryMax=1073741824");
  expect(invocation.arguments).toContain("--property=MemorySwapMax=0");
  expect(invocation.arguments).toContain("--property=TasksMax=128");
  expect(invocation.arguments).toContain("--property=CPUQuota=100%");
  expect(invocation.arguments).toContain("--property=RuntimeMaxSec=120s");
  expect(invocation.arguments).toContain("--property=LimitFSIZE=67108864");
  expect(invocation.arguments).toContain(
    "--property=TemporaryFileSystem=/tmp:mode=1777,size=67108864,nr_inodes=512",
  );
  expect(invocation.arguments).toContain("--property=RootDirectory=/");
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
        ...protectedRuntimeProfile,
        inputPath: input,
      },
      [input],
      join(workspace, "other"),
    ),
  ).rejects.toThrow(/private firmware workspace/u);
});

it("bounds inherited systemd manager environment properties before unit launch", async () => {
  const workspace = await createTestTempDirectory("rea-unblob-systemd-env-");
  await expect(
    buildUnblobSystemdInvocation(
      protectedRuntimeProfile,
      ["--version"],
      workspace,
      `rea-firmware-${randomUUID()}`,
      Array.from({ length: 257 }, (_, index) => `REA_TEST_${index}`),
    ),
  ).rejects.toThrow(/manager environment exceeds/u);
});

it.each([
  {
    name: "a caller .pth startup hook",
    path: "usr/local/lib/python3.12/site-packages/rea-hostile.pth",
    contents: "import pathlib; pathlib.Path('/tmp/rea-pth-ran').touch()\n",
  },
  {
    name: "a caller sitecustomize hook",
    path: "usr/local/lib/python3.12/site-packages/sitecustomize.py",
    contents: "raise RuntimeError('must not run')\n",
  },
  {
    name: "a caller usercustomize hook",
    path: "usr/local/lib/python3.12/site-packages/usercustomize.py",
    contents: "raise RuntimeError('must not run')\n",
  },
  {
    name: "a modified file using the pinned setuptools .pth name",
    path: "usr/local/lib/python3.12/site-packages/distutils-precedence.pth",
    contents: "import pathlib; pathlib.Path('/tmp/rea-pth-ran').touch()\n",
  },
  {
    name: "a caller-installed Unblob entrypoint, even with a known target digest",
    path: "usr/local/lib/python3.12/site-packages/rea_custom_plugin-1.0.dist-info/entry_points.txt",
    contents: "[unblob_v1]\ncustom = rea_custom_plugin:install\n",
  },
])("refuses $name before Python startup", async ({ path, contents }) => {
  const workspace = await createTestTempDirectory(
    "rea-unblob-startup-admission-",
  );
  const root = join(workspace, "runtime-root");
  const sitePackages = join(root, "usr/local/lib/python3.12/site-packages");
  await mkdir(sitePackages, { recursive: true });
  const executable = join(root, "usr/local/bin/unblob");
  const python = join(root, "usr/local/bin/python3");
  await mkdir(join(root, "usr/local/bin"), { recursive: true });
  await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await writeFile(python, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  const injected = join(root, path);
  await mkdir(join(injected, ".."), { recursive: true });
  await writeFile(injected, contents);
  if (path.endsWith("entry_points.txt")) {
    const plugin = "def install():\n    return None\n";
    await writeFile(join(sitePackages, "rea_custom_plugin.py"), plugin);
    expect(createHash("sha256").update(plugin).digest("hex")).toBe(
      "fbb7d7880ee8891e5de603763bb9a1f5a39175fe8f25076713f248dc09265afe",
    );
  }

  await expect(auditUnblobRuntimeStartupFiles(root)).rejects.toThrow(
    /startup hook|sitecustomize|unblob_v1 plugin/u,
  );
});

it("rejects FIFO entry-point metadata without opening it", async () => {
  const workspace = await createTestTempDirectory(
    "rea-unblob-entrypoint-fifo-",
  );
  const root = join(workspace, "runtime-root");
  const sitePackages = join(root, "usr/local/lib/python3.12/site-packages");
  const metadata = join(sitePackages, "rea-custom-1.0.dist-info");
  const entryPoints = join(metadata, "entry_points.txt");
  await mkdir(metadata, { recursive: true });
  await execFileAsync("/usr/bin/mkfifo", [entryPoints]);

  const writer = execFileAsync("/usr/bin/python3", [
    "-I",
    "-S",
    "-c",
    [
      "import errno, os, sys, time",
      "path = sys.argv[1]",
      "for _ in range(100):",
      "    try:",
      "        fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)",
      "    except OSError as error:",
      "        if error.errno != errno.ENXIO: raise",
      "        time.sleep(0.005)",
      "    else:",
      "        os.write(fd, b'[unblob_v1]\\ncustom = bad:plugin\\n')",
      "        os.close(fd)",
      "        raise SystemExit(1)",
      "raise SystemExit(0)",
    ].join("\n"),
    entryPoints,
  ]);

  const observedWriter = writer.then(
    (result) => ({ result }),
    (error: unknown) => ({ error }),
  );

  await expect(auditUnblobRuntimeStartupFiles(root)).rejects.toThrow(
    /not a regular file/u,
  );
  await expect(observedWriter).resolves.toMatchObject({
    result: { stdout: "" },
  });
});

it("admits the pinned setuptools .pth by digest without executing it", async () => {
  const workspace = await createTestTempDirectory("rea-unblob-pinned-hook-");
  const root = join(workspace, "runtime-root");
  const bin = join(root, "usr/local/bin");
  const sitePackages = join(root, "usr/local/lib/python3.12/site-packages");
  await mkdir(bin, { recursive: true });
  await mkdir(sitePackages, { recursive: true });
  const executable = join(bin, "unblob");
  const python = join(bin, "python3");
  await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await writeFile(python, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await writeFile(
    join(sitePackages, "distutils-precedence.pth"),
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
  );

  await expect(auditUnblobRuntimeStartupFiles(root)).resolves.toBeUndefined();
});

it.each([
  { name: "a startup directory over its entry budget", target: "directory" },
  {
    name: "cumulative entries split across two under-limit directories",
    target: "cumulative-directories",
  },
  { name: "an oversized .pth file", target: "pth" },
  { name: "oversized entry-point metadata", target: "entry-points" },
])("fails closed for $name", async ({ target }) => {
  const workspace = await createTestTempDirectory("rea-unblob-startup-bounds-");
  const root = join(workspace, "runtime-root");
  const sitePackages = join(root, "usr/local/lib/python3.12/site-packages");
  await mkdir(sitePackages, { recursive: true });
  const secondSitePackages =
    target === "cumulative-directories"
      ? join(root, "usr/local/lib/python3.13/site-packages")
      : sitePackages;
  if (target === "directory") {
    await Promise.all(
      Array.from({ length: 8193 }, (_, index) =>
        writeFile(join(sitePackages, `asset-${index}.data`), ""),
      ),
    );
  } else if (target === "cumulative-directories") {
    await mkdir(secondSitePackages, { recursive: true });
    await Promise.all(
      [sitePackages, secondSitePackages].flatMap((directory) =>
        Array.from({ length: 2500 }, (_, index) =>
          writeFile(join(directory, `asset-${index}.data`), ""),
        ),
      ),
    );
  } else if (target === "pth") {
    await writeFile(
      join(sitePackages, "large-hook.pth"),
      Buffer.alloc(1024 * 1024 + 1, 0x78),
    );
  } else {
    const metadata = join(sitePackages, "large-1.0.dist-info");
    await mkdir(metadata);
    await writeFile(
      join(metadata, "entry_points.txt"),
      Buffer.concat([
        Buffer.from("[console_scripts]\\n"),
        Buffer.alloc(1024 * 1024 + 1, 0x23),
      ]),
    );
  }

  await expect(auditUnblobRuntimeStartupFiles(root)).rejects.toThrow(
    /bounded entry scan|exceeds 1048576 bytes/u,
  );

  const invocation = await buildUnblobSystemdInvocation(
    protectedRuntimeProfile,
    ["--version"],
    workspace,
  );
  const gate = await readFile(
    join(
      workspace,
      `rea-unblob-gate-${invocation.unit.slice("rea-unblob-".length)}.py`,
    ),
    "utf8",
  );
  const startupAudit = extractEmbeddedStartupAudit(gate);
  const pythonScript = [
    "import configparser, hashlib, os, pathlib, stat, sys, sysconfig",
    "def fail(reason='policy mismatch'):",
    "    print(reason, file=sys.stderr)",
    "    raise SystemExit(125)",
    "sysconfig.get_paths = lambda: {'purelib': sys.argv[1], 'platlib': sys.argv[2], 'stdlib': sys.argv[1], 'platstdlib': sys.argv[2]}",
    startupAudit,
    "audit_runtime_startup_files()",
  ].join("\n");
  const startupAuditPath = join(workspace, "startup-audit.py");
  await writeFile(startupAuditPath, pythonScript);
  await expect(
    execFileAsync("/usr/bin/python3", [
      "-I",
      "-S",
      startupAuditPath,
      sitePackages,
      secondSitePackages,
    ]),
  ).rejects.toThrow(/bounded entry scan|exceeds 1048576 bytes/u);
});

function extractEmbeddedStartupAudit(gate: string): string {
  const start = gate.indexOf("def audit_runtime_startup_files():");
  const end = gate.indexOf(
    "\nsite_paths = audit_runtime_startup_files()",
    start,
  );
  if (start < 0 || end < 0)
    throw new Error("Embedded Python startup audit could not be located");
  return gate.slice(start, end);
}

it("keeps Python site initialization and Unblob execution behind the in-unit admission gate", async () => {
  const workspace = await createTestTempDirectory("rea-unblob-startup-gate-");
  const root = join(workspace, "runtime-root");
  await mkdir(join(root, "bin"), { recursive: true });
  const executable = join(root, "bin", "unblob");
  const python = join(root, "bin", "python3");
  await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await writeFile(python, "#!/bin/sh\nexit 0\n", { mode: 0o700 });

  const invocation = await buildUnblobSystemdInvocation(
    protectedRuntimeProfile,
    ["--version"],
    workspace,
  );
  const gateArgument = invocation.arguments.at(-4);
  expect(gateArgument).toMatch(/^\/tmp\/rea-unblob-gate\.py$/u);
  const gate = await readFile(
    join(
      workspace,
      `rea-unblob-gate-${invocation.unit.slice("rea-unblob-".length)}.py`,
    ),
    "utf8",
  );
  await execFileAsync("/usr/bin/python3", [
    "-I",
    "-S",
    "-c",
    "import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(), sys.argv[1], 'exec')",
    join(
      workspace,
      `rea-unblob-gate-${invocation.unit.slice("rea-unblob-".length)}.py`,
    ),
  ]);
  const admission = gate.indexOf("site_paths = audit_runtime_startup_files()");
  const producer = gate.indexOf(
    "runpy.run_path(sys.argv[0], run_name='__main__')",
  );
  expect(admission).toBeGreaterThan(-1);
  const namespaceAdmission = gate.indexOf(
    "if os.readlink('/proc/self/ns/ipc') == host_ipc_namespace:",
  );
  const providerBootstrap = gate.indexOf(
    "runpy.run_path(sys.argv[0], run_name='__main__')",
  );
  expect(namespaceAdmission).toBeGreaterThan(-1);
  expect(namespaceAdmission).toBeLessThan(providerBootstrap);
  expect(gate.slice(0, namespaceAdmission)).not.toContain(
    "import configparser",
  );
  const beforeCgroupAdmission = gate.slice(
    0,
    gate.indexOf("    cgroup_line ="),
  );
  const verifyNamespaceGate = async (config: object) =>
    execFileAsync(
      "/usr/bin/python3",
      [
        "-I",
        "-S",
        "-c",
        "import sys; code, config = sys.argv[1:3]; sys.argv = ['gate.py', config]; exec(code)",
        `${beforeCgroupAdmission}    print('IPC admitted')\nexcept SystemExit:\n    raise\n`,
        JSON.stringify(config),
      ],
      { encoding: "utf8" },
    );
  await expect(
    verifyNamespaceGate({
      host_pid_namespace: "pid:[different]",
      host_ipc_namespace: await readlink("/proc/self/ns/ipc"),
    }),
  ).rejects.toThrow(/PrivateIPC is unavailable or was not applied/u);
  await expect(
    verifyNamespaceGate({ host_pid_namespace: "pid:[different]" }),
  ).rejects.toThrow(/host IPC namespace identity is unavailable/u);
  expect(
    gate.indexOf("audit_immutable_runtime(_runtime_paths)"),
  ).toBeGreaterThan(
    gate.indexOf("import configparser, hashlib, re, runpy, stat, sysconfig"),
  );
  expect(gate.indexOf("audit_immutable_runtime(_runtime_paths)")).toBeLessThan(
    admission,
  );
  expect(gate).toContain("list(sys.path)");
  expect(gate).toContain(
    "def enqueue_bounded(pending, visited_count, candidate):",
  );
  expect(gate).toContain("enqueue_bounded(pending, len(visited), child)");
  expect(gate).not.toContain("pending.extend(resolved.iterdir())");
  const lexicalScanStart = gate.indexOf(
    "            for ancestor in (lexical, *lexical.parents):",
  );
  const lexicalScanEnd = gate.indexOf(
    "            if candidate.is_symlink():",
    lexicalScanStart,
  );
  expect(lexicalScanStart).toBeGreaterThan(-1);
  expect(gate.slice(lexicalScanStart, lexicalScanEnd)).toContain(
    "                visited.add(ancestor)",
  );
  const boundStart = gate.indexOf("def fail(");
  const boundEnd = gate.indexOf("def audit_immutable_runtime(");
  const boundHelper = gate.slice(boundStart, boundEnd);
  await expect(
    execFileAsync("/usr/bin/python3", [
      "-I",
      "-S",
      "-c",
      "import sys; exec(sys.argv[1]); pending = [None] * 100000; enqueue_bounded(pending, 0, 'overflow')",
      boundHelper,
    ]),
  ).rejects.toThrow(/runtime admission scan exceeds its bound/u);
  await execFileAsync("/usr/bin/python3", [
    "-I",
    "-S",
    "-c",
    "import sys; exec(sys.argv[1]); pending = [None] * 99999; enqueue_bounded(pending, 0, 'last'); assert len(pending) == 100000",
    boundHelper,
  ]);
  expect(producer).toBeGreaterThan(admission);
  expect(gate).not.toMatch(/\bsite\.main\s*\(/u);
  expect(
    gate.indexOf(
      "pluggy.PluginManager.load_setuptools_entrypoints = disable_setuptools_plugin_discovery",
    ),
  ).toBeGreaterThan(admission);
  expect(
    gate.indexOf(
      "pluggy.PluginManager.load_setuptools_entrypoints = disable_setuptools_plugin_discovery",
    ),
  ).toBeLessThan(producer);
});

it("verifies the effective file-size limit before launching Unblob", async () => {
  const workspace = await createTestTempDirectory("rea-unblob-fsize-gate-");
  const root = join(workspace, "runtime-root");
  await mkdir(join(root, "bin"), { recursive: true });
  const executable = join(root, "bin", "unblob");
  const python = join(root, "bin", "python3");
  await writeFile(executable, "x", { mode: 0o700 });
  await writeFile(python, "x", { mode: 0o700 });

  const invocation = await buildUnblobSystemdInvocation(
    protectedRuntimeProfile,
    ["--version"],
    workspace,
  );
  const gatePath = join(
    workspace,
    `rea-unblob-gate-${invocation.unit.slice("rea-unblob-".length)}.py`,
  );
  const gate = await readFile(gatePath, "utf8");
  const start = gate.indexOf(
    "    file_size_soft, file_size_hard = resource.getrlimit(resource.RLIMIT_FSIZE)",
  );
  const end = gate.indexOf("    cgroup_line =", start);
  expect(start).toBeGreaterThan(-1);
  expect(end).toBeGreaterThan(start);
  expect(
    gate.indexOf("runpy.run_path(sys.argv[0], run_name='__main__')"),
  ).toBeGreaterThan(end);

  const fileSizeGate = gate.slice(start, end).trim().replace(/^    /gmu, "");
  const verifyLimit = (softLimit: number, hardLimit: number) =>
    execFileAsync(
      "/usr/bin/python3",
      [
        "-I",
        "-S",
        "-c",
        "import resource, sys; soft, hard, maximum, source = sys.argv[1:5]; resource.getrlimit = lambda _: (int(soft), int(hard)); config = {'file_size_bytes': int(maximum)}; fail = lambda reason: (_ for _ in ()).throw(SystemExit(reason)); exec(source)",
        String(softLimit),
        String(hardLimit),
        "8",
        `import resource\n${fileSizeGate}`,
      ],
      { encoding: "utf8" },
    );

  await verifyLimit(7, 8);
  await expect(verifyLimit(9, 8)).rejects.toThrow(/file-size limit mismatch/u);
  await expect(verifyLimit(8, 9)).rejects.toThrow(/file-size limit mismatch/u);
  await expect(verifyLimit(-1, 8)).rejects.toThrow(
    /file-size limit is unbounded/u,
  );
  await expect(verifyLimit(8, -1)).rejects.toThrow(
    /file-size limit is unbounded/u,
  );
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
      ...protectedRuntimeProfile,
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
    file_size_bytes: 67108864,
    max_bytes: 4096,
    max_entries: 12,
    tmpfs_bytes: 8392704,
  });
  await expect(
    buildUnblobSystemdInvocation(
      protectedRuntimeProfile,
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
  "keeps an unrelated host-readable canary outside the admitted runtime view",
  async () => {
    const root = process.env.REA_UNBLOB_ACCEPTANCE_ROOT!;
    const workspace = await createTestTempDirectory("rea-unblob-host-canary-");
    const canary = join(workspace, "host-readable-canary.txt");
    await writeFile(canary, "must remain outside RootDirectory");
    const runId = `rea-firmware-${randomUUID()}`;
    const spawned = await spawnUnblobSystemdProcess(
      {
        rootDirectory: root,
        executable: join(root, "usr", "local", "bin", "python3"),
      },
      [
        "-c",
        "import os,sys; raise SystemExit(1 if os.path.exists(sys.argv[1]) else 0)",
        canary,
      ],
      {
        command: "/usr/bin/systemd-run",
        arguments: [],
        expectedCommand: "/usr/bin/systemd-run",
        runId,
        cwd: workspace,
      },
    );
    const supervisor = new ProviderProcessSupervisor(
      { ...spawned, ownsProcessLifetime: true },
      { maxDiagnosticBytes: 4096 },
    );
    await supervisor.waitForOutputClose(5000);
    expect(supervisor.snapshot()).toMatchObject({
      exitCode: 0,
      stdout: { text: "" },
      stderr: { text: "" },
    });
    expect(await supervisor.stop()).toEqual({ status: "verified-cleanup" });
  },
  15_000,
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
