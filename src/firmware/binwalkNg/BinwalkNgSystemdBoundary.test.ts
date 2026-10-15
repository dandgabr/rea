import { expect, it } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { join } from "node:path";
import { Readable } from "node:stream";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { consumeBinwalkNgTransfer } from "./BinwalkNgTransfer.js";
import {
  BINWALK_NG_CGROUP_LIMITS,
  BINWALK_NG_DYNAMIC_LOADER_ENVIRONMENT_NAMES,
  binwalkNgCgroupGateArguments,
  readBinwalkNgSystemdEnvironmentNames,
  parseBinwalkNgSystemdEnvironment,
  binwalkNgSystemdRunArguments,
  isBinwalkNgTmpfs,
} from "./BinwalkNgSystemdBoundary.js";

const execFileAsync = promisify(execFile);

it("places the complete selected process tree in a private bounded user service", () => {
  const arguments_ = binwalkNgSystemdRunArguments({
    runId: "rea-firmware-12345678-1234-1234-1234-123456789abc",
    cwd: "/tmp/rea work",
    command: process.execPath,
    inheritedEnvironmentNames: ["HOME", "LD_LIBRARY_PATH"],
    commandArguments: binwalkNgCgroupGateArguments({
      workRoot: "/tmp/rea work",
      command: "/usr/bin/prlimit",
      commandArguments: ["--cpu=120", "--", "/usr/bin/bwrap", "--version"],
    }),
  });
  expect(arguments_).toEqual([
    "--user",
    "--quiet",
    "--wait",
    "--collect",
    "--pipe",
    "--unit=rea-binwalk-ng-12345678-1234-1234-1234-123456789abc.service",
    "--property=MemoryMax=536870912",
    "--property=MemorySwapMax=0",
    "--property=TasksMax=64",
    "--property=CPUQuota=100%",
    "--property=RuntimeMaxSec=120s",
    "--property=KillMode=control-group",
    "--property=OOMPolicy=kill",
    "--property=UMask=0077",
    ...[
      ...new Set([...BINWALK_NG_DYNAMIC_LOADER_ENVIRONMENT_NAMES, "HOME"]),
    ].map((name) => `--property=UnsetEnvironment=${name}`),
    "--property=Environment=PATH=/usr/bin:/bin",
    "--property=Environment=REA_PROCESS_RUN_ID=rea-firmware-12345678-1234-1234-1234-123456789abc",
    "--property=WorkingDirectory=/tmp/rea work",
    "--",
    "/usr/bin/env",
    "-i",
    "PATH=/usr/bin:/bin",
    "REA_PROCESS_RUN_ID=rea-firmware-12345678-1234-1234-1234-123456789abc",
    process.execPath,
    "-e",
    expect.any(String),
    JSON.stringify({
      workRoot: "/tmp/rea work",
      memoryBytes: 536870912,
      tasks: 64,
    }),
    "/usr/bin/prlimit",
    "--cpu=120",
    "--",
    "/usr/bin/bwrap",
    "--version",
  ]);
  expect(BINWALK_NG_CGROUP_LIMITS).toMatchObject({
    memoryBytes: 512 * 1024 * 1024,
    memorySwapBytes: 0,
    tasks: 64,
    cpuQuotaPercent: 100,
    runtimeMs: 120_000,
  });
});

it("mounts a temporary byte- and inode-bounded workspace only for artifact transfer runs", () => {
  const arguments_ = binwalkNgSystemdRunArguments({
    runId: "rea-firmware-12345678-1234-1234-1234-123456789abc",
    cwd: "/tmp/rea workspace",
    command: process.execPath,
    commandArguments: [],
    workspaceQuota: {
      bytes: 16 * 1024 * 1024,
      inodes: 128,
      uid: 1000,
      gid: 1000,
    },
  });
  expect(arguments_).toContain(
    "--property=TemporaryFileSystem=/tmp/rea workspace:size=16777216,nr_inodes=128,mode=0700,uid=1000,gid=1000",
  );
  expect(arguments_).toContain("--property=WorkingDirectory=/");
});

it("extracts only valid environment names for a per-unit full environment reset", () => {
  expect(
    parseBinwalkNgSystemdEnvironment("HOME=/x\nLD_LIBRARY_PATH=/tmp\n"),
  ).toEqual(["HOME", "LD_LIBRARY_PATH"]);
  expect(() =>
    parseBinwalkNgSystemdEnvironment("not-an-assignment\n"),
  ).toThrow();
});

it("checks effective cgroup controls and the workspace filesystem before exec", () => {
  const args = binwalkNgCgroupGateArguments({
    workRoot: "/tmp/rea work",
    command: "/usr/bin/prlimit",
    commandArguments: ["--cpu=120", "--", "/usr/bin/bwrap"],
    workspaceQuota: { bytes: 16 * 1024 * 1024, inodes: 128 },
  });
  expect(args.slice(0, 2)).toEqual(["-e", expect.any(String)]);
  expect(args[1]).toContain("memory.max");
  expect(args[1]).toContain("memory.swap.max");
  expect(args[1]).toContain("pids.max");
  expect(args[1]).toContain("cpu.max");
  expect(args[1]).toContain("memory.oom.group");
  expect(args[1]).toContain("statfsSync");
  expect(args[1]).toContain("/proc/self/mountinfo");
  expect(args[1]).toContain("nr_inodes=");
  expect(args.slice(2)).toEqual([
    JSON.stringify({
      workRoot: "/tmp/rea work",
      memoryBytes: 536870912,
      tasks: 64,
      workspaceQuota: { bytes: 16 * 1024 * 1024, inodes: 128 },
    }),
    "/usr/bin/prlimit",
    "--cpu=120",
    "--",
    "/usr/bin/bwrap",
  ]);
});

it("configures a bounded transfer manifest for a producer-owned protocol stream", () => {
  const args = binwalkNgCgroupGateArguments({
    workRoot: "/tmp/work",
    command: "/usr/bin/true",
    commandArguments: [],
    transfer: {
      paths: ["reports/0000.json", "artifacts/0000"],
      maxBytes: 4096,
      maxFiles: 4,
      maxEntries: 8,
    },
  });
  expect(JSON.parse(args[2] ?? "{}")).toMatchObject({
    transfer: {
      paths: ["reports/0000.json", "artifacts/0000"],
      maxBytes: 4096,
      maxFiles: 4,
      maxEntries: 8,
    },
  });
  expect(args[1]).toContain("REABWNG1");
});

it("rejects caller-controlled unit names and distinguishes tmpfs from ordinary filesystems", () => {
  expect(() =>
    binwalkNgSystemdRunArguments({
      runId: "caller-controlled.service",
      cwd: "/tmp",
      command: "/usr/bin/true",
      commandArguments: [],
    }),
  ).toThrow("REA-generated process run identity");
  expect(isBinwalkNgTmpfs(0x01021994)).toBe(true);
  expect(isBinwalkNgTmpfs(0x794c7630)).toBe(false);
});

it.runIf(process.env.REA_RUN_USER_SYSTEMD_BOUNDARY_TEST === "1")(
  "clears manager variables added after the snapshot before the Node gate starts",
  async () => {
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("Linux uid is unavailable");
    const root = await createTestTempDirectory("rea-ng-systemd-gate-");
    const runtimeDirectory = `/run/user/${uid}`;
    const systemdEnvironment = {
      PATH: "/usr/bin:/bin",
      XDG_RUNTIME_DIR: runtimeDirectory,
      DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`,
    };
    const variable = `REA_BINWALK_NG_LATE_ENV_${process.pid}_${Date.now()}`;
    const names = await readBinwalkNgSystemdEnvironmentNames(uid);
    expect(names).not.toContain(variable);
    const lateVariables = [
      `${variable}=must-not-leak`,
      "LD_PRELOAD=/rea-nonexistent-loader-probe.so",
      "LD_AUDIT=/rea-nonexistent-audit-probe.so",
      "GLIBC_TUNABLES=glibc.malloc.tcache_count=7",
    ];
    expect(names).not.toContain("LD_PRELOAD");
    expect(names).not.toContain("LD_AUDIT");
    expect(names).not.toContain("GLIBC_TUNABLES");
    await execFileAsync(
      "/usr/bin/systemctl",
      ["--user", "set-environment", ...lateVariables],
      {
        encoding: "utf8",
        timeout: 10_000,
        env: systemdEnvironment,
      },
    );
    const unitName =
      "rea-binwalk-ng-12345678-1234-1234-1234-123456789abc.service";
    const probe = [
      "-e",
      `const { execFileSync } = require('node:child_process'); const unset = execFileSync('/usr/bin/systemctl', ['--user','show',${JSON.stringify(unitName)},'-p','UnsetEnvironment','--value'], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin', XDG_RUNTIME_DIR: ${JSON.stringify(runtimeDirectory)}, DBUS_SESSION_BUS_ADDRESS: ${JSON.stringify(`unix:path=${runtimeDirectory}/bus`)} } }).trim().split(/\\s+/u); process.stdout.write(JSON.stringify({ late: process.env[${JSON.stringify(variable)}] ?? null, leaked: ['HOME','LD_LIBRARY_PATH','LD_PRELOAD','LD_AUDIT','GLIBC_TUNABLES','CLOUDFLARE_API_TOKEN','NODE_OPTIONS'].filter((name) => process.env[name] !== undefined), path: process.env.PATH, token: process.env.REA_PROCESS_RUN_ID, unset }))`,
    ];
    try {
      const args = binwalkNgSystemdRunArguments({
        runId: "rea-firmware-12345678-1234-1234-1234-123456789abc",
        cwd: root,
        command: process.execPath,
        commandArguments: binwalkNgCgroupGateArguments({
          workRoot: root,
          command: process.execPath,
          commandArguments: probe,
        }),
        inheritedEnvironmentNames: names,
      });
      const result = await execFileAsync("/usr/bin/systemd-run", args, {
        encoding: "utf8",
        timeout: 30_000,
        env: systemdEnvironment,
      });
      expect(JSON.parse(result.stdout.trim())).toEqual({
        late: null,
        leaked: [],
        path: "/usr/bin:/bin",
        token: "rea-firmware-12345678-1234-1234-1234-123456789abc",
        unset: expect.arrayContaining([
          "LD_PRELOAD",
          "LD_AUDIT",
          "LD_LIBRARY_PATH",
          "GLIBC_TUNABLES",
        ]),
      });
      expect(result.stderr).not.toMatch(
        /(ERROR: ld\.so|cannot be preloaded|cannot be audited)/u,
      );
      expect(BINWALK_NG_CGROUP_LIMITS.memoryBytes).toBe(536870912);
    } finally {
      await execFileAsync(
        "/usr/bin/systemctl",
        [
          "--user",
          "unset-environment",
          variable,
          "LD_PRELOAD",
          "LD_AUDIT",
          "GLIBC_TUNABLES",
        ],
        {
          encoding: "utf8",
          timeout: 10_000,
          env: systemdEnvironment,
        },
      );
    }
  },
  40_000,
);

it.runIf(process.env.REA_RUN_USER_SYSTEMD_BOUNDARY_TEST === "1")(
  "frames quota-bounded producer files out of the private systemd tmpfs and verifies them into SafeOutputTree",
  async () => {
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("Linux uid is unavailable");
    const root = await createTestTempDirectory("rea-ng-systemd-transfer-");
    const runtimeDirectory = `/run/user/${uid}`;
    const transfer = {
      paths: ["reports/0000.json", "artifacts/0000"],
      maxBytes: 4096,
      maxFiles: 4,
      maxEntries: 8,
    };
    const quota = { bytes: 1024 * 1024, inodes: 24 };
    const gate = binwalkNgCgroupGateArguments({
      workRoot: root,
      workspaceQuota: quota,
      transfer,
      command: process.execPath,
      commandArguments: [
        "-e",
        "const fs=require('node:fs');fs.writeFileSync('reports/0000.json','[]');fs.mkdirSync('artifacts/0000',{recursive:true});fs.writeFileSync('artifacts/0000/000000_00000000_payload.raw','carved-bytes')",
      ],
    });
    const args = binwalkNgSystemdRunArguments({
      runId: "rea-firmware-12345678-1234-1234-1234-123456789abc",
      cwd: root,
      command: process.execPath,
      commandArguments: gate,
      workspaceQuota: { ...quota, uid, gid: process.getgid?.() ?? uid },
    });
    const result = await execFileAsync("/usr/bin/systemd-run", args, {
      encoding: "buffer",
      timeout: 30_000,
      env: {
        PATH: "/usr/bin:/bin",
        XDG_RUNTIME_DIR: runtimeDirectory,
        DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`,
      },
    });
    expect(
      await import("node:fs/promises").then(({ readdir }) => readdir(root)),
    ).toEqual([]);
    const tree = await SafeOutputTree.create(join(root, "staged"));
    try {
      const completed = await consumeBinwalkNgTransfer(
        Readable.from([result.stdout]),
        tree,
        {
          maxBytes: 4096,
          maxFiles: 4,
          maxEntries: 8,
          signal: AbortSignal.timeout(2_000),
        },
      );
      await tree.commit();
      expect(completed).toMatchObject({ files: 2 });
      expect(
        await import("node:fs/promises").then(({ readFile }) =>
          readFile(
            join(tree.outputRoot, "artifacts/0000/000000_00000000_payload.raw"),
            "utf8",
          ),
        ),
      ).toBe("carved-bytes");
    } finally {
      await tree.rollback();
    }
  },
  40_000,
);

it.runIf(process.env.REA_RUN_USER_SYSTEMD_BOUNDARY_TEST === "1")(
  "enforces producer-time tmpfs byte and inode ceilings in a private systemd mount and does not expose its files to the host",
  async () => {
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("Linux uid is unavailable");
    const root = await createTestTempDirectory("rea-ng-systemd-quota-");
    const runtimeDirectory = `/run/user/${uid}`;
    const quota = { bytes: 1024 * 1024, inodes: 20 };
    const gate = binwalkNgCgroupGateArguments({
      workRoot: root,
      workspaceQuota: quota,
      command: process.execPath,
      commandArguments: [
        "-e",
        "const fs=require('node:fs');let count=0;try{for(;count<100;count++)fs.writeFileSync('tmp/f'+count,'')}catch(e){if(e.code!=='ENOSPC')throw e}process.stdout.write(JSON.stringify({count,fs:fs.statfsSync('.').type}))",
      ],
    });
    const args = binwalkNgSystemdRunArguments({
      runId: "rea-firmware-12345678-1234-1234-1234-123456789abc",
      cwd: root,
      command: process.execPath,
      commandArguments: gate,
      workspaceQuota: { ...quota, uid, gid: process.getgid?.() ?? uid },
    });
    const result = await execFileAsync("/usr/bin/systemd-run", args, {
      encoding: "utf8",
      timeout: 30_000,
      env: {
        PATH: "/usr/bin:/bin",
        XDG_RUNTIME_DIR: runtimeDirectory,
        DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`,
      },
    });
    expect(JSON.parse(result.stdout.trim()).count).toBeLessThan(100);
    expect(
      await import("node:fs/promises").then(({ readdir }) => readdir(root)),
    ).toEqual([]);
  },
  40_000,
);
