import { statfs } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { firmwareToolUnavailable } from "../FirmwareCommand.js";

export const BINWALK_NG_CGROUP_LIMITS = {
  memoryBytes: 512 * 1024 * 1024,
  memorySwapBytes: 0,
  tasks: 64,
  cpuQuotaPercent: 100,
  runtimeMs: 120_000,
  outputBytes: 512 * 1024 * 1024,
} as const;

const runIdPattern =
  /^rea-firmware-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/u;

// systemd must remove these before it execs even the dynamically-linked env
// wrapper; env -i cannot protect that wrapper's own ELF loader.
export const BINWALK_NG_DYNAMIC_LOADER_ENVIRONMENT_NAMES = [
  "GLIBC_TUNABLES",
  "LD_ASSUME_KERNEL",
  "LD_AUDIT",
  "LD_BIND_NOT",
  "LD_BIND_NOW",
  "LD_DEBUG",
  "LD_DEBUG_OUTPUT",
  "LD_DYNAMIC_WEAK",
  "LD_HWCAP_MASK",
  "LD_LIBRARY_PATH",
  "LD_ORIGIN_PATH",
  "LD_POINTER_GUARD",
  "LD_PREFER_MAP_32BIT_EXEC",
  "LD_PRELOAD",
  "LD_PROFILE",
  "LD_PROFILE_OUTPUT",
  "LD_SHOW_AUXV",
  "LD_TRACE_LOADED_OBJECTS",
  "LD_USE_LOAD_BIAS",
  "LD_VERBOSE",
  "LD_WARN",
] as const;

export const isBinwalkNgTmpfs = (type: number): boolean => type === 0x01021994;

const execFileAsync = promisify(execFile);
export const parseBinwalkNgSystemdEnvironment = (output: string): string[] => {
  const names = new Set<string>();
  for (const line of output.split(/\r?\n/u)) {
    if (line.length === 0) continue;
    const separator = line.indexOf("=");
    const name = separator < 0 ? "" : line.slice(0, separator);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name))
      throw firmwareToolUnavailable(
        "binwalk-ng",
        "binwalk_ng_confinement",
        "The user-systemd manager environment could not be safely sanitized",
      );
    names.add(name);
  }
  return [...names].sort();
};

export const readBinwalkNgSystemdEnvironmentNames = async (
  uid: number,
  signal?: AbortSignal,
): Promise<string[]> => {
  const runtimeDirectory = `/run/user/${uid}`;
  try {
    const result = await execFileAsync(
      "/usr/bin/systemctl",
      ["--user", "show-environment"],
      {
        encoding: "utf8",
        maxBuffer: 1024 * 1024,
        signal,
        env: {
          PATH: "/usr/bin:/bin",
          XDG_RUNTIME_DIR: runtimeDirectory,
          DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`,
        },
      },
    );
    return parseBinwalkNgSystemdEnvironment(result.stdout);
  } catch (cause: unknown) {
    if (cause instanceof Error && cause.name === "AbortError") throw cause;
    throw firmwareToolUnavailable(
      "binwalk-ng",
      "binwalk_ng_confinement",
      `The user-systemd environment could not be enumerated for sanitization: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
};

const cgroupGateProgram = String.raw`
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const config = JSON.parse(process.argv[1]);
const fail = (reason = 'unknown') => { process.stderr.write('Binwalk-NG resource boundary verification failed: ' + reason + '\n'); process.exit(125); };
try {
  const cgroupLine = fs.readFileSync('/proc/self/cgroup', 'utf8').split('\n').find((line) => line.startsWith('0::'));
  if (!cgroupLine) fail('no unified cgroup');
  const relative = cgroupLine.slice(3);
  const root = path.resolve('/sys/fs/cgroup');
  const directory = path.resolve(root, '.' + relative);
  if (directory !== root && !directory.startsWith(root + path.sep)) fail('cgroup path escaped root');
  const read = (name) => fs.readFileSync(path.join(directory, name), 'utf8').trim();
  const memory = Number(read('memory.max'));
  const swap = Number(read('memory.swap.max'));
  const pids = Number(read('pids.max'));
  const baselineTasks = Number(read('pids.current'));
  const [quotaText, periodText] = read('cpu.max').split(/\s+/);
  const quota = Number(quotaText), period = Number(periodText);
  const oomGroup = read('memory.oom.group');
  const stat = fs.statfsSync(config.workRoot);
  if (config.workspaceQuota) {
    const escaped = config.workRoot.replace(/\\/g, '\\134').replace(/ /g, '\\040');
    const mount = fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n').find((line) => line.split(' ')[4] === escaped);
    if (!mount) fail('workspace tmpfs mount not found');
    const superOptions = mount.split(' - ')[1]?.split(' ')[2]?.split(',') ?? [];
    const expectedSizeKiB = Math.ceil(config.workspaceQuota.bytes / 1024);
    if (!superOptions.includes('size=' + expectedSizeKiB + 'k') ||
        !superOptions.includes('nr_inodes=' + config.workspaceQuota.inodes)) fail('workspace tmpfs quota mismatch: ' + superOptions.join(','));
    for (const name of ['reports', 'artifacts', 'home', 'tmp'])
      fs.mkdirSync(path.join(config.workRoot, name), { recursive: true, mode: 0o700 });
    process.chdir(config.workRoot);
  }
  if (!Number.isSafeInteger(memory) || memory <= 0 || memory > config.memoryBytes ||
      swap !== 0 || !Number.isSafeInteger(pids) || pids <= 0 || pids > config.tasks ||
      !Number.isSafeInteger(baselineTasks) || baselineTasks <= 0 || baselineTasks > pids ||
      !Number.isFinite(quota) || !Number.isFinite(period) || quota <= 0 || period <= 0 || quota > period ||
      oomGroup !== '1' || Number(stat.type) !== 0x01021994) fail('effective cgroup/tmpfs limits: memory=' + memory + ' swap=' + swap + ' pids=' + pids + ' current=' + baselineTasks + ' oom=' + oomGroup + ' fs=' + Number(stat.type));
  const result = spawnSync(process.argv[2], process.argv.slice(3), {
    shell: false,
    stdio: config.transfer ? ['inherit', 2, 2] : 'inherit',
  });
  if (result.error) { process.stderr.write('Binwalk-NG confined command could not start\n'); process.exit(125); }
  if (result.status !== 0) process.exit(result.status === null ? 125 : result.status);
  if (!config.transfer) process.exit(0);
  (async () => {
    const cgroup = path.resolve('/sys/fs/cgroup', '.' + relative);
    const taskPath = path.join(cgroup, 'pids.current');
    let finalTasks = Number(fs.readFileSync(taskPath, 'utf8').trim());
    const taskDeadline = Date.now() + 2_000;
    while (finalTasks !== baselineTasks && Date.now() < taskDeadline) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      finalTasks = Number(fs.readFileSync(taskPath, 'utf8').trim());
    }
    if (finalTasks !== baselineTasks) fail('task count changed from ' + baselineTasks + ' to ' + finalTasks);
    const hashFile = async (file) => {
      const hash = require('node:crypto').createHash('sha256');
      let size = 0;
      for await (const chunk of fs.createReadStream(file)) { size += chunk.length; hash.update(chunk); }
      return { size, sha256: hash.digest('hex') };
    };
    const write = (chunk) => new Promise((resolve, reject) => {
      process.stdout.write(chunk, (error) => error ? reject(error) : resolve());
    });
    const jsonFrame = (value) => {
      const body = Buffer.from(JSON.stringify(value));
      if (body.length > 16384) fail();
      const length = Buffer.alloc(4); length.writeUInt32BE(body.length);
      return Buffer.concat([length, body]);
    };
    let files = 0, bytes = 0, entries = 0;
    const directories = new Set();
    const seen = new Set();
    const emitFile = async (file, relative) => {
      if (files >= config.transfer.maxFiles) fail('file count limit');
      const before = fs.lstatSync(file, { bigint: true });
      if (!before.isFile()) fail('output is not a regular file');
      const measured = await hashFile(file);
      if (measured.size > config.transfer.maxBytes - bytes) fail('output byte limit');
      const header = { type: 'file', path: relative.split(path.sep).join('/'), bytes: measured.size, sha256: measured.sha256 };
      await write(jsonFrame(header));
      const transferHash = require('node:crypto').createHash('sha256');
      let transferred = 0;
      for await (const chunk of fs.createReadStream(file)) {
        transferred += chunk.length; transferHash.update(chunk); await write(chunk);
      }
      const after = fs.lstatSync(file, { bigint: true });
      if (transferred !== measured.size || transferHash.digest('hex') !== measured.sha256 ||
          before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs) fail('output changed during transfer');
      files += 1; bytes += measured.size;
    };
    const walk = async (relative) => {
      const normalized = path.posix.normalize(relative);
      if (!normalized || normalized === '.' || normalized.startsWith('../') || path.posix.isAbsolute(normalized) || normalized !== relative) fail('invalid configured output path');
      const absolute = path.join(config.workRoot, ...normalized.split('/'));
      const stat = fs.lstatSync(absolute, { bigint: true });
      if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) fail('output contains symlink or special file');
      if (stat.isFile()) { await emitFile(absolute, normalized); return; }
      const children = fs.readdirSync(absolute).sort();
      for (const child of children) await walk(path.posix.join(normalized, child));
    };
    await write(Buffer.from('REABWNG1'));
    for (const relative of config.transfer.paths) await walk(relative);
    for (const relative of config.transfer.paths) {
      let directory = path.posix.dirname(relative);
      while (directory !== '.' && directory !== '/') { directories.add(directory); directory = path.posix.dirname(directory); }
    }
    entries = files + directories.size;
    if (entries > config.transfer.maxEntries) fail('output entry limit');
    await write(jsonFrame({ type: 'end', files, bytes }));
  })().catch(() => fail());
} catch { fail(); }
`;

export const binwalkNgCgroupGateArguments = (input: {
  readonly workRoot: string;
  readonly command: string;
  readonly commandArguments: readonly string[];
  readonly workspaceQuota?: {
    readonly bytes: number;
    readonly inodes: number;
  };
  readonly transfer?: {
    readonly paths: readonly string[];
    readonly maxBytes: number;
    readonly maxFiles: number;
    readonly maxEntries: number;
  };
}): string[] => {
  if (!input.workRoot.startsWith("/") || !input.command.startsWith("/"))
    throw firmwareToolUnavailable(
      "binwalk-ng",
      "binwalk_ng_confinement",
      "The resource gate requires absolute workspace and command paths",
    );
  return [
    "-e",
    cgroupGateProgram,
    JSON.stringify({
      workRoot: input.workRoot,
      memoryBytes: BINWALK_NG_CGROUP_LIMITS.memoryBytes,
      tasks: BINWALK_NG_CGROUP_LIMITS.tasks,
      ...(input.workspaceQuota === undefined
        ? {}
        : { workspaceQuota: input.workspaceQuota }),
      ...(input.transfer === undefined ? {} : { transfer: input.transfer }),
    }),
    input.command,
    ...input.commandArguments,
  ];
};

export const requireBinwalkNgTmpfs = async (
  root: string,
  operation: string,
): Promise<void> => {
  let observed: Awaited<ReturnType<typeof statfs>>;
  try {
    observed = await statfs(root);
  } catch (cause: unknown) {
    throw firmwareToolUnavailable(
      "binwalk-ng",
      operation,
      `The private workspace filesystem could not be identified: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  if (!isBinwalkNgTmpfs(observed.type))
    throw firmwareToolUnavailable(
      "binwalk-ng",
      operation,
      "Native Binwalk-NG requires a private tmpfs workspace so the aggregate cgroup memory ceiling also bounds staged output bytes",
    );
};

export const binwalkNgSystemdRunArguments = (input: {
  readonly runId: string;
  readonly cwd: string;
  readonly command: string;
  readonly commandArguments: readonly string[];
  readonly inheritedEnvironmentNames?: readonly string[];
  readonly workspaceQuota?: {
    readonly bytes: number;
    readonly inodes: number;
    readonly uid: number;
    readonly gid: number;
  };
}): string[] => {
  const match = runIdPattern.exec(input.runId);
  if (match === null)
    throw firmwareToolUnavailable(
      "binwalk-ng",
      "binwalk_ng_confinement",
      "The systemd unit requires an REA-generated process run identity",
    );
  if (!input.cwd.startsWith("/") || !input.command.startsWith("/"))
    throw firmwareToolUnavailable(
      "binwalk-ng",
      "binwalk_ng_confinement",
      "The systemd working directory and command must be absolute paths",
    );
  const quota = input.workspaceQuota;
  if (
    quota !== undefined &&
    [quota.bytes, quota.inodes, quota.uid, quota.gid].some(
      (value) => !Number.isSafeInteger(value) || value < 0,
    )
  )
    throw firmwareToolUnavailable(
      "binwalk-ng",
      "binwalk_ng_confinement",
      "The private tmpfs quota requires safe integer bytes, inodes, uid and gid",
    );
  const limits = BINWALK_NG_CGROUP_LIMITS;
  return [
    "--user",
    "--quiet",
    "--wait",
    "--collect",
    "--pipe",
    `--unit=rea-binwalk-ng-${match[1]}.service`,
    `--property=MemoryMax=${limits.memoryBytes}`,
    `--property=MemorySwapMax=${limits.memorySwapBytes}`,
    `--property=TasksMax=${limits.tasks}`,
    `--property=CPUQuota=${limits.cpuQuotaPercent}%`,
    `--property=RuntimeMaxSec=${limits.runtimeMs / 1000}s`,
    "--property=KillMode=control-group",
    "--property=OOMPolicy=kill",
    "--property=UMask=0077",
    ...(quota === undefined
      ? []
      : [
          `--property=TemporaryFileSystem=${input.cwd}:size=${quota.bytes},nr_inodes=${quota.inodes},mode=0700,uid=${quota.uid},gid=${quota.gid}`,
        ]),
    ...[
      ...new Set([
        ...BINWALK_NG_DYNAMIC_LOADER_ENVIRONMENT_NAMES,
        ...(input.inheritedEnvironmentNames ?? []),
      ]),
    ].map((name) => `--property=UnsetEnvironment=${name}`),
    "--property=Environment=PATH=/usr/bin:/bin",
    `--property=Environment=REA_PROCESS_RUN_ID=${input.runId}`,
    `--property=WorkingDirectory=${quota === undefined ? input.cwd : "/"}`,
    "--",
    // systemd manager variables are mutable concurrently. Reset the environment
    // in a trusted executable before the Node gate/interpreter starts.
    "/usr/bin/env",
    "-i",
    "PATH=/usr/bin:/bin",
    `REA_PROCESS_RUN_ID=${input.runId}`,
    input.command,
    ...input.commandArguments,
  ];
};
