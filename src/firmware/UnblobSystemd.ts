import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, open, realpath, readlink, writeFile } from "node:fs/promises";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import {
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import {
  cleanupOwnedProcessGroup,
  type ProcessCleanupResult,
} from "../process/ProcessOwnership.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";

const execFileAsync = promisify(execFile);
const SERVICE_LIMITS = {
  memoryMax: 1024 * 1024 * 1024,
  tasksMax: 128,
  cpuQuota: "100%",
  runtimeMax: "120s",
  fileSizeMax: FIRMWARE_LIMITS.extractionBytes,
} as const;
const runIdPattern =
  /^rea-firmware-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/u;
const cgroupGate = String.raw`import json, os, pathlib, sys
config = json.loads(sys.argv[1])
def fail(reason='policy mismatch'):
    print('Unblob systemd resource boundary verification failed: ' + reason, file=sys.stderr)
    raise SystemExit(125)
try:
    if os.readlink('/proc/self/ns/pid') == config['host_pid_namespace']:
        fail('PrivatePIDs is unavailable or was not applied')
    cgroup_line = next(line for line in open('/proc/self/cgroup', encoding='ascii') if line.startswith('0::'))
    process_cgroup = '/' + cgroup_line[3:].strip().strip('/')
    if process_cgroup == '/' or '..' in pathlib.PurePosixPath(process_cgroup).parts:
        fail('missing or unsafe process cgroup path')
    cgroup_mount = None
    for line in open('/proc/self/mountinfo', encoding='ascii'):
        fields, tail = line.rstrip('\\n').split(' - ', 1)
        left = fields.split()
        mountpoint = left[4].replace('\\040', ' ')
        filesystem = tail.split()[0]
        mount_root = left[3].replace('\\040', ' ')
        if mountpoint == '/sys/fs/cgroup' and filesystem == 'cgroup2':
            cgroup_mount = (pathlib.Path(mountpoint), mount_root)
            break
    if cgroup_mount is None:
        fail('cgroup2 mount not visible')
    mountpoint, mount_root = cgroup_mount
    if mount_root == process_cgroup:
        cgroup = mountpoint
    elif process_cgroup.startswith(mount_root.rstrip('/') + '/'):
        cgroup = mountpoint / process_cgroup[len(mount_root.rstrip('/')) + 1:]
    else:
        fail('process cgroup not covered by visible cgroup mount')
    cgroup = cgroup.resolve()
    if mountpoint.resolve() not in cgroup.parents and cgroup != mountpoint.resolve():
        fail('cgroup path escaped its mount')
    read = lambda name: (cgroup / name).read_text(encoding='ascii').strip()
    memory = int(read('memory.max'))
    swap = int(read('memory.swap.max'))
    tasks = int(read('pids.max'))
    quota_text, period_text = read('cpu.max').split()
    quota, period = int(quota_text), int(period_text)
    oom_group = read('memory.oom.group')
    stat = os.statvfs('/tmp')
    capacity = stat.f_blocks * stat.f_frsize
    mount_types = []
    for line in open('/proc/self/mountinfo', encoding='ascii'):
        fields, tail = line.rstrip('\n').split(' - ', 1)
        mountpoint = fields.split()[4].replace('\\040', ' ')
        if mountpoint == '/tmp':
            mount_types.append(tail.split()[0])
    if memory <= 0 or memory > config['memory_bytes'] or swap != 0 or \
       tasks <= 0 or tasks > config['tasks'] or quota <= 0 or period <= 0 or quota > period or \
       oom_group != '1' or mount_types != ['tmpfs'] or capacity <= 0 or capacity > config['tmpfs_bytes'] or \
       stat.f_files <= 0 or stat.f_files > config['tmpfs_inodes']:
        fail('limits or tmpfs mismatch: memory=%s swap=%s tasks=%s cpu=%s/%s oom=%s mount=%s bytes=%s inodes=%s' % (memory, swap, tasks, quota, period, oom_group, mount_types, capacity, stat.f_files))
except SystemExit:
    raise
except Exception as error:
    fail(type(error).__name__ + ': ' + str(error))
# User-manager variables are not part of the provider contract. Keep only the
# fixed runtime environment after admission and before either Unblob exec or
# post-gate site initialization.
run_id = os.environ.get('REA_PROCESS_RUN_ID', '')
os.environ.clear()
os.environ.update({'PATH': '/usr/local/bin:/usr/bin:/bin', 'TMPDIR': '/tmp', 'REA_PROCESS_RUN_ID': run_id})
arguments = sys.argv[3:]
if '--extract-dir' not in arguments or '--skip-extraction' in arguments:
    os.execv(sys.argv[2], [sys.argv[2], *arguments])

# Extraction mode runs only after the resource gate, then emits a bounded,
# authenticated file stream. All producer bytes stay on the capped service tmpfs.
# Restore the runtime's global site-packages only after the manager boundary and
# gate are active; -I -S prevented .pth/sitecustomize execution during bootstrap.
import site
site.main()
import contextlib, hashlib, io, json, runpy, struct, traceback
MAX_TEXT = 8 * 1024 * 1024
MAX_ENTRIES = config.get('max_entries', 512)
MAX_BYTES = config.get('max_bytes', 64 * 1024 * 1024)
class CappedText(io.TextIOBase):
    def __init__(self): self.parts, self.size, self.observed, self.truncated = [], 0, 0, False
    def write(self, text):
        encoded = text.encode('utf-8', 'replace')
        self.observed += len(encoded)
        remaining = MAX_TEXT - self.size
        if remaining > 0:
            kept = encoded[:remaining].decode('utf-8', 'ignore')
            self.parts.append(kept); self.size += len(kept.encode('utf-8'))
        if len(encoded) > remaining: self.truncated = True
        return len(text)
    def getvalue(self): return ''.join(self.parts).encode('utf-8', 'replace')
def read_bounded(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not __import__('stat').S_ISREG(info.st_mode) or info.st_size > limit:
            raise RuntimeError('report is not a bounded regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream: return stream.read(limit + 1)
    finally: os.close(fd)
def open_directory(root, relative=''):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        components = [part for part in root.split('/') if part] + [part for part in relative.split('/') if part]
        for component in components:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = next_fd
        return fd
    except BaseException:
        os.close(fd); raise
def open_regular(root, relative):
    parts = relative.split('/')
    parent = open_directory(root, '/'.join(parts[:-1]))
    try: return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally: os.close(parent)
def walk(root):
    result = []
    pending = ['']
    while pending:
        prefix = pending.pop()
        directory_fd = open_directory(root, prefix)
        try:
            with os.scandir(directory_fd) as entries:
                ordered = sorted(entries, key=lambda item: os.fsencode(item.name), reverse=True)
                children = []
                for entry in ordered:
                    name = entry.name
                    relative = name if not prefix else prefix + '/' + name
                    relative.encode('utf-8', 'strict')
                    info = entry.stat(follow_symlinks=False)
                    if entry.is_symlink():
                        result.append((2, relative, 0, os.readlink(name, dir_fd=directory_fd)))
                    elif entry.is_dir(follow_symlinks=False):
                        result.append((0, relative, 0, None)); children.append(relative)
                    elif entry.is_file(follow_symlinks=False):
                        if info.st_size < 0: raise RuntimeError('negative extraction file size')
                        result.append((1, relative, info.st_size, None))
                    else:
                        result.append((3, relative, 0, None))
                    if len(result) > MAX_ENTRIES: raise RuntimeError('caller staging entry budget exceeded')
                pending.extend(children)
        finally: os.close(directory_fd)
    return result
def digest_file(root, relative, expected_size):
    fd = open_regular(root, relative)
    digest = hashlib.sha256(); seen = 0
    try:
        before = os.fstat(fd)
        if not __import__('stat').S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise RuntimeError('extracted file identity or size changed')
        while True:
            block = os.read(fd, 65536)
            if not block: break
            seen += len(block); digest.update(block)
        after = os.fstat(fd)
        if seen != expected_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError('extracted file changed during framing')
        return digest.digest()
    finally: os.close(fd)
def emit_frame(exit_code, stdout, stderr, report, auxiliary, entries):
    files = [entry for entry in entries if entry[0] == 1]
    total = sum(entry[2] for entry in files)
    if total > MAX_BYTES: raise RuntimeError('service output byte budget exceeded')
    out = sys.stdout.buffer
    out.write(b'REAUB1\0\0' + struct.pack('>iIIIIIQ', exit_code, len(stdout), len(stderr), len(report), len(auxiliary), len(entries), total))
    out.write(stdout); out.write(stderr); out.write(report); out.write(auxiliary)
    for kind, relative, size, target in entries:
        path_bytes = relative.encode('utf-8', 'strict')
        target_bytes = b'' if target is None else target.encode('utf-8', 'strict')
        if len(path_bytes) > 65535 or len(target_bytes) > 65535: raise RuntimeError('frame path too long')
        digest = digest_file(extract_root, relative, size) if kind == 1 else bytes(32)
        out.write(struct.pack('>BHHQ', kind, len(path_bytes), len(target_bytes), size) + digest + path_bytes + target_bytes)
        if kind == 1:
            fd = open_regular(extract_root, relative)
            try:
                sent = 0
                while True:
                    block = os.read(fd, 65536)
                    if not block: break
                    sent += len(block); out.write(block)
                if sent != size: raise RuntimeError('extracted file changed while framing')
            finally: os.close(fd)
    out.flush()
argv = [sys.argv[2], *arguments]
extract_root = '/tmp/rea-extracted'
for index, value in enumerate(argv[:-1]):
    if value == '--extract-dir': extract_root = argv[index + 1]
stdout, stderr = CappedText(), CappedText()
code = 0
import atexit
def silence_unblob_shutdown_output():
    fd = os.open('/dev/null', os.O_WRONLY | os.O_CLOEXEC)
    try: os.dup2(fd, 1); os.dup2(fd, 2)
    finally: os.close(fd)
saved_stdout, saved_stderr = os.dup(1), os.dup(2)
null_fd = os.open('/dev/null', os.O_WRONLY | os.O_CLOEXEC)
try:
    os.dup2(null_fd, 1); os.dup2(null_fd, 2)
    os.makedirs(extract_root, mode=0o700, exist_ok=True)
    sys.argv = argv
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try: runpy.run_path(sys.argv[0], run_name='__main__')
        except SystemExit as result: code = result.code if isinstance(result.code, int) else (0 if result.code is None else 1)
    atexit.register(silence_unblob_shutdown_output)
    report_path = None
    for index, value in enumerate(argv[:-1]):
        if value == '--report': report_path = argv[index + 1]
    if report_path is None: raise RuntimeError('extraction report path is required')
    report = read_bounded(report_path, MAX_TEXT)
    if len(report) > MAX_TEXT: raise RuntimeError('report byte budget exceeded')
    entries = walk(extract_root)
    auxiliary = json.dumps({'stdout_observed_bytes': stdout.observed, 'stderr_observed_bytes': stderr.observed, 'stdout_truncated': stdout.truncated, 'stderr_truncated': stderr.truncated}, separators=(',', ':')).encode('ascii')
    os.dup2(saved_stdout, 1); os.dup2(saved_stderr, 2)
    emit_frame(code, stdout.getvalue(), stderr.getvalue(), report, auxiliary, entries)
except BaseException as error:
    os.dup2(saved_stdout, 1); os.dup2(saved_stderr, 2)
    # No untrusted traceback or path is sent. A valid empty frame lets the host
    # fail closed while preserving the bounded diagnostic and exact service exit.
    message = ('Unblob extraction framing failed: ' + type(error).__name__).encode('utf-8')
    try: emit_frame(125, b'', message[:MAX_TEXT], b'{}', b'{}', [])
    except BaseException: pass
    raise SystemExit(125)
finally:
    os.close(null_fd); os.close(saved_stdout); os.close(saved_stderr)
`;

export interface UnblobSystemdProfile {
  readonly rootDirectory: string;
  readonly executable: string;
  readonly pythonExecutable?: string;
  readonly inputPath?: string;
  readonly extractionBudget?: {
    readonly bytes: number;
    readonly entries: number;
  };
}

export interface UnblobSystemdInvocation {
  readonly unit: string;
  readonly arguments: readonly string[];
  readonly guestArguments: readonly string[];
}

/** Construct a fixed-policy transient user service; no caller text becomes a unit property. */
export async function buildUnblobSystemdInvocation(
  profile: UnblobSystemdProfile,
  args: readonly string[],
  workspace: string,
  runId = `rea-firmware-${randomUUID()}`,
  inheritedEnvironmentNames: readonly string[] = [],
): Promise<UnblobSystemdInvocation> {
  const rootDirectory = await realpath(profile.rootDirectory);
  const executable = await realpath(profile.executable);
  const executableRelative = relative(rootDirectory, executable);
  const pythonPath = await realpath(
    profile.pythonExecutable ??
      join(rootDirectory, "usr", "local", "bin", "python3"),
  );
  const pythonRelative = relative(rootDirectory, pythonPath);
  if (
    !isAbsolute(profile.rootDirectory) ||
    executableRelative === "" ||
    executableRelative === ".." ||
    executableRelative.startsWith(`..${sep}`) ||
    isAbsolute(executableRelative)
  )
    throw new Error(
      "Unblob executable must resolve inside its admitted runtime root",
    );
  if (
    pythonRelative === "" ||
    pythonRelative === ".." ||
    pythonRelative.startsWith(`..${sep}`) ||
    isAbsolute(pythonRelative)
  )
    throw new Error(
      "Unblob Python interpreter must resolve inside its admitted runtime root",
    );
  const runIdMatch = runIdPattern.exec(runId);
  if (runIdMatch === null)
    throw new Error(
      "Unblob systemd unit requires an REA-generated run identity",
    );
  const uniqueEnvironmentNames = [...new Set(inheritedEnvironmentNames)];
  if (
    uniqueEnvironmentNames.length > 256 ||
    uniqueEnvironmentNames.some(
      (name) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name),
    ) ||
    uniqueEnvironmentNames.reduce((bytes, name) => bytes + name.length, 0) >
      32 * 1024
  )
    throw new Error(
      "User-systemd manager environment exceeds its bounded property profile",
    );

  const root = resolve(workspace);
  const tmpfsBytes = Math.min(
    profile.extractionBudget === undefined
      ? FIRMWARE_LIMITS.extractionBytes
      : Math.max(
          FIRMWARE_LIMITS.extractionMinimumBytes,
          profile.extractionBudget.bytes +
            FIRMWARE_LIMITS.extractionTemporaryBytes,
        ),
    FIRMWARE_LIMITS.extractionBytes,
  );
  const guestArgs = [...args];
  const bindings: string[] = [];
  const outputArguments = guestArgs.reduce<number[]>(
    (indices, argument, index) =>
      argument === "--report" ||
      argument === "--log" ||
      argument === "--build-handlers-doc"
        ? [...indices, index]
        : indices,
    [],
  );
  if (profile.inputPath !== undefined) {
    const input = await realpath(profile.inputPath);
    const inputRelative = relative(root, input);
    if (
      inputRelative === ".." ||
      inputRelative.startsWith(`..${sep}`) ||
      isAbsolute(inputRelative)
    )
      throw new Error(
        "Unblob input must be owned by the private firmware workspace",
      );
    bindings.push(`--property=BindReadOnlyPaths=${input}:/tmp/rea-input`);
    for (let index = 0; index < guestArgs.length; index += 1)
      if (guestArgs[index] === profile.inputPath || guestArgs[index] === input)
        guestArgs[index] = "/tmp/rea-input";
  }

  for (const index of outputArguments) {
    const arg = guestArgs[index];
    const hostPath = guestArgs[index + 1];
    if (hostPath === undefined || !isAbsolute(hostPath))
      throw new Error(
        `Unblob ${arg} requires an absolute workspace output path`,
      );
    const resolvedPath = resolve(hostPath);
    const outputRelative = relative(root, resolvedPath);
    if (
      outputRelative === ".." ||
      outputRelative.startsWith(`..${sep}`) ||
      isAbsolute(outputRelative)
    )
      throw new Error(`Unblob ${arg} path escapes its private workspace`);
    const outputName = basename(resolvedPath);
    if (outputName === "." || outputName === ".." || outputName.length === 0)
      throw new Error(
        `Unblob ${arg} path must name a file inside its private workspace`,
      );
    const guestPath = `/tmp/rea-${outputName}`;
    if (arg === "--log") {
      guestArgs[index + 1] = guestPath;
      continue;
    }
    const hostFile = await open(
      resolvedPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
    await hostFile.close();
    bindings.push(`--property=BindPaths=${resolvedPath}:${guestPath}`);
    guestArgs[index + 1] = guestPath;
  }

  for (let index = 0; index < guestArgs.length; index += 1) {
    if (guestArgs[index] !== "--extract-dir") continue;
    const extractionPath = guestArgs[index + 1];
    if (extractionPath === undefined || !isAbsolute(extractionPath))
      throw new Error("Unblob --extract-dir omitted its path");
    const extractionRelative = relative(root, resolve(extractionPath));
    if (
      extractionRelative === ".." ||
      extractionRelative.startsWith(`..${sep}`) ||
      isAbsolute(extractionRelative)
    )
      throw new Error(
        "Unblob extraction staging path escapes its private workspace",
      );
    guestArgs[index + 1] = "/tmp/rea-extracted";
  }

  const gateHostPath = join(root, `rea-unblob-gate-${runIdMatch[1]}.py`);
  await writeFile(gateHostPath, cgroupGate, { flag: "wx", mode: 0o400 });
  bindings.push(
    `--property=BindReadOnlyPaths=${gateHostPath}:/tmp/rea-unblob-gate.py`,
  );
  const unit = `rea-unblob-${runIdMatch[1]}`;
  const alwaysUnsetEnvironmentNames = [
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
    "LD_TRACE_PRELINKING",
    "LD_USE_LOAD_BIAS",
    "LD_VERBOSE",
    "LD_WARN",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "LOCPATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "PYTHONINSPECT",
  ];
  const invocationArguments = [
    "--user",
    "--quiet",
    "--wait",
    "--collect",
    "--pipe",
    `--unit=${unit}.service`,
    `--property=RootDirectory=${rootDirectory}`,
    "--property=WorkingDirectory=/tmp",
    "--property=PrivateNetwork=yes",
    "--property=PrivateDevices=yes",
    "--property=PrivatePIDs=yes",
    "--property=NoNewPrivileges=yes",
    "--property=ProtectSystem=strict",
    "--property=ProtectHome=tmpfs",
    "--property=ProtectControlGroups=yes",
    "--property=RestrictSUIDSGID=yes",
    "--property=LockPersonality=yes",
    `--property=MemoryMax=${SERVICE_LIMITS.memoryMax}`,
    "--property=MemorySwapMax=0",
    `--property=TasksMax=${SERVICE_LIMITS.tasksMax}`,
    `--property=CPUQuota=${SERVICE_LIMITS.cpuQuota}`,
    `--property=RuntimeMaxSec=${SERVICE_LIMITS.runtimeMax}`,
    "--property=TimeoutStopSec=2s",
    "--property=SendSIGKILL=yes",
    `--property=LimitFSIZE=${SERVICE_LIMITS.fileSizeMax}`,
    "--property=KillMode=control-group",
    "--property=OOMPolicy=kill",
    "--property=UMask=0077",
    `--property=TemporaryFileSystem=/tmp:mode=1777,size=${tmpfsBytes},nr_inodes=${FIRMWARE_LIMITS.extractionInodes}`,
    ...[
      ...new Set([...uniqueEnvironmentNames, ...alwaysUnsetEnvironmentNames]),
    ].map((name) => `--property=UnsetEnvironment=${name}`),
    "--property=Environment=PATH=/usr/local/bin:/usr/bin:/bin",
    "--property=Environment=TMPDIR=/tmp",
    `--property=Environment=REA_PROCESS_RUN_ID=${runId}`,
    ...bindings,
    "--",
    `/${pythonRelative.split(sep).join("/")}`,
    "-I",
    "-S",
    "/tmp/rea-unblob-gate.py",
    JSON.stringify({
      host_pid_namespace: await readlink("/proc/self/ns/pid"),
      memory_bytes: SERVICE_LIMITS.memoryMax,
      tasks: SERVICE_LIMITS.tasksMax,
      tmpfs_bytes: tmpfsBytes,
      tmpfs_inodes: FIRMWARE_LIMITS.extractionInodes,
      ...(profile.extractionBudget === undefined
        ? {}
        : {
            max_bytes: Math.min(
              profile.extractionBudget.bytes,
              FIRMWARE_LIMITS.extractionBytes,
            ),
            max_entries: Math.min(
              profile.extractionBudget.entries,
              FIRMWARE_LIMITS.extractionEntries,
            ),
          }),
    }),
    `/${executableRelative.split(sep).join("/")}`,
    ...guestArgs,
  ];
  return { unit, arguments: invocationArguments, guestArguments: guestArgs };
}

/** Spawn and retain the exact unit identity as part of process cleanup ownership. */
export async function spawnUnblobSystemdProcess(
  profile: UnblobSystemdProfile,
  args: readonly string[],
  options: OwnedProviderProcessSpawnOptions,
): Promise<SpawnedOwnedProviderProcess> {
  const uid = process.getuid?.();
  if (uid === undefined)
    throw new Error("Linux uid is unavailable for user-systemd Unblob");
  const inheritedNames = await readSystemdEnvironmentNames(uid);
  const invocation = await buildUnblobSystemdInvocation(
    profile,
    args,
    options.cwd ?? "",
    options.runId,
    inheritedNames,
  );
  options.signal?.throwIfAborted();
  const spawned = await spawnOwnedProviderProcess({
    ...options,
    command: "/usr/bin/systemd-run",
    arguments: [...invocation.arguments],
    expectedCommand: "/usr/bin/systemd-run",
  });
  return {
    ...spawned,
    cleanup: async () => {
      const processCleanup = await cleanupOwnedProcessGroup(spawned.ownership);
      if (!processCleanup.cleaned) return processCleanup;
      return stopAndVerifyUnit(invocation.unit, processCleanup);
    },
  };
}

async function stopAndVerifyUnit(
  unit: string,
  processCleanup: Extract<ProcessCleanupResult, { cleaned: true }>,
): Promise<ProcessCleanupResult> {
  try {
    let stopFailure: unknown;
    try {
      await execFileAsync("/usr/bin/systemctl", [
        "--user",
        "stop",
        `${unit}.service`,
      ]);
    } catch (cause: unknown) {
      stopFailure = cause;
    }
    let stdout: string;
    try {
      stdout = (
        await execFileAsync("/usr/bin/systemctl", [
          "--user",
          "show",
          `${unit}.service`,
          "--property=LoadState",
          "--property=ActiveState",
          "--property=ControlGroup",
          "--property=MemoryMax",
          "--property=TasksMax",
          "--property=RootDirectory",
          "--property=PrivateNetwork",
          "--property=PrivateDevices",
          "--property=ProtectSystem",
          "--property=ProtectHome",
          "--property=NoNewPrivileges",
          "--property=LimitFSIZE",
          "--property=TimeoutStopUSec",
          "--property=SendSIGKILL",
        ])
      ).stdout;
    } catch (cause: unknown) {
      if (stopFailure === undefined) throw cause;
      await assertUnitCgroupAbsent(unit);
      return processCleanup;
    }
    const properties = new Map(
      stdout
        .trim()
        .split("\n")
        .map((line) => {
          const separator = line.indexOf("=");
          return [line.slice(0, separator), line.slice(separator + 1)] as const;
        }),
    );
    if (properties.get("LoadState") === "not-found") {
      await assertUnitCgroupAbsent(unit);
      return processCleanup;
    }
    if (
      properties.get("ActiveState") !== "inactive" ||
      properties.get("ControlGroup") !== "" ||
      properties.get("MemoryMax") !== String(SERVICE_LIMITS.memoryMax) ||
      properties.get("TasksMax") !== String(SERVICE_LIMITS.tasksMax) ||
      properties.get("RootDirectory") === "" ||
      properties.get("PrivateNetwork") !== "yes" ||
      properties.get("PrivateDevices") !== "yes" ||
      properties.get("ProtectSystem") !== "strict" ||
      properties.get("ProtectHome") !== "tmpfs" ||
      properties.get("NoNewPrivileges") !== "yes" ||
      properties.get("LimitFSIZE") !== String(SERVICE_LIMITS.fileSizeMax) ||
      properties.get("TimeoutStopUSec") !== "2s" ||
      properties.get("SendSIGKILL") !== "yes"
    )
      return {
        cleaned: false,
        reason: `Unblob systemd unit lifecycle or enforced profile could not be verified: ${[...properties].map(([key, value]) => `${key}=${value}`).join(",")}`,
      };
    return processCleanup;
  } catch (cause: unknown) {
    return {
      cleaned: false,
      reason: `Could not stop and verify exact Unblob systemd unit ${unit}: ${cause instanceof Error ? cause.message : String(cause)}`,
    };
  }
}

async function assertUnitCgroupAbsent(unit: string): Promise<void> {
  const { stdout } = await execFileAsync("/usr/bin/systemctl", [
    "--user",
    "show",
    "app.slice",
    "--property=ControlGroup",
    "--value",
  ]);
  const appCgroup = stdout.trim();
  if (!appCgroup.startsWith("/"))
    throw new Error("User systemd app.slice cgroup could not be verified");
  const exactCgroup = join("/sys/fs/cgroup", appCgroup, `${unit}.service`);
  try {
    await access(exactCgroup);
  } catch (cause: unknown) {
    if (cause instanceof Error && "code" in cause && cause.code === "ENOENT")
      return;
    throw cause;
  }
  throw new Error(`Exact Unblob cgroup still exists: ${exactCgroup}`);
}

async function readSystemdEnvironmentNames(uid: number): Promise<string[]> {
  const runtimeDirectory = `/run/user/${uid}`;
  const { stdout } = await execFileAsync(
    "/usr/bin/systemctl",
    ["--user", "show-environment"],
    {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      env: {
        PATH: "/usr/bin:/bin",
        XDG_RUNTIME_DIR: runtimeDirectory,
        DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtimeDirectory}/bus`,
      },
    },
  );
  const names = new Set<string>();
  for (const line of stdout.split(/\r?\n/u)) {
    if (line.length === 0) continue;
    const separator = line.indexOf("=");
    const name = separator < 0 ? "" : line.slice(0, separator);
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name))
      throw new Error(
        "User-systemd environment contains an invalid variable name",
      );
    names.add(name);
  }
  return [...names].sort();
}
