import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import {
  access,
  lstat,
  opendir,
  open,
  realpath,
  readlink,
  writeFile,
} from "node:fs/promises";
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
const SETUPTOOLS_STARTUP_HOOK_SHA256 =
  "2638ce9e2500e572a5e0de7faed6661eb569d1b696fcba07b0dd223da5f5d224";
const MAX_AUDITED_RUNTIME_NODES = 100_000;
const MAX_STARTUP_SCAN_ENTRIES = 8_192;
const MAX_STARTUP_METADATA_BYTES = 1024 * 1024;

const isMissingPath = (cause: unknown): boolean =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  cause.code === "ENOENT";

async function* readStartupDirectory(
  path: string,
  count: { value: number },
): AsyncGenerator<import("node:fs").Dirent<string>> {
  const directory = await opendir(path);
  for await (const entry of directory) {
    count.value += 1;
    if (count.value > MAX_STARTUP_SCAN_ENTRIES)
      throw new Error("Unblob startup audit exceeds its bounded entry scan");
    yield entry;
  }
}

async function readBoundedStartupMetadata(path: string): Promise<Buffer> {
  const file = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const identity = await file.stat();
    if (!identity.isFile() || identity.size > MAX_STARTUP_METADATA_BYTES)
      throw new Error(
        `Unblob startup metadata exceeds ${MAX_STARTUP_METADATA_BYTES} bytes`,
      );
    const buffer = Buffer.alloc(MAX_STARTUP_METADATA_BYTES + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const result = await file.read(
        buffer,
        bytesRead,
        buffer.length - bytesRead,
        bytesRead,
      );
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    if (bytesRead > MAX_STARTUP_METADATA_BYTES)
      throw new Error(
        `Unblob startup metadata exceeds ${MAX_STARTUP_METADATA_BYTES} bytes`,
      );
    return buffer.subarray(0, bytesRead);
  } finally {
    await file.close();
  }
}

export async function auditUnblobRuntimeStartupFiles(
  root: string,
): Promise<void> {
  const localSiteDirectories: string[] = [];
  const systemSiteDirectories: string[] = [];
  const startupDirectories: string[] = [];
  const scannedEntries = { value: 0 };
  for (const libraryRoot of [
    join(root, "usr/local/lib"),
    join(root, "usr/lib"),
  ]) {
    try {
      for await (const candidate of readStartupDirectory(
        libraryRoot,
        scannedEntries,
      )) {
        if (
          !candidate.isDirectory() ||
          !/^python\d+(?:\.\d+)?$/u.test(candidate.name)
        )
          continue;
        startupDirectories.push(join(libraryRoot, candidate.name));
        for (const leaf of ["site-packages", "dist-packages"]) {
          const path = join(libraryRoot, candidate.name, leaf);
          try {
            const identity = await lstat(path);
            if (identity.isSymbolicLink())
              throw new Error(
                "Unblob runtime site-package directory is a symbolic link",
              );
            if (identity.isDirectory()) {
              if (libraryRoot.includes("/usr/local/lib"))
                localSiteDirectories.push(path);
              else systemSiteDirectories.push(path);
              startupDirectories.push(path);
            }
          } catch (cause) {
            if (!isMissingPath(cause)) throw cause;
          }
        }
      }
    } catch (cause) {
      if (isMissingPath(cause)) continue;
      throw cause;
    }
  }
  const siteDirectories =
    localSiteDirectories.length > 0
      ? localSiteDirectories
      : systemSiteDirectories;
  for (const startupDirectory of startupDirectories) {
    for await (const entry of readStartupDirectory(
      startupDirectory,
      scannedEntries,
    )) {
      const name = entry.name;
      if (
        ["sitecustomize", "usercustomize"].some(
          (hook) => name === hook || name.startsWith(`${hook}.`),
        )
      )
        throw new Error(
          `Unblob runtime contains a prohibited Python startup hook: ${name}`,
        );
    }
  }
  for (const siteDirectory of siteDirectories) {
    for await (const item of readStartupDirectory(
      siteDirectory,
      scannedEntries,
    )) {
      if (item.name.endsWith(".pth")) {
        const path = join(siteDirectory, item.name);
        if (
          !item.isFile() ||
          createHash("sha256")
            .update(await readBoundedStartupMetadata(path))
            .digest("hex") !== SETUPTOOLS_STARTUP_HOOK_SHA256
        )
          throw new Error(
            `Unblob runtime contains an unaudited Python startup hook: ${item.name}`,
          );
      }
      if (!item.name.endsWith(".dist-info") && !item.name.endsWith(".egg-info"))
        continue;
      if (!item.isDirectory())
        throw new Error(
          `Unblob runtime distribution metadata has an unsafe identity: ${item.name}`,
        );
      const entryPointsPath = join(
        siteDirectory,
        item.name,
        "entry_points.txt",
      );
      let entryPoints: string;
      try {
        const identity = await lstat(entryPointsPath);
        if (!identity.isFile())
          throw new Error(
            "Unblob runtime entry point metadata is not a regular file",
          );
        entryPoints = (
          await readBoundedStartupMetadata(entryPointsPath)
        ).toString("utf8");
      } catch (cause) {
        if (isMissingPath(cause)) continue;
        throw cause;
      }
      let group: string | undefined;
      for (const rawLine of entryPoints.split(/\r?\n/u)) {
        const line = rawLine.trim();
        if (line.length === 0 || line.startsWith("#") || line.startsWith(";"))
          continue;
        const heading = /^\[([^\]]+)\]$/u.exec(line);
        if (heading !== null) {
          group = heading[1]?.trim().toLowerCase();
          continue;
        }
        if (group === "unblob_v1")
          throw new Error(
            "Unblob runtime contains a caller-installed unblob_v1 plugin entrypoint",
          );
      }
    }
  }
}

const immutableRuntimeAdmissionCache = new Set<string>();

export function assertUnblobRuntimeAdmissionQueueBound(
  visitedCount: number,
  pendingCount: number,
  additions = 1,
): void {
  if (visitedCount + pendingCount + additions > MAX_AUDITED_RUNTIME_NODES)
    throw new Error("Unblob Python runtime exceeds the bounded admission scan");
}

export function assertUnblobRuntimeNodeBudget(
  scannedNodes: number,
  additions = 1,
): number {
  const total = scannedNodes + additions;
  if (total > MAX_AUDITED_RUNTIME_NODES)
    throw new Error("Unblob Python runtime exceeds the bounded admission scan");
  return total;
}

async function auditImmutableRuntimePath(
  root: string,
  path: string,
  seen: Set<string>,
  pending: string[],
): Promise<void> {
  const canonicalRoot = resolve(root);
  const absolute = resolve(path);
  const relativePath = relative(canonicalRoot, absolute);
  if (
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    isAbsolute(relativePath)
  )
    throw new Error("Unblob Python runtime path escapes its admitted root");

  let current = canonicalRoot;
  const components = relativePath === "" ? [] : relativePath.split(sep);
  const rootComponents = canonicalRoot.split(sep).filter(Boolean);
  current = sep;
  for (const component of [...rootComponents, ...components]) {
    if (component !== "") current = join(current, component);
    if (seen.has(current)) continue;
    let identity;
    try {
      identity = await lstat(current);
    } catch {
      throw new Error("Unblob Python runtime contains an unverifiable path");
    }
    if (
      identity.uid === process.getuid?.() ||
      identity.uid === process.geteuid?.() ||
      (await access(current, constants.W_OK)
        .then(() => true)
        .catch(() => false))
    )
      throw new Error("Unblob Python runtime is mutable or unverifiable");
    assertUnblobRuntimeAdmissionQueueBound(seen.size, pending.length);
    seen.add(current);
    if (identity.isSymbolicLink()) {
      let target: string;
      try {
        target = await realpath(current);
      } catch {
        throw new Error(
          "Unblob Python runtime contains an unverifiable symlink",
        );
      }
      const targetRelative = relative(canonicalRoot, target);
      if (
        targetRelative === ".." ||
        targetRelative.startsWith(`..${sep}`) ||
        isAbsolute(targetRelative)
      )
        throw new Error(
          "Unblob Python runtime symlink escapes its admitted root",
        );
      assertUnblobRuntimeAdmissionQueueBound(seen.size, pending.length);
      pending.push(target);
    }
  }
  assertUnblobRuntimeAdmissionQueueBound(seen.size, pending.length);
  pending.push(absolute);
}

async function auditImmutableUnblobRuntime(
  root: string,
  executable: string,
  python: string,
): Promise<void> {
  const effectiveUid = process.geteuid?.();
  const realUid = process.getuid?.();
  if (
    effectiveUid === undefined ||
    realUid === undefined ||
    effectiveUid === 0 ||
    realUid !== effectiveUid
  )
    throw new Error("Unblob Python runtime is mutable or unverifiable");
  const cacheKey = `${effectiveUid}:${root}:${executable}:${python}`;
  if (immutableRuntimeAdmissionCache.has(cacheKey)) return;
  const seen = new Set<string>();
  const pending: string[] = [];
  assertUnblobRuntimeAdmissionQueueBound(0, pending.length, 2);
  pending.push(executable, python);
  const libraryRoots = [
    join(root, "usr/lib"),
    join(root, "usr/lib64"),
    join(root, "usr/local/lib"),
    join(root, "usr/local/lib64"),
  ];
  let pythonRootCount = 0;
  let scannedRuntimeNodes = 0;
  for (const libraryRoot of libraryRoots) {
    let directory;
    try {
      directory = await opendir(libraryRoot);
    } catch (cause) {
      if (isMissingPath(cause)) continue;
      throw cause;
    }
    for await (const entry of directory) {
      scannedRuntimeNodes = assertUnblobRuntimeNodeBudget(scannedRuntimeNodes);
      if (/^python\d+(?:\.\d+)?\.zip$/u.test(entry.name)) {
        assertUnblobRuntimeAdmissionQueueBound(seen.size, pending.length);
        pending.push(join(libraryRoot, entry.name));
      }
      if (!entry.isDirectory() || !/^python\d+(?:\.\d+)?$/u.test(entry.name))
        continue;
      pythonRootCount += 1;
      assertUnblobRuntimeAdmissionQueueBound(seen.size, pending.length);
      pending.push(join(libraryRoot, entry.name));
    }
  }
  if (pythonRootCount === 0)
    throw new Error("Unblob Python runtime is mutable or unverifiable");

  while (pending.length > 0) {
    const path = pending.pop();
    if (path === undefined) continue;
    if (seen.has(resolve(path))) continue;
    await auditImmutableRuntimePath(root, path, seen, pending);
    let canonical: string;
    try {
      canonical = await realpath(path);
    } catch {
      throw new Error("Unblob Python runtime contains an unverifiable path");
    }
    const identity = await lstat(canonical);
    if (identity.isDirectory()) {
      let directory;
      try {
        directory = await opendir(canonical);
      } catch {
        throw new Error(
          "Unblob Python runtime contains an unverifiable directory",
        );
      }
      for await (const entry of directory) {
        scannedRuntimeNodes =
          assertUnblobRuntimeNodeBudget(scannedRuntimeNodes);
        assertUnblobRuntimeAdmissionQueueBound(seen.size, pending.length);
        pending.push(join(canonical, entry.name));
      }
    }
    if (seen.size > MAX_AUDITED_RUNTIME_NODES)
      throw new Error(
        "Unblob Python runtime exceeds the bounded admission scan",
      );
  }
  // A successful scan proves this identity cannot mutate any admitted node or
  // parent path. Keep that proof for this process; runtime changes by its
  // trusted owner require restarting REA to establish a fresh admission.
  immutableRuntimeAdmissionCache.add(cacheKey);
}
const cgroupGate = String.raw`import json, os, pathlib, resource, sys
config = json.loads(sys.argv[1])
def fail(reason='policy mismatch'):
    print('Unblob systemd resource boundary verification failed: ' + reason, file=sys.stderr)
    raise SystemExit(125)
def enqueue_bounded(pending, visited_count, candidate):
    if visited_count + len(pending) + 1 > 100000:
        fail('runtime admission scan exceeds its bound')
    pending.append(str(candidate))
def audit_immutable_runtime(paths):
    if os.geteuid() == 0 or os.getuid() != os.geteuid():
        fail('runtime mutability cannot be excluded for this identity')
    root = pathlib.Path('/').resolve()
    visited = set()
    pending = []
    for path in paths:
        enqueue_bounded(pending, len(visited), path)
    while pending:
        candidate = pathlib.Path(os.path.abspath(pending.pop()))
        try:
            lexical = candidate
            lexical.relative_to(root)
            for ancestor in (lexical, *lexical.parents):
                if ancestor in visited:
                    continue
                info = ancestor.lstat()
                writable = os.access(ancestor, os.W_OK, effective_ids=True)
                if info.st_uid in (os.getuid(), os.geteuid()) or writable:
                    fail('runtime lexical path is mutable by the invoking identity')
                if len(visited) + len(pending) + 1 > 100000:
                    fail('runtime admission scan exceeds its bound')
                visited.add(ancestor)
            if candidate.is_symlink():
                link_info = candidate.lstat()
                if link_info.st_uid in (os.getuid(), os.geteuid()) or os.access(candidate, os.W_OK, effective_ids=True):
                    fail('mutable runtime symlink')
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except SystemExit:
            raise
        except Exception:
            fail('unverifiable runtime path or escaping symlink')
        for ancestor in (resolved, *resolved.parents):
            if ancestor in visited:
                continue
            try:
                info = ancestor.lstat()
                writable = os.access(ancestor, os.W_OK, effective_ids=True)
            except Exception:
                fail('unverifiable runtime path')
            if info.st_uid in (os.getuid(), os.geteuid()) or writable:
                fail('runtime path is mutable by the invoking identity')
            if len(visited) + len(pending) + 1 > 100000:
                fail('runtime admission scan exceeds its bound')
            visited.add(ancestor)
        if resolved.is_dir():
            try:
                for child in resolved.iterdir():
                    enqueue_bounded(pending, len(visited), child)
            except Exception:
                fail('unverifiable runtime directory')
try:
    if os.readlink('/proc/self/ns/pid') == config['host_pid_namespace']:
        fail('PrivatePIDs is unavailable or was not applied')
    host_ipc_namespace = config.get('host_ipc_namespace')
    if (not isinstance(host_ipc_namespace, str) or
            not host_ipc_namespace.startswith('ipc:[') or
            not host_ipc_namespace.endswith(']') or
            not host_ipc_namespace[5:-1].isdigit()):
        fail('host IPC namespace identity is unavailable')
    if os.readlink('/proc/self/ns/ipc') == host_ipc_namespace:
        fail('PrivateIPC is unavailable or was not applied')
    file_size_soft, file_size_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    if file_size_soft == resource.RLIM_INFINITY or file_size_hard == resource.RLIM_INFINITY:
        fail('file-size limit is unbounded')
    if file_size_soft > config['file_size_bytes'] or file_size_hard > config['file_size_bytes']:
        fail('file-size limit mismatch: soft=%s hard=%s' % (file_size_soft, file_size_hard))
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
# fixed runtime environment after resource admission and before Python imports.
run_id = os.environ.get('REA_PROCESS_RUN_ID', '')
os.environ.clear()
os.environ.update({'PATH': '/usr/local/bin:/usr/bin:/bin', 'TMPDIR': '/tmp', 'REA_PROCESS_RUN_ID': run_id})
import configparser, hashlib, re, runpy, stat, sysconfig
if re.fullmatch(r'/usr/(?:local/)?bin/python3(?:\.\d+)?', sys.executable) is None:
    fail('Python interpreter is outside the supported system prefixes')
_configured = sysconfig.get_paths()
_runtime_paths = [sys.executable] + list(sys.path) + [_configured[key] for key in ('purelib', 'platlib', 'stdlib', 'platstdlib') if _configured.get(key)]
audit_immutable_runtime(_runtime_paths)
def audit_runtime_startup_files():
    configured = sysconfig.get_paths()
    paths = sorted(set(path for key, path in configured.items() if key in ('purelib', 'platlib')))
    startup_paths = sorted(set(path for key, path in configured.items() if key in ('purelib', 'platlib', 'stdlib', 'platstdlib')))
    if not paths or any(not os.path.isdir(path) for path in paths + startup_paths):
        fail('Python site-package directories are unavailable for admission')
    scanned = [0]
    def bounded_scandir(path):
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    scanned[0] += 1
                    if scanned[0] > 8192:
                        fail('Python startup audit exceeds its bounded entry scan')
                    yield entry
        except SystemExit:
            raise
        except Exception as error:
            fail('unverifiable Python startup directory: ' + type(error).__name__)
    def read_bounded_metadata(path):
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576:
                fail('Python startup metadata exceeds 1048576 bytes or is not regular')
            data = bytearray()
            while len(data) <= 1048576:
                chunk = os.read(fd, min(65536, 1048577 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > 1048576:
                fail('Python startup metadata exceeds 1048576 bytes')
            return data.decode('utf-8')
        except SystemExit:
            raise
        except Exception as error:
            fail('unverifiable Python startup metadata: ' + type(error).__name__)
        finally:
            if fd is not None:
                os.close(fd)
    for startup_path in startup_paths:
        for entry in bounded_scandir(startup_path):
            name = entry.name
            if name in ('sitecustomize', 'usercustomize') or name.startswith(('sitecustomize.', 'usercustomize.')):
                fail('prohibited Python startup hook: ' + name)
    for site_path in paths:
        for item in bounded_scandir(site_path):
            name = item.name
            candidate = pathlib.Path(site_path) / name
            if name.endswith('.pth'):
                if candidate.is_symlink() or not candidate.is_file() or hashlib.sha256(read_bounded_metadata(candidate)).hexdigest() != '2638ce9e2500e572a5e0de7faed6661eb569d1b696fcba07b0dd223da5f5d224':
                    fail('unaudited Python startup hook: ' + name)
            if not name.endswith(('.dist-info', '.egg-info')):
                continue
            if candidate.is_symlink() or not candidate.is_dir():
                fail('unsafe Python distribution metadata identity: ' + name)
            entry_points = candidate / 'entry_points.txt'
            try:
                entry_identity = entry_points.lstat()
            except FileNotFoundError:
                continue
            if entry_identity:
                if stat.S_ISLNK(entry_identity.st_mode) or not stat.S_ISREG(entry_identity.st_mode):
                    fail('unsafe Python entry point metadata identity')
                parser = configparser.ConfigParser(interpolation=None, strict=True)
                try: parser.read_string(read_bounded_metadata(entry_points))
                except SystemExit: raise
                except Exception as error: fail('malformed Python distribution entry point metadata: ' + type(error).__name__)
                if parser.has_section('unblob_v1') and list(parser.items('unblob_v1')):
                    fail('caller-installed unblob_v1 plugin entrypoint is prohibited')
    return paths
site_paths = audit_runtime_startup_files()
# Do not initialize the site module: it executes .pth files and imports
# sitecustomize. The pinned setuptools hook is admitted by digest but disabled.
sys.path.extend(path for path in site_paths if path not in sys.path)
import pluggy
def disable_setuptools_plugin_discovery(self, group='unblob_v1', name=None):
    return 0
pluggy.PluginManager.load_setuptools_entrypoints = disable_setuptools_plugin_discovery
arguments = sys.argv[3:]
argv = [sys.argv[2], *arguments]
sys.argv = argv
if '--extract-dir' not in arguments or '--skip-extraction' in arguments:
    try:
        runpy.run_path(sys.argv[0], run_name='__main__')
    except SystemExit as result:
        code = result.code if isinstance(result.code, int) else (0 if result.code is None else 1)
        raise SystemExit(code)
    raise SystemExit(0)

# Extraction mode runs only after the resource gate, then emits a bounded,
# authenticated file stream. All producer bytes stay on the capped service tmpfs.
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
  if (!/^(?:usr|usr\/local)\/bin\/python3(?:\.\d+)?$/u.test(pythonRelative))
    throw new Error(
      "Unblob Python interpreter must resolve under a supported system prefix",
    );
  await auditImmutableUnblobRuntime(rootDirectory, executable, pythonPath);
  await auditUnblobRuntimeStartupFiles(rootDirectory);
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
    "--property=PrivateIPC=yes",
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
      host_ipc_namespace: await readlink("/proc/self/ns/ipc"),
      file_size_bytes: SERVICE_LIMITS.fileSizeMax,
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
