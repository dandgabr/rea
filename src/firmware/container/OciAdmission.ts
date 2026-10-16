import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { glob, lstat, open, readlink } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { jsonValueValidationIssue } from "../../domain/jsonValue.js";
import { freezeJsonSnapshot } from "../../domain/immutableJson.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { FirmwareFileCleanupError } from "../FirmwareFiles.js";
import { parseLinuxProcessStartTime } from "../../process/ProcessOwnershipObservation.js";
import type { PodmanContainerIdentity } from "./OwnedPodmanContainer.js";
import {
  podmanMountDestination,
  type PodmanCreateSelection,
} from "./PodmanLifecycleCommands.js";
import {
  decodePodmanProfileText,
  observePodmanProfileDirectory,
  observePodmanProfileFile,
  podmanProfileUnavailable,
} from "./PodmanProfileFiles.js";
import {
  parsePodmanMountInfo,
  type PodmanMountEntry,
} from "./PodmanMountInfo.js";
import type {
  PodmanDescriptorIdentity,
  PodmanExistingStoreProfile,
} from "./PodmanStoreProfile.js";
import {
  observePodmanNamespaceMetadata,
  type PodmanMetadataExecutionContext,
} from "./PodmanNamespaceMetadata.js";
import { observePodmanSharedHelper } from "./PodmanSharedHelper.js";

const namespaceTypes = [
  "pid",
  "network",
  "ipc",
  "uts",
  "mount",
  "user",
  "cgroup",
] as const;
const procNamespaces = [
  "pid",
  "net",
  "ipc",
  "uts",
  "mnt",
  "user",
  "cgroup",
] as const;
const maskedPaths = [
  "/proc/acpi",
  "/proc/kcore",
  "/proc/keys",
  "/proc/latency_stats",
  "/proc/sched_debug",
  "/proc/scsi",
  "/proc/timer_list",
  "/proc/timer_stats",
  "/sys/devices/virtual/powercap",
  "/sys/firmware",
  "/sys/fs/selinux",
  "/proc/interrupts",
];
const readonlyPaths = [
  "/proc/asound",
  "/proc/bus",
  "/proc/fs",
  "/proc/irq",
  "/proc/sys",
  "/proc/sysrq-trigger",
];
// Generated x86_64/capabilities-empty default, observed with Podman5.8.7/c593.
// This is a supported runtime-policy identity, not attestation of the installed binary.
const seccompPolicySha256 =
  "a72d56cf20d9616e7121a2e2f2840f08fd69772a71a72896142f5b912389450c";
const canonical = (value: unknown): unknown =>
  Array.isArray(value)
    ? value.map(canonical)
    : value !== null && typeof value === "object"
      ? Object.fromEntries(
          Object.entries(value)
            .sort(([a], [b]) => a.localeCompare(b, "en"))
            .map(([key, child]) => [key, canonical(child)]),
        )
      : value;
const policyDigest = (value: unknown) =>
  createHash("sha256")
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
const same = (a: unknown, b: unknown) =>
  JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const requireFact: (condition: unknown, reason: string) => asserts condition = (
  condition,
  reason,
) => {
  if (!condition) throw podmanProfileUnavailable(reason);
};
const integer = z.number().int().nonnegative().max(0xffffffff);
const mapping = z.strictObject({
  containerID: integer,
  hostID: integer,
  size: integer.positive(),
});
const ociMount = z.strictObject({
  destination: z.string(),
  type: z.string(),
  source: z.string(),
  options: z.array(z.string()),
});
const ociSchema = z.strictObject({
  ociVersion: z.literal("1.2.1"),
  hostname: z.literal("rea-firmware"),
  process: z.strictObject({
    user: z.strictObject({
      uid: integer,
      gid: integer,
      umask: integer.optional(),
      additionalGids: z.array(integer).optional(),
    }),
    args: z.array(z.string()),
    env: z.array(z.string()),
    cwd: z.literal("/rea-work"),
    capabilities: z.strictObject({}),
    rlimits: z
      .array(
        z.strictObject({
          type: z.enum(["RLIMIT_NOFILE", "RLIMIT_NPROC"]),
          hard: z.number().int().positive(),
          soft: z.number().int().positive(),
        }),
      )
      .length(2),
    noNewPrivileges: z.literal(true),
    selinuxLabel: z.string(),
  }),
  root: z.strictObject({ path: z.string(), readonly: z.literal(true) }),
  mounts: z.array(ociMount).max(10_000),
  annotations: z.record(z.string(), z.string()),
  linux: z.strictObject({
    uidMappings: z.array(mapping),
    gidMappings: z.array(mapping),
    resources: z.strictObject({
      pids: z.strictObject({ limit: z.literal(-1) }),
    }),
    cgroupsPath: z.string(),
    namespaces: z
      .array(z.strictObject({ type: z.enum(namespaceTypes) }))
      .length(7),
    seccomp: z.unknown(),
    maskedPaths: z.array(z.string()),
    readonlyPaths: z.array(z.string()),
    mountLabel: z.string(),
  }),
});
/** proc attr files expose a label optionally terminated by one LF or NUL. */
export const parsePodmanSelinuxAttribute = (raw: string) => {
  const value = /[\n\0]$/u.test(raw) ? raw.slice(0, -1) : raw;
  requireFact(
    !/[\s\0]/u.test(value),
    "Actual proc SELinux attribute has an unsupported representation",
  );
  return { raw, value };
};
export interface PodmanPreparedProcess {
  readonly pid: number;
  readonly start_ticks: string;
  readonly namespaces: Readonly<Record<string, string>>;
  readonly current_label: string;
  readonly pending_exec_label: string;
  readonly current_label_raw: string;
  readonly pending_exec_label_raw: string;
  readonly status: string;
  readonly mountinfo: PodmanDescriptorIdentity;
  readonly mounts: readonly PodmanMountEntry[];
}
export interface OwnedPodmanOci {
  readonly metadata: Awaited<ReturnType<typeof observePodmanNamespaceMetadata>>;
  readonly identity: PodmanDescriptorIdentity;
  readonly process: PodmanPreparedProcess;
  readonly configuration: z.infer<typeof ociSchema>;
  readonly bindings: readonly {
    readonly source: string;
    readonly destination: string;
    readonly directory: boolean;
    readonly device: string;
    readonly inode: string;
  }[];
  readonly source_view: {
    readonly pid: number;
    readonly start_ticks: string;
    readonly mount_ns: string;
  };
  readonly source_semantics: "Podman5.8.7/c593/crun1.28/54f16ff; Linux x86_64 rootless native-overlay, default SELinux and generated seccomp";
}
const processFile = async (
  pid: number,
  name: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
  maximum = 64 * 1024,
) => {
  const source = await observePodmanProfileFile(
    `/proc/${pid}/${name}`,
    maximum,
    signal,
    scope,
  );
  return { ...source, text: decodePodmanProfileText(source.bytes) };
};
export const observePodmanProcessGeneration = async (
  pid: number,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
) => {
  const stat = await processFile(pid, "stat", signal, scope);
  const start = parseLinuxProcessStartTime(stat.text);
  requireFact(
    start !== undefined,
    "Owned prepared process start generation is unreadable",
  );
  return { pid, start_ticks: start! };
};
export const observePodmanPreparedProcess = async (
  pid: number,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
): Promise<PodmanPreparedProcess> => {
  requireFact(
    Number.isSafeInteger(pid) && pid > 0,
    "Prepared container requires a positive host PID",
  );
  const before = await processFile(pid, "stat", signal, scope);
  const start = parseLinuxProcessStartTime(before.text);
  requireFact(
    start !== undefined,
    "Prepared process stat does not establish a start generation",
  );
  const namespaces: Record<string, string> = {};
  for (const name of procNamespaces) {
    signal.throwIfAborted();
    namespaces[name] = await readlink(`/proc/${pid}/ns/${name}`);
    requireFact(
      new RegExp(`^${name}:\\[[0-9]+\\]$`, "u").test(namespaces[name]!),
      "Prepared namespace identity is malformed",
    );
  }
  const current = await processFile(pid, "attr/current", signal, scope);
  const pending = await processFile(pid, "attr/exec", signal, scope);
  const status = await processFile(pid, "status", signal, scope);
  const mountinfo = await processFile(
    pid,
    "mountinfo",
    signal,
    scope,
    8 * 1024 * 1024,
  );
  const mounts = parsePodmanMountInfo(mountinfo.text);
  const after = await processFile(pid, "stat", signal, scope);
  requireFact(
    parseLinuxProcessStartTime(after.text) === start,
    "Prepared process generation changed during admission",
  );
  for (const name of procNamespaces)
    requireFact(
      (await readlink(`/proc/${pid}/ns/${name}`)) === namespaces[name],
      "Prepared namespace generation changed during admission",
    );
  // crun sets attr/exec before its FIFO. NNP/seccomp are applied after FIFO when NNP=true.
  return {
    pid,
    start_ticks: start!,
    namespaces,
    current_label: parsePodmanSelinuxAttribute(current.text).value,
    pending_exec_label: parsePodmanSelinuxAttribute(pending.text).value,
    current_label_raw: current.text,
    pending_exec_label_raw: pending.text,
    status: status.text,
    mountinfo: mountinfo.identity,
    mounts,
  };
};
const nativeMappings = async (
  pid: number,
  name: "uid_map" | "gid_map",
  selected: number,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
) => {
  const observed = await processFile(pid, name, signal, scope);
  const lines = observed.text
    .trim()
    .split("\n")
    .map((line) => line.trim().split(/\s+/u).map(Number));
  requireFact(
    lines.length === 2 &&
      lines.every(
        (line) => line.length === 3 && line.every(Number.isSafeInteger),
      ) &&
      lines[0]![0] === 0 &&
      lines[0]![1] === selected &&
      lines[0]![2] === 1 &&
      lines[1]![0] === 1 &&
      lines[1]![2]! > selected,
    "Unsupported shared-helper subordinate-ID mapping",
  );
  return [
    { containerID: 0, hostID: 1, size: selected },
    { containerID: selected, hostID: 0, size: 1 },
    {
      containerID: selected + 1,
      hostID: selected + 1,
      size: lines[1]![2]! - selected,
    },
  ];
};
const defaults = async (signal: AbortSignal) => {
  const thermal: string[] = [];
  for await (const path of glob(
    "/sys/devices/system/cpu/cpu*/thermal_throttle",
  )) {
    signal.throwIfAborted();
    thermal.push(path);
    requireFact(
      thermal.length <= 4096,
      "Host thermal-mask projection exceeds its 4096-path admission budget",
    );
  }
  // c593 common/config/default.go getMaskedPaths; libpod/container_internal_linux.go addMaskedPaths appends powercap again.
  return [...maskedPaths, ...thermal.sort(), "/sys/devices/virtual/powercap"];
};
const generatedMounts = (
  identity: PodmanContainerIdentity,
  selection: PodmanCreateSelection,
  store: PodmanExistingStoreProfile,
) => {
  requireFact(
    identity.static_dir !== null && identity.static_dir !== "",
    "Initialized OCI requires its observed exact userdata directory",
  );
  const bindOptions = ["bind", "rprivate", "ro", "nosuid", "noexec", "nodev"];
  return [
    ...selection.mounts.map((mount) => ({
      destination: podmanMountDestination(mount.role),
      type: "bind",
      source: mount.source,
      options: [
        mount.role === "work" ? "rw" : "ro",
        "nosuid",
        "nodev",
        "rprivate",
        "rbind",
      ],
    })),
    {
      destination: "/proc",
      type: "proc",
      source: "proc",
      options: ["nosuid", "noexec", "nodev"],
    },
    {
      destination: "/dev",
      type: "tmpfs",
      source: "tmpfs",
      options: ["nosuid", "strictatime", "mode=755", "size=65536k", "ro"],
    },
    {
      destination: "/sys",
      type: "sysfs",
      source: "sysfs",
      options: ["nosuid", "noexec", "nodev", "ro"],
    },
    {
      destination: "/dev/pts",
      type: "devpts",
      source: "devpts",
      options: [
        "nosuid",
        "noexec",
        "newinstance",
        "ptmxmode=0666",
        "mode=0620",
        "gid=5",
      ],
    },
    {
      destination: "/dev/mqueue",
      type: "mqueue",
      source: "mqueue",
      options: ["nosuid", "noexec", "nodev"],
    },
    {
      destination: "/etc/hosts",
      type: "bind",
      source: join(
        store.run_root,
        "overlay-containers",
        identity.id,
        "userdata/hosts",
      ),
      options: bindOptions,
    },
    {
      destination: "/dev/shm",
      type: "bind",
      source: join(identity.static_dir, "shm"),
      options: [...bindOptions, "nosuid", "noexec", "nodev"],
    },
    {
      destination: "/run/.containerenv",
      type: "bind",
      source: join(
        store.run_root,
        "overlay-containers",
        identity.id,
        "userdata/.containerenv",
      ),
      options: bindOptions,
    },
    {
      destination: "/etc/hostname",
      type: "bind",
      source: join(
        store.run_root,
        "overlay-containers",
        identity.id,
        "userdata/hostname",
      ),
      options: bindOptions,
    },
    {
      destination: "/sys/fs/cgroup",
      type: "cgroup",
      source: "cgroup",
      options: ["rprivate", "nosuid", "noexec", "nodev", "relatime", "ro"],
    },
  ];
};
export const observePodmanNamespaceEntry = async (
  pid: number,
  destination: string,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
  directory = true,
) => {
  signal.throwIfAborted();
  const path = `/proc/${pid}/root${destination}`;
  const handle = await open(
    path,
    // Linux x86_64 asm-generic/fcntl.h: O_PATH=(1<<21); metadata only, no directory read authority.
    (1 << 21) | (directory ? constants.O_DIRECTORY : 0) | constants.O_NOFOLLOW,
  );
  const owner = {
    kind: "file-handle" as const,
    resource: path,
    handle: new OwnedFileHandle(handle),
  };
  let primary: unknown;
  try {
    signal.throwIfAborted();
    const stat = await handle.stat({ bigint: true });
    requireFact(
      directory ? stat.isDirectory() : stat.isFile(),
      "Namespace bind source/target is not the expected regular file or directory",
    );
    return { device: stat.dev.toString(), inode: stat.ino.toString() };
  } catch (cause: unknown) {
    primary =
      cause instanceof AnalysisError
        ? cause
        : signal.aborted
          ? new AnalysisCancelledError("firmware_container_runtime", { cause })
          : cause;
    throw primary;
  } finally {
    const released = await scope.release(owner);
    if (released.kind === "failed")
      throw new FirmwareFileCleanupError(
        scope,
        path,
        "firmware_container_runtime",
        released.cause,
        primary,
        "podman",
      );
  }
};

/** Pure interpretation of observed OCI against typed intent and independently observed host defaults. */
export const admitPodmanOciConfiguration = (
  value: unknown,
  expected: {
    identity: PodmanContainerIdentity;
    selection: PodmanCreateSelection;
    store: PodmanExistingStoreProfile;
    uid_mappings: readonly z.infer<typeof mapping>[];
    gid_mappings: readonly z.infer<typeof mapping>[];
    masked_paths: readonly string[];
  },
) => {
  const { identity, selection, store } = expected;
  requireFact(
    jsonValueValidationIssue(value) === undefined,
    "OCI value exceeds supported JSON representation/depth",
  );
  const oci = ociSchema.parse(value);
  requireFact(
    same(oci.process.args, [
      selection.invocation.executable,
      ...selection.invocation.arguments,
    ]),
    "Actual OCI command differs from the selected fixed producer command",
  );
  const env = [
    "PATH=/usr/local/bin:/usr/bin:/bin",
    "HOME=/rea-work",
    "TMPDIR=/rea-work",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    `REA_PROCESS_RUN_ID=${selection.token}`,
    "HOSTNAME=rea-firmware",
  ];
  requireFact(
    same([...oci.process.env].sort(), env.sort()) &&
      new Set(oci.process.env.map((value) => value.split("=", 1)[0])).size ===
        oci.process.env.length,
    "Actual OCI environment omitted or added authority outside the selected fixed environment",
  );
  requireFact(
    oci.process.user.uid === selection.uid &&
      oci.process.user.gid === selection.gid &&
      same(oci.process.user.additionalGids ?? [], [selection.gid]) &&
      (oci.process.user.umask === undefined || oci.process.user.umask === 0o22),
    "Actual OCI process UID/GID/groups/umask differ from the fixed nonroot selection",
  );
  requireFact(
    new Set(oci.process.rlimits.map((limit) => limit.type)).size === 2 &&
      oci.process.rlimits.every((limit) => limit.soft === limit.hard),
    "Actual OCI inherited limits are unsupported",
  );
  requireFact(
    oci.root.path === identity.image_root,
    "Actual readonly image root differs from exact inspected native-overlay root",
  );
  requireFact(
    same(
      oci.linux.namespaces.map((namespace) => namespace.type).sort(),
      [...namespaceTypes].sort(),
    ),
    "Actual OCI namespaces omit or duplicate a required private namespace",
  );
  requireFact(
    same(oci.linux.uidMappings, expected.uid_mappings) &&
      same(oci.linux.gidMappings, expected.gid_mappings),
    "Actual OCI keep-id mappings differ from the admitted helper subordinate IDs",
  );
  requireFact(
    oci.linux.cgroupsPath === `user.slice:libpod:${identity.id}`,
    "Actual OCI cgroup association differs from exact owned CID",
  );
  requireFact(
    policyDigest(oci.linux.seccomp) === seccompPolicySha256,
    "Actual OCI seccomp differs from the supported generated x86_64 default policy",
  );
  requireFact(
    same(oci.linux.maskedPaths, expected.masked_paths) &&
      same(oci.linux.readonlyPaths, readonlyPaths),
    "Actual OCI mask/readonly policy differs from complete pinned vendor defaults",
  );
  const label = /^system_u:system_r:container_t:s0:(c[0-9]+,c[0-9]+)$/u.exec(
    oci.process.selinuxLabel,
  );
  requireFact(
    label !== null &&
      oci.linux.mountLabel ===
        `system_u:object_r:container_file_t:s0:${label?.[1]}`,
    "Actual OCI SELinux execution/mount label is not the supported default MCS policy",
  );
  const annotations = {
    "io.container.manager": "libpod",
    "io.podman.annotations.cid-file": selection.cidfile,
    "io.podman.annotations.pids-limit": "-1",
    "io.podman.annotations.userns": "keep-id",
    "org.opencontainers.image.stopSignal": "15",
    "org.systemd.property.KillSignal": "15",
    "org.systemd.property.TimeoutStopUSec": "uint64 10000000",
  };
  requireFact(
    same(oci.annotations, annotations),
    "Actual OCI annotations add or change unsupported execution policy",
  );
  const expectedMounts = generatedMounts(identity, selection, store);
  const byDestination = (
    a: z.infer<typeof ociMount>,
    b: z.infer<typeof ociMount>,
  ) => a.destination.localeCompare(b.destination, "en");
  requireFact(
    same(
      [...oci.mounts].sort(byDestination),
      expectedMounts.sort(byDestination),
    ),
    "Actual OCI mount map differs from fixed disjoint producer/runtime mounts",
  );
  return oci;
};

/** The supported profile is fixed by typed intent and pinned vendor defaults, never an operator allow-list. */
export const admitOwnedPodmanOci = async (context: {
  identity: PodmanContainerIdentity;
  selection: PodmanCreateSelection;
  store: PodmanExistingStoreProfile;
  directories: ReadonlyMap<
    string,
    Awaited<ReturnType<typeof observePodmanProfileDirectory>>
  >;
  signal: AbortSignal;
  scope: ArtifactResourceScope;
  observer?: PodmanMetadataExecutionContext;
  retainSource?: (source: {
    identity: PodmanDescriptorIdentity;
    raw_base64: string;
  }) => void;
}): Promise<OwnedPodmanOci> => {
  const { identity, selection, store, signal, scope } = context;
  requireFact(
    process.platform === "linux" &&
      process.arch === "x64" &&
      identity.image_root !== null &&
      identity.image_root !== "" &&
      identity.static_dir !== null &&
      identity.static_dir !== "" &&
      identity.oci_path !== null &&
      identity.oci_path !== "",
    "Supported OCI admission requires the Linux x86_64 native-overlay image root",
  );
  const directory = await observePodmanProfileDirectory(
    identity.static_dir,
    signal,
    scope,
  );
  const observed = await observePodmanProfileFile(
    identity.oci_path,
    8 * 1024 * 1024,
    signal,
    scope,
    (source) =>
      context.retainSource?.({
        identity: source.identity,
        raw_base64: source.bytes.toString("base64"),
      }),
  );
  requireFact(
    same(
      directory,
      await observePodmanProfileDirectory(identity.static_dir, signal, scope),
    ),
    "Owned OCI userdata directory changed during descriptor admission",
  );
  const oci = admitPodmanOciConfiguration(
    JSON.parse(decodePodmanProfileText(observed.bytes)),
    {
      identity,
      selection,
      store,
      uid_mappings: await nativeMappings(
        store.shared_helper.pid,
        "uid_map",
        selection.uid,
        signal,
        scope,
      ),
      gid_mappings: await nativeMappings(
        store.shared_helper.pid,
        "gid_map",
        selection.gid,
        signal,
        scope,
      ),
      masked_paths: await defaults(signal),
    },
  );
  const prepared = await observePodmanPreparedProcess(
    identity.pid,
    signal,
    scope,
  );
  requireFact(
    prepared.pending_exec_label === oci.process.selinuxLabel,
    "Prepared pending SELinux execution label differs from admitted OCI; current label is only an observation before FIFO",
  );
  const destinations = new Map<string, PodmanMountEntry[]>();
  for (const mount of prepared.mounts) {
    const entries = destinations.get(mount.destination) ?? [];
    entries.push(mount);
    destinations.set(mount.destination, entries);
  }
  const root = destinations.get("/");
  requireFact(
    root?.length === 1 &&
      root[0]!.filesystem === "overlay" &&
      root[0]!.options.includes("ro"),
    "Actual prepared image root is not one readonly overlay mount",
  );
  const deviceRoots = new Map(
    ["null", "zero", "full", "random", "urandom", "tty"].map((name) => [
      `/dev/${name}`,
      `/${name}`,
    ]),
  );
  const allowed = new Set([
    "/",
    ...oci.mounts.map((mount) => mount.destination),
    ...oci.linux.maskedPaths,
    ...oci.linux.readonlyPaths,
    ...deviceRoots.keys(),
  ]);
  for (const mount of prepared.mounts) {
    requireFact(
      allowed.has(mount.destination) && mount.optional.length === 0,
      "Actual prepared mounts include an unknown target or shared propagation",
    );
    if (deviceRoots.has(mount.destination))
      requireFact(
        mount.filesystem === "devtmpfs" &&
          mount.root === deviceRoots.get(mount.destination) &&
          mount.options.includes("nosuid") &&
          mount.options.includes("noexec"),
        "Actual prepared device mount differs from the fixed runtime default",
      );
    else if (
      oci.linux.maskedPaths.includes(mount.destination) ||
      oci.linux.readonlyPaths.includes(mount.destination)
    )
      requireFact(
        mount.options.includes("ro"),
        "Actual prepared mask/readonly path is writable",
      );
    if (oci.linux.maskedPaths.includes(mount.destination))
      requireFact(
        (mount.filesystem === "tmpfs" &&
          mount.root === "/crun/.empty-directory") ||
          (mount.filesystem === "devtmpfs" && mount.root === "/null"),
        "Actual prepared mask is not the fixed empty-directory/null-file mechanism",
      );
    if (oci.linux.readonlyPaths.includes(mount.destination))
      requireFact(
        mount.filesystem === "proc" &&
          mount.root === mount.destination.slice("/proc".length) &&
          mount.device === destinations.get("/proc")?.[0]?.device,
        "Actual prepared readonly proc path is not bound to the prepared proc mount",
      );
  }
  for (const path of new Set(oci.linux.maskedPaths)) {
    const count = destinations.get(path)?.length ?? 0;
    const expectedCount = oci.linux.maskedPaths.filter(
      (mask) => mask === path,
    ).length;
    requireFact(
      count === 0 || count === expectedCount,
      "Actual prepared mask stack lost or added a pinned default layer",
    );
    try {
      await lstat(path);
      requireFact(
        count === expectedCount,
        "An applicable default kernel mask is missing from prepared mounts",
      );
    } catch (cause: unknown) {
      if (
        !(cause instanceof Error && "code" in cause && cause.code === "ENOENT")
      )
        throw cause;
    }
  }
  for (const mount of oci.mounts) {
    const entries = destinations.get(mount.destination);
    requireFact(
      entries?.length === 1,
      "Actual prepared runtime/producer mount is missing or stacked unexpectedly",
    );
    const actual = entries![0]!;
    if (mount.options.includes("ro"))
      requireFact(
        actual.options.includes("ro"),
        "Actual prepared readonly mount is writable",
      );
    if (mount.type !== "bind")
      requireFact(
        actual.filesystem ===
          (mount.type === "cgroup" ? "cgroup2" : mount.type),
        "Actual prepared mount filesystem differs from admitted OCI",
      );
    for (const flag of ["nosuid", "nodev", "noexec"])
      if (mount.options.includes(flag))
        requireFact(
          actual.options.includes(flag),
          "Actual prepared mount dropped an admitted security flag",
        );
  }
  const helper = await observePodmanSharedHelper(store, signal, scope);
  requireFact(
    context.observer !== undefined,
    "Owned OCI requires its admitted metadata observer execution context",
  );
  const metadata = await observePodmanNamespaceMetadata({
    store,
    identity,
    selection,
    signal,
    scope,
    execution: context.observer,
  });
  const bindings: OwnedPodmanOci["bindings"][number][] =
    metadata.response.pairs.map((pair) => ({
      source: pair.source,
      destination: pair.destination,
      directory: pair.directory,
      device: pair.source_identity.device,
      inode: pair.source_identity.inode,
    }));
  for (const mount of selection.mounts) {
    const source = await observePodmanProfileDirectory(
      mount.source,
      signal,
      scope,
    );
    const actual = bindings.find(
      (binding) => binding.destination === podmanMountDestination(mount.role),
    );
    requireFact(
      same(source, context.directories.get(mount.source)) &&
        actual?.device === source.device &&
        actual.inode === source.inode,
      "Prepared bind differs from its retained staging directory identity",
    );
    requireFact(
      destinations
        .get(podmanMountDestination(mount.role))![0]!
        .options.includes(mount.role === "work" ? "rw" : "ro"),
      "Prepared role mount has wrong read/write authority",
    );
  }
  requireFact(
    same(helper, await observePodmanSharedHelper(store, signal, scope)),
    "Shared helper generation changed across prepared mount-source observation",
  );
  const result: OwnedPodmanOci = {
    identity: observed.identity,
    metadata,
    process: prepared,
    configuration: oci,
    bindings,
    source_view: {
      pid: helper.pid,
      start_ticks: helper.start_ticks,
      mount_ns: helper.mount_ns,
    },
    source_semantics:
      "Podman5.8.7/c593/crun1.28/54f16ff; Linux x86_64 rootless native-overlay, default SELinux and generated seccomp",
  };
  await recheckOwnedPodmanOci(result, signal, scope, {
    store,
    identity,
    selection,
    execution: context.observer,
  });
  freezeJsonSnapshot(
    result as unknown as import("../../domain/jsonValue.js").JsonValue,
  );
  return result;
};
export const recheckOwnedPodmanOci = async (
  admitted: OwnedPodmanOci,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
  observer?: {
    store: PodmanExistingStoreProfile;
    identity: PodmanContainerIdentity;
    selection: PodmanCreateSelection;
    execution: PodmanMetadataExecutionContext;
  },
) => {
  const config = await observePodmanProfileFile(
    admitted.identity.path,
    8 * 1024 * 1024,
    signal,
    scope,
  );
  requireFact(
    same(config.identity, admitted.identity),
    "Admitted OCI descriptor changed before producer start",
  );
  const process = await observePodmanPreparedProcess(
    admitted.process.pid,
    signal,
    scope,
  );
  requireFact(
    process.start_ticks === admitted.process.start_ticks &&
      same(process.namespaces, admitted.process.namespaces) &&
      same(process.mounts, admitted.process.mounts) &&
      process.pending_exec_label ===
        admitted.configuration.process.selinuxLabel,
    "Admitted prepared PID/namespace/mount/pending label generation changed before producer start",
  );
  const helper = await observePodmanProcessGeneration(
    admitted.source_view.pid,
    signal,
    scope,
  );
  requireFact(
    helper.start_ticks === admitted.source_view.start_ticks &&
      (await readlink(`/proc/${helper.pid}/ns/mnt`)) ===
        admitted.source_view.mount_ns,
    "Admitted helper source view changed before producer start",
  );
  requireFact(
    observer !== undefined,
    "Prepared recheck requires the admitted metadata observer context",
  );
  const metadata = await observePodmanNamespaceMetadata({
    ...observer,
    signal,
    scope,
  });
  requireFact(
    same(
      metadata.response.pairs.map((pair) => ({
        source: pair.source,
        destination: pair.destination,
        directory: pair.directory,
        device: pair.source_identity.device,
        inode: pair.source_identity.inode,
      })),
      admitted.bindings,
    ),
    "Admitted bind source/target descriptor generation changed before producer start",
  );
  requireFact(
    (await observePodmanProcessGeneration(helper.pid, signal, scope))
      .start_ticks === admitted.source_view.start_ticks &&
      (await readlink(`/proc/${helper.pid}/ns/mnt`)) ===
        admitted.source_view.mount_ns &&
      (
        await observePodmanProcessGeneration(
          admitted.process.pid,
          signal,
          scope,
        )
      ).start_ticks === admitted.process.start_ticks,
    "Source/producer namespace generation changed across bind revalidation",
  );
};
