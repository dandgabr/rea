import {
  chmod,
  mkdtemp,
  open,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import {
  admitOwnedPodmanOci,
  admitPodmanOciConfiguration,
  parsePodmanSelinuxAttribute,
  observePodmanNamespaceEntry,
} from "./OciAdmission.js";
import { podmanCreateSelectionSchema } from "./PodmanLifecycleCommands.js";
import type { PodmanExistingStoreProfile } from "./PodmanStoreProfile.js";

// Generated default seccomp is retained from the real root-owned Podman5.8.7 init observation.
// Remaining paths/command/UID fixture are synthetic fixed-policy controls, never real producer evidence.
const seccomp = JSON.parse(
  await readFile(
    new URL("./fixtures/podman-5.8.7-seccomp.json", import.meta.url),
    "utf8",
  ),
);
const descriptorFixtures = new Map<string, ArtifactResourceScope>();
afterEach(async () => {
  vi.restoreAllMocks();
  for (const [root, scope] of descriptorFixtures) {
    await scope.close();
    await rm(root, { recursive: true, force: true });
    descriptorFixtures.delete(root);
  }
});
const cid = "b".repeat(64),
  image = "a".repeat(64),
  token = "c".repeat(32);
const selection = podmanCreateSelectionSchema.parse({
  purpose: "inventory",
  token,
  cidfile: `/private/owner-${token}.cid`,
  authfile: "/private/auth.json",
  image_id: image,
  uid: 1000,
  gid: 1000,
  mounts: [{ role: "work", source: "/private/work" }],
  invocation: {
    executable: "/usr/bin/prlimit",
    arguments: [
      "--as=1073741824",
      "--cpu=120",
      "--core=0",
      "--fsize=8388608",
      "--",
      "/usr/bin/true",
    ],
  },
});
const identity = {
  id: cid,
  image_id: image,
  created: "2026-10-13T00:00:00Z",
  static_dir: `/store/graph/overlay-containers/${cid}/userdata`,
  oci_path: `/store/graph/overlay-containers/${cid}/userdata/config.json`,
  image_root: `/store/graph/overlay/${"d".repeat(64)}/merged`,
  pid: 42,
  conmon_pid: 43,
  running: false,
  status: "initialized",
  exit_code: 0,
};
const masked_paths = [
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
  "/sys/devices/system/cpu/cpu0/thermal_throttle",
  "/sys/devices/virtual/powercap",
];
const uid_mappings = [
  { containerID: 0, hostID: 1, size: 1000 },
  { containerID: 1000, hostID: 0, size: 1 },
  { containerID: 1001, hostID: 1001, size: 64536 },
];
const expected = {
  identity,
  selection,
  store: {
    run_root: "/store/run",
    graph_root: "/store/graph",
  } as PodmanExistingStoreProfile,
  uid_mappings,
  gid_mappings: uid_mappings,
  masked_paths,
};
const fixture = () => ({
  ociVersion: "1.2.1",
  hostname: "rea-firmware",
  root: { path: identity.image_root, readonly: true },
  process: {
    user: { uid: 1000, gid: 1000, umask: 18, additionalGids: [1000] },
    args: ["/usr/bin/prlimit", ...selection.invocation.arguments],
    env: [
      "PATH=/usr/local/bin:/usr/bin:/bin",
      "HOME=/rea-work",
      "TMPDIR=/rea-work",
      "LANG=C.UTF-8",
      "LC_ALL=C.UTF-8",
      `REA_PROCESS_RUN_ID=${token}`,
      "HOSTNAME=rea-firmware",
    ],
    cwd: "/rea-work",
    capabilities: {},
    rlimits: [
      { type: "RLIMIT_NOFILE", hard: 1048576, soft: 1048576 },
      { type: "RLIMIT_NPROC", hard: 126742, soft: 126742 },
    ],
    noNewPrivileges: true,
    selinuxLabel: "system_u:system_r:container_t:s0:c74,c658",
  },
  annotations: {
    "io.container.manager": "libpod",
    "io.podman.annotations.cid-file": selection.cidfile,
    "io.podman.annotations.pids-limit": "-1",
    "io.podman.annotations.userns": "keep-id",
    "org.opencontainers.image.stopSignal": "15",
    "org.systemd.property.KillSignal": "15",
    "org.systemd.property.TimeoutStopUSec": "uint64 10000000",
  },
  linux: {
    uidMappings: uid_mappings,
    gidMappings: uid_mappings,
    resources: { pids: { limit: -1 } },
    cgroupsPath: `user.slice:libpod:${cid}`,
    namespaces: ["pid", "network", "ipc", "uts", "mount", "user", "cgroup"].map(
      (type) => ({ type }),
    ),
    seccomp: structuredClone(seccomp),
    maskedPaths: [...masked_paths],
    readonlyPaths: [
      "/proc/asound",
      "/proc/bus",
      "/proc/fs",
      "/proc/irq",
      "/proc/sys",
      "/proc/sysrq-trigger",
    ],
    mountLabel: "system_u:object_r:container_file_t:s0:c74,c658",
  },
  mounts: [
    {
      destination: "/rea-work",
      type: "bind",
      source: "/private/work",
      options: ["rw", "nosuid", "nodev", "rprivate", "rbind"],
    },
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
      source: `/store/run/overlay-containers/${cid}/userdata/hosts`,
      options: ["bind", "rprivate", "ro", "nosuid", "noexec", "nodev"],
    },
    {
      destination: "/dev/shm",
      type: "bind",
      source: `${identity.static_dir}/shm`,
      options: [
        "bind",
        "rprivate",
        "ro",
        "nosuid",
        "noexec",
        "nodev",
        "nosuid",
        "noexec",
        "nodev",
      ],
    },
    {
      destination: "/run/.containerenv",
      type: "bind",
      source: `/store/run/overlay-containers/${cid}/userdata/.containerenv`,
      options: ["bind", "rprivate", "ro", "nosuid", "noexec", "nodev"],
    },
    {
      destination: "/etc/hostname",
      type: "bind",
      source: `/store/run/overlay-containers/${cid}/userdata/hostname`,
      options: ["bind", "rprivate", "ro", "nosuid", "noexec", "nodev"],
    },
    {
      destination: "/sys/fs/cgroup",
      type: "cgroup",
      source: "cgroup",
      options: ["rprivate", "nosuid", "noexec", "nodev", "relatime", "ro"],
    },
  ],
});
it("admits fixed native-default semantics, retains both powercap masks and disjoint mount ordering", () => {
  const oci = fixture();
  expect(
    admitPodmanOciConfiguration(oci, expected).linux.maskedPaths.filter(
      (path) => path.endsWith("powercap"),
    ),
  ).toHaveLength(2);
  oci.mounts.reverse();
  expect(admitPodmanOciConfiguration(oci, expected).mounts).toHaveLength(11);
});
it("refuses new mechanisms and altered command, environment, UID, mounts, namespaces and defaults", () => {
  const faults: ((oci: ReturnType<typeof fixture>) => unknown)[] = [
    (o) => ({ ...o, hooks: { prestart: [{ path: "/host/helper" }] } }),
    (o) => ({
      ...o,
      linux: { ...o.linux, devices: [{ path: "/dev/arbitrary" }] },
    }),
    (o) => {
      o.process.args.push("--root=/host");
      return o;
    },
    (o) => {
      o.process.env.push("SECRET=ambient");
      return o;
    },
    (o) => {
      o.process.env.push("HOME=/other");
      return o;
    },
    (o) => {
      o.process.user.uid = 0;
      return o;
    },
    (o) => {
      o.process.noNewPrivileges = false;
      return o;
    },
    (o) => ({
      ...o,
      process: { ...o.process, capabilities: { bounding: ["CAP_SYS_ADMIN"] } },
    }),
    (o) => {
      o.root.readonly = false;
      return o;
    },
    (o) => {
      o.root.path = "/host/root";
      return o;
    },
    (o) => {
      o.mounts[0]!.source = "/";
      return o;
    },
    (o) => {
      o.mounts[3]!.options = o.mounts[3]!.options.filter(
        (option) => option !== "ro",
      );
      return o;
    },
    (o) => {
      o.mounts.push(o.mounts[0]!);
      return o;
    },
    (o) => ({
      ...o,
      linux: {
        ...o.linux,
        namespaces: [
          { type: "network", path: "/proc/1/ns/net" },
          ...o.linux.namespaces.slice(1),
        ],
      },
    }),
    (o) => {
      o.linux.maskedPaths.pop();
      return o;
    },
    (o) => {
      o.linux.seccomp.defaultAction = "SCMP_ACT_ALLOW";
      return o;
    },
    (o) => {
      o.process.selinuxLabel = o.process.selinuxLabel.replace(
        "container_t",
        "container_userns_t",
      );
      return o;
    },
    (o) => {
      o.annotations["io.podman.annotations.cid-file"] = "/unrelated/owner.cid";
      return o;
    },
  ];
  for (const fault of faults)
    expect(() =>
      admitPodmanOciConfiguration(fault(fixture()), expected),
    ).toThrow();
});
it("preserves a bounded JSON corpus and refuses authority drift with seed0x4f434931 across128cases", () => {
  let seed = 0x4f434931;
  for (let index = 0; index < 128; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const original = fixture();
    expect(
      admitPodmanOciConfiguration(
        JSON.parse(JSON.stringify(original)),
        expected,
      ).process.args.at(-1),
    ).toBe("/usr/bin/true");
    if (seed % 4 === 0)
      original.mounts[seed % original.mounts.length]!.source =
        "/unselected/authority";
    else if (seed % 4 === 1)
      original.process.env.push(`UNSELECTED_${seed}=source`);
    else if (seed % 4 === 2)
      original.linux.maskedPaths = original.linux.maskedPaths.filter(
        (_, position) => position !== seed % original.linux.maskedPaths.length,
      );
    else original.process.args.push(`unexpected-${seed}`);
    expect(() => admitPodmanOciConfiguration(original, expected)).toThrow();
  }
});
it("retains actual preclose OCI source bytes/SHA through malformed UTF8, cancellation and failed sole-owner close", async () => {
  for (const fault of ["utf8", "cancel", "close"] as const) {
    const root = await mkdtemp(join(tmpdir(), "rea-oci-descriptor-fixture-"));
    const scope = new ArtifactResourceScope();
    descriptorFixtures.set(root, scope);
    const path = join(root, "config.json");
    const bytes =
      fault === "utf8"
        ? Buffer.from([0xff, 0x7b])
        : Buffer.from("{malformed-json");
    await writeFile(path, bytes, { mode: 0o600 });
    const controller = new AbortController();
    const original = OwnedFileHandle.prototype.close;
    let retained:
      | { identity: { sha256: string }; raw_base64: string }
      | undefined;
    let failed = false;
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (this: OwnedFileHandle) {
        const selected = await readlink(
          `/proc/self/fd/${this.handle.fd}`,
        ).catch(() => undefined);
        if (fault === "close" && selected === path && !failed) {
          failed = true;
          expect(retained).toBeDefined();
          throw new Error("actual OCI descriptor close injection");
        }
        return original.call(this);
      });
    try {
      await expect(
        admitOwnedPodmanOci({
          identity: { ...identity, static_dir: root, oci_path: path },
          selection,
          store: expected.store,
          directories: new Map(),
          signal: controller.signal,
          scope,
          retainSource: (source) => {
            retained = source;
            if (fault === "cancel")
              controller.abort(
                new Error("caller canceled after authoritative source read"),
              );
          },
        }),
      ).rejects.toThrow();
      expect(retained?.identity.sha256).toBe(
        createHash("sha256").update(bytes).digest("hex"),
      );
      expect(Buffer.from(retained!.raw_base64, "base64")).toEqual(bytes);
      if (fault === "close") expect(failed).toBe(true);
    } finally {
      close.mockRestore();
      await scope.close();
      await rm(root, { recursive: true, force: true });
    }
  }
});

it("interprets one proc SELinux attribute terminator while preserving raw bytes and refusing interior or whitespace changes", () => {
  const label = "system_u:system_r:container_t:s0:c12,c34";
  for (const raw of [label, `${label}\n`, `${label}\0`])
    expect(parsePodmanSelinuxAttribute(raw)).toEqual({ raw, value: label });
  expect(parsePodmanSelinuxAttribute("")).toEqual({ raw: "", value: "" });
  for (const raw of [
    ` ${label}`,
    `${label} `,
    `${label}\0\n`,
    `${label}\n\n`,
    `system_u\0:system_r`,
  ])
    expect(() => parsePodmanSelinuxAttribute(raw)).toThrow(
      /SELinux attribute/u,
    );
});

it.skipIf(process.platform !== "linux")(
  "acquires metadata-only namespace directory identity without read permission and refuses a final symlink",
  async () => {
    const scope = new ArtifactResourceScope();
    const root = await mkdtemp(join(tmpdir(), "rea-oci-path-fixture-"));
    descriptorFixtures.set(root, scope);
    await chmod(root, 0);
    const signal = AbortSignal.timeout(5000);
    try {
      await expect(
        open(
          root,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        ),
      ).rejects.toMatchObject({ code: "EACCES" });
      const identity = await observePodmanNamespaceEntry(
        process.pid,
        root,
        signal,
        scope,
      );
      expect(identity.inode).toMatch(/^[0-9]+$/u);
      await chmod(root, 0o700);
      await symlink(root, join(root, "link"));
      await expect(
        observePodmanNamespaceEntry(
          process.pid,
          join(root, "link"),
          signal,
          scope,
        ),
      ).rejects.toThrow();
      const cancelled = new AbortController();
      cancelled.abort();
      await expect(
        observePodmanNamespaceEntry(process.pid, root, cancelled.signal, scope),
      ).rejects.toThrow();
    } finally {
      await chmod(root, 0o700);
    }
  },
);

it.skipIf(process.platform !== "linux")(
  "retains the namespace descriptor lease and resolves its public failure after retry",
  async () => {
    const scope = new ArtifactResourceScope();
    const root = await mkdtemp(join(tmpdir(), "rea-oci-namespace-close-"));
    descriptorFixtures.set(root, scope);
    const resource = `/proc/${process.pid}/root${root}`;
    const close = OwnedFileHandle.prototype.close;
    let allowClose = false;
    let closes = 0;
    const spy = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (this: OwnedFileHandle) {
        closes++;
        if (!allowClose) throw Error("namespace descriptor close refused");
        await Reflect.apply(close, this, []);
      });
    try {
      const failure = await observePodmanNamespaceEntry(
        process.pid,
        root,
        new AbortController().signal,
        scope,
      ).catch((cause: unknown) => cause);
      expect(failure).toMatchObject({
        cleanupIncomplete: true,
        cleanupResources: [resource],
      });
      expect(scope.cleanupResources).toEqual([resource]);
      allowClose = true;
      await scope.retryCleanup();
      expect(closes).toBe(2);
      expect(failure).toMatchObject({
        cleanupIncomplete: false,
        cleanupResources: [],
      });
    } finally {
      allowClose = true;
      await scope.close();
      spy.mockRestore();
    }
  },
);
