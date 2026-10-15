import { createHash } from "node:crypto";
import { readFile, readlink, writeFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { parseLinuxProcessStartTime } from "../../process/ProcessOwnershipObservation.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import * as command from "../FirmwareCommand.js";
import * as processLauncher from "../../process/ProviderProcess.js";
import { observePodmanNamespaceMetadata } from "./PodmanNamespaceMetadata.js";
import type { PodmanExistingStoreProfile } from "./PodmanStoreProfile.js";
import type { PodmanCreateSelection } from "./PodmanLifecycleCommands.js";

afterEach(() => vi.restoreAllMocks());
const fixture = async () => {
  const root = await createTestTempDirectory("rea-metadata-boundary-");
  const pidfile = join(root, "pid");
  await writeFile(pidfile, String(process.pid));
  const store = {
    graph_root: "/fixture/graph",
    run_root: "/fixture/run",
    rootless_uid: process.getuid!(),
    shared_helper: {
      pid: process.pid,
      start_ticks: parseLinuxProcessStartTime(
        await readFile(`/proc/${process.pid}/stat`, "utf8"),
      )!,
      uid: process.getuid!(),
      user_ns: await readlink(`/proc/${process.pid}/ns/user`),
      mount_ns: await readlink(`/proc/${process.pid}/ns/mnt`),
      pid_ns: await readlink(`/proc/${process.pid}/ns/pid`),
      executable: await readlink(`/proc/${process.pid}/exe`),
      pidfile,
    },
    metadata_observer: {
      kind: "python-preloaded-v1",
      command: "/usr/bin/python3",
      resolved_command: await readlink("/usr/bin/python3").then(
        (value) => `/usr/bin/${value}`,
      ),
      version: "3.14.8",
      sha256: createHash("sha256")
        .update(await readFile("/usr/bin/python3"))
        .digest("hex"),
    },
  } as unknown as PodmanExistingStoreProfile;
  const identity = {
    id: "a".repeat(64),
    image_id: "b".repeat(64),
    created: "2026-10-13T00:00:00Z",
    static_dir: null,
    oci_path: null,
    image_root: `/fixture/graph/overlay/${"c".repeat(64)}/merged`,
    pid: process.pid,
    conmon_pid: null,
    running: false,
    status: "initialized",
    exit_code: 0,
  };
  const selection = {
    mounts: [{ role: "work", source: root }],
  } as PodmanCreateSelection;
  const owners: { path: string; close(): Promise<void> }[] = [];
  const observations: unknown[] = [];
  const scope = new ArtifactResourceScope();
  const context = {
    store,
    identity,
    selection,
    signal: AbortSignal.timeout(5000),
    scope,
    execution: {
      limiter: "/usr/bin/prlimit",
      cwd: root,
      environment: { PATH: "/usr/bin:/bin" },
      retainOwner: (owner: (typeof owners)[number]) => owners.push(owner),
      retainObservation: (value: unknown) => observations.push(value),
    },
  };
  return { context, owners, observations, scope };
};
const syntheticResponse = (input: Buffer) => {
  const request = JSON.parse(input.toString());
  const userdata = `${request.run_root}/overlay-containers/${request.id}/userdata/`;
  const locations = [
    ["image", request.image_root, "/", true],
    ["hosts", `${userdata}hosts`, "/etc/hosts", false],
    ["hostname", `${userdata}hostname`, "/etc/hostname", false],
    ["containerenv", `${userdata}.containerenv`, "/run/.containerenv", false],
    [
      "shm",
      `${request.graph_root}/overlay-containers/${request.id}/userdata/shm`,
      "/dev/shm",
      true,
    ],
    ...request.roles.map((role: { role: string; source: string }) => [
      role.role,
      role.source,
      `/rea-${role.role}`,
      true,
    ]),
  ];
  return {
    protocol: "rea-podman-metadata-v1",
    status: "verified",
    stage: "entry",
    pairs: locations.map(([role, source, destination, directory]) => ({
      role,
      source,
      destination,
      directory,
      source_identity: { device: "1", inode: "2", directory },
      target_identity: { device: "1", inode: "2", directory },
    })),
    entry: {
      uid: 0,
      gid: 0,
      groups: [] as number[],
      thread_count: 1,
      user_ns: request.helper.user_ns,
      mount_ns: request.helper.mount_ns,
      uid_map: "",
      gid_map: "",
    },
    preload: {
      thread_count: 1,
      host_pid: 123,
      host_start_ticks: "1",
      run_token: "",
      executable_device: "",
      executable_inode: "",
    },
    generations: {
      before: { helper: request.helper, prepared: request.prepared },
      after: { helper: request.helper, prepared: request.prepared },
    },
  };
};
const capture = {
  stdout: "native retained bytes",
  stderr: "native diagnostic",
  truncated: false,
  exit_code: 0,
};
const installResponse = (
  change: (value: ReturnType<typeof syntheticResponse>) => void = () => {},
) => {
  vi.spyOn(processLauncher, "spawnOwnedProviderProcess").mockImplementation(
    async (actual) =>
      ({
        process: { pid: 123 },
        ownership: { leaderPid: 123, processGroupId: 123, runId: actual.runId },
      }) as never,
  );
  return vi
    .spyOn(command, "runFirmwareCommand")
    .mockImplementation(async (context) => {
      const request = JSON.parse(context.protocolInput!.toString());
      const runId = "rea-firmware-11111111-1111-4111-a111-111111111111";
      await context.launcher!({
        command: context.limiter,
        arguments: [
          "--as=1073741824",
          "--fsize=1048576",
          "--core=0",
          "--cpu=5",
          "--",
          context.command,
          ...context.args,
        ],
        cwd: context.cwd,
        hostEnvironment: context.environment,
        env: {
          TMPDIR: context.cwd,
          OMP_NUM_THREADS: "1",
          OPENBLAS_NUM_THREADS: "1",
          RAYON_NUM_THREADS: "1",
          NO_COLOR: "1",
        },
        stdin: "pipe",
        inheritedDescriptors: context.inheritedDescriptors!,
        signal: context.signal,
        expectedCommand: null,
        runId,
      });
      const response = syntheticResponse(context.protocolInput!);
      response.entry.uid_map = await readFile(
        `/proc/${request.helper.pid}/uid_map`,
        "utf8",
      );
      response.entry.gid_map = await readFile(
        `/proc/${request.helper.pid}/gid_map`,
        "utf8",
      );
      response.preload.run_token = runId;
      const executable = await stat("/usr/bin/python3", { bigint: true });
      response.preload.executable_device = executable.dev.toString();
      response.preload.executable_inode = executable.ino.toString();
      change(response);
      const text = JSON.stringify(response);
      return {
        stdout: { text, bytes: Buffer.byteLength(text), utf8Valid: true },
        stderr: { text: "", bytes: 0, utf8Valid: true },
        exit_code: 0,
        captured_output: capture,
      } as never;
    });
};
it.skipIf(process.platform !== "linux")(
  "checks independently reconstructed full pair authority and preserves every partial raw response before refusal (simulated helper, actual FD preparation)",
  async () => {
    for (const change of [
      (value: ReturnType<typeof syntheticResponse>) => {
        value.pairs[0]!.source = "/unrelated";
      },
      (value: ReturnType<typeof syntheticResponse>) => {
        value.pairs[0]!.destination = "/unrelated";
      },
      (value: ReturnType<typeof syntheticResponse>) => {
        value.pairs[0]!.directory = false;
      },
      (value: ReturnType<typeof syntheticResponse>) => {
        value.pairs.pop();
      },
      (value: ReturnType<typeof syntheticResponse>) => {
        value.pairs[1]!.target_identity.inode = "3";
      },
      (value: ReturnType<typeof syntheticResponse>) => {
        value.generations.after.prepared.start_ticks = "0";
      },
      (value: ReturnType<typeof syntheticResponse>) => {
        value.entry.groups = [1000];
      },
    ]) {
      const f = await fixture();
      installResponse(change);
      const failure = await observePodmanNamespaceMetadata(f.context).catch(
        (value: unknown) => value,
      );
      expect(failure).toMatchObject({
        _tag: "AnalysisCapabilityUnavailableError",
      });
      expect(f.observations.at(-1)).toMatchObject({
        captured_output: capture,
        response: { status: "verified" },
      });
      await f.scope.close();
      vi.restoreAllMocks();
    }
    const f = await fixture();
    installResponse();
    expect(
      (await observePodmanNamespaceMetadata(f.context)).response.pairs,
    ).toHaveLength(6);
    await f.scope.close();
  },
);
it.skipIf(process.platform !== "linux")(
  "preserves captured primary/partial observation through a real failed FD close and retries the sole retained owner without relaunch",
  async () => {
    const f = await fixture();
    const invocation = installResponse((value) => {
      value.pairs.pop();
    });
    const original = OwnedFileHandle.prototype.close;
    let failed = false;
    vi.spyOn(OwnedFileHandle.prototype, "close").mockImplementation(
      async function (this: OwnedFileHandle) {
        // Only fail after the helper response exists, preserving real setup closes.
        if (!failed && f.observations.length >= 3) {
          failed = true;
          throw Error("injected actual close failure");
        }
        await original.call(this);
      },
    );
    const failure = await observePodmanNamespaceMetadata(f.context).catch(
      (value: unknown) => value,
    );
    expect(failure).toMatchObject({
      _tag: "ProviderAdapterError",
      cleanupIncomplete: true,
      capturedOutput: capture,
      diagnostics: { primary_error: { code: "capability_unavailable" } },
    });
    expect(failure).toHaveProperty(
      "partialObservation.result.response.status",
      "verified",
    );
    expect(invocation).toHaveBeenCalledTimes(1);
    await f.scope.retryCleanup();
    await f.owners[0]!.close();
    await f.scope.close();
    expect(invocation).toHaveBeenCalledTimes(1);
  },
);
it.skipIf(process.platform !== "linux")(
  "refuses actual command/code/FD/env/cwd substitution before any spawn (actual admitted descriptors, simulated invocation mutation)",
  async () => {
    const mutations = [
      (value: processLauncher.OwnedProviderProcessSpawnOptions) => ({
        ...value,
        command: "/unrelated/prlimit",
      }),
      (value: processLauncher.OwnedProviderProcessSpawnOptions) => ({
        ...value,
        cwd: "/unrelated",
      }),
      (value: processLauncher.OwnedProviderProcessSpawnOptions) => ({
        ...value,
        hostEnvironment: {
          ...value.hostEnvironment,
          PYTHONPATH: "/substitution",
        },
      }),
      (value: processLauncher.OwnedProviderProcessSpawnOptions) => ({
        ...value,
        env: { ...value.env, LD_PRELOAD: "/substitution.so" },
      }),
      (value: processLauncher.OwnedProviderProcessSpawnOptions) => ({
        ...value,
        arguments: [
          ...value.arguments.slice(0, -1),
          "open('/substitution-marker','w')",
        ],
      }),
      (value: processLauncher.OwnedProviderProcessSpawnOptions) => ({
        ...value,
        inheritedDescriptors: [...value.inheritedDescriptors!].reverse(),
      }),
    ];
    for (const mutation of mutations) {
      const f = await fixture();
      const launched = vi
        .spyOn(processLauncher, "spawnOwnedProviderProcess")
        .mockRejectedValue(Error("unexpected spawn"));
      vi.spyOn(command, "runFirmwareCommand").mockImplementation(
        async (context) => {
          await context.launcher!({
            ...mutation({
              command: context.limiter,
              arguments: [
                "--as=1073741824",
                "--fsize=1048576",
                "--core=0",
                "--cpu=5",
                "--",
                context.command,
                ...context.args,
              ],
              cwd: context.cwd,
              hostEnvironment: context.environment,
              env: {
                TMPDIR: context.cwd,
                OMP_NUM_THREADS: "1",
                OPENBLAS_NUM_THREADS: "1",
                RAYON_NUM_THREADS: "1",
                NO_COLOR: "1",
              },
              stdin: "pipe",
              inheritedDescriptors: context.inheritedDescriptors!,
              expectedCommand: null,
              signal: context.signal,
              runId: "rea-firmware-11111111-1111-4111-a111-111111111111",
            }),
          });
          throw Error("unreachable");
        },
      );
      await expect(observePodmanNamespaceMetadata(f.context)).rejects.toThrow();
      expect(launched).not.toHaveBeenCalled();
      await f.scope.close();
      vi.restoreAllMocks();
    }
  },
);
it.skipIf(process.platform !== "linux")(
  "runs 120 seeded response mutations with independent authority/partial/cleanup oracles (seed 0x31a9, simulated helper and actual descriptor preparation)",
  async () => {
    let seed = 0x31a9;
    const next = () => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      return seed;
    };
    for (let index = 0; index < 120; index++) {
      const f = await fixture();
      const rule = index % 12;
      const unexpected = String(next() + 10);
      const invocation = installResponse((value) => {
        if (rule === 0) value.entry.uid_map += "unadmitted map";
        else if (rule === 1) value.entry.gid_map += "unadmitted map";
        else if (rule === 2) value.preload.host_pid = 124;
        else if (rule === 3)
          value.preload.run_token =
            "rea-firmware-22222222-2222-4222-a222-222222222222";
        else if (rule === 4) value.preload.executable_inode = unexpected;
        else if (rule === 5) value.preload.executable_device = unexpected;
        else if (rule === 6) value.preload.thread_count = 2;
        else if (rule === 7) value.entry.thread_count = 2;
        else if (rule === 8) value.pairs.push({ ...value.pairs[0]! });
        else if (rule === 9) value.pairs.reverse();
        else if (rule === 10) value.pairs[0]!.source_identity.directory = false;
        else value.generations.before.helper.start_ticks = unexpected;
      });
      const failure = await observePodmanNamespaceMetadata(f.context).catch(
        (value: unknown) => value,
      );
      expect(failure, `case ${index}, rule ${rule}`).toMatchObject({
        _tag: "AnalysisCapabilityUnavailableError",
        capturedOutput: capture,
      });
      expect(f.observations.at(-1)).toHaveProperty(
        "response.status",
        "verified",
      );
      expect(invocation).toHaveBeenCalledTimes(1);
      await f.scope.close();
      for (const owner of f.owners) await owner.close();
      expect(invocation).toHaveBeenCalledTimes(1);
      vi.restoreAllMocks();
    }
  },
  10000,
);
it.skipIf(process.platform !== "linux")(
  "refuses cancellation before any acquired interpreter or spawn and retains the primary cancellation through owner settlement",
  async () => {
    const f = await fixture();
    const controller = new AbortController();
    controller.abort();
    f.context.signal = controller.signal;
    const spawned = vi
      .spyOn(processLauncher, "spawnOwnedProviderProcess")
      .mockRejectedValue(Error("unexpected launch"));
    await expect(
      observePodmanNamespaceMetadata(f.context),
    ).rejects.toMatchObject({ _tag: "AnalysisCancelledError" });
    expect(spawned).not.toHaveBeenCalled();
    await f.scope.close();
    for (const owner of f.owners) await owner.close();
  },
);
it.skipIf(process.platform !== "linux")(
  "accounts complete argv/environment representation before native spawn even for a structurally valid fixed command",
  async () => {
    const f = await fixture();
    Object.assign(f.context.execution.environment, {
      DECLARED_VALUE: "x".repeat(98304),
    });
    const spawned = vi
      .spyOn(processLauncher, "spawnOwnedProviderProcess")
      .mockRejectedValue(Error("unexpected native launch"));
    vi.spyOn(command, "runFirmwareCommand").mockImplementation(
      async (context) => {
        await context.launcher!({
          command: context.limiter,
          arguments: [
            "--as=1073741824",
            "--fsize=1048576",
            "--core=0",
            "--cpu=5",
            "--",
            context.command,
            ...context.args,
          ],
          cwd: context.cwd,
          hostEnvironment: context.environment,
          env: {
            TMPDIR: context.cwd,
            OMP_NUM_THREADS: "1",
            OPENBLAS_NUM_THREADS: "1",
            RAYON_NUM_THREADS: "1",
            NO_COLOR: "1",
          },
          stdin: "pipe",
          inheritedDescriptors: context.inheritedDescriptors!,
          signal: context.signal,
          expectedCommand: null,
          runId: "rea-firmware-11111111-1111-4111-a111-111111111111",
        });
        throw Error("unreachable");
      },
    );
    await expect(
      observePodmanNamespaceMetadata(f.context),
    ).rejects.toMatchObject({ _tag: "AnalysisCapabilityUnavailableError" });
    expect(spawned).not.toHaveBeenCalled();
    await f.scope.close();
  },
);
