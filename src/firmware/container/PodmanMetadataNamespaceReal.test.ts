import { randomUUID } from "node:crypto";
import { constants, renameSync, writeFileSync, readFileSync } from "node:fs";
import {
  open,
  readFile,
  readlink,
  realpath,
  mkdir,
  writeFile,
  link,
  stat,
  access,
  copyFile,
  chmod,
  mkdtemp,
  rmdir,
} from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import {
  spawnOwnedProviderProcess,
  ProviderProcessSupervisor,
} from "../../process/ProviderProcess.js";
import { parseLinuxProcessStartTime } from "../../process/ProcessOwnershipObservation.js";
import { observePodmanSharedHelper } from "./PodmanSharedHelper.js";
import { observePodmanNamespaceMetadata as sourceObserver } from "./PodmanNamespaceMetadata.js";
import type { PodmanExistingStoreProfile } from "./PodmanStoreProfile.js";
import type { PodmanCreateSelection } from "./PodmanLifecycleCommands.js";
const profile = process.env.REA_METADATA_TEST_PROFILE;
const moduleRoot = process.env.REA_METADATA_TEST_MODULE_ROOT;
const observer: typeof sourceObserver =
  moduleRoot === undefined
    ? sourceObserver
    : (await import(`${moduleRoot}/PodmanNamespaceMetadata.js`))
        .observePodmanNamespaceMetadata;
const helperPath =
  moduleRoot === undefined
    ? fileURLToPath(
        new URL(
          "../../../bridge/firmware/podman_namespace_metadata.py",
          import.meta.url,
        ),
      )
    : fileURLToPath(
        new URL(
          "../../../bridge/firmware/podman_namespace_metadata.py",
          `${moduleRoot}/PodmanNamespaceMetadata.js`,
        ),
      );
const prepareNamespaceFiles = async (
  rootPath: string,
  selected: PodmanExistingStoreProfile,
) => {
  const id = "d".repeat(64),
    imageId = "e".repeat(64);
  const graph = join(rootPath, "graph"),
    run = join(rootPath, "run"),
    imageRoot = join(graph, "overlay", "f".repeat(64), "merged");
  const fake = join(rootPath, "image"),
    work = join(rootPath, "work"),
    userdata = join(run, "overlay-containers", id, "userdata"),
    shm = join(graph, "overlay-containers", id, "userdata/shm");
  for (const directory of [
    imageRoot,
    work,
    userdata,
    shm,
    join(fake, "etc"),
    join(fake, "run"),
    join(fake, "dev/shm"),
    join(fake, "rea-work"),
    join(rootPath, "markers"),
  ])
    await mkdir(directory, { recursive: true, mode: 0o700 });
  for (const [source, target] of [
    ["hosts", "etc/hosts"],
    ["hostname", "etc/hostname"],
    [".containerenv", "run/.containerenv"],
  ]) {
    await writeFile(join(userdata, source!), "owned fixture runtime file", {
      mode: 0o400,
    });
    await link(join(userdata, source!), join(fake, target!));
  }
  const copiedPython = join(rootPath, "admitted-python");
  await copyFile(selected.metadata_observer!.resolved_command, copiedPython);
  await chmod(copiedPython, 0o755);
  const targets = [
    copiedPython,
    await realpath(helperPath),
    await realpath("/usr/lib64/python3.14/json/__init__.py"),
    await realpath("/lib64/ld-linux-x86-64.so.2"),
  ];
  const binds: {
    source: string;
    target: string;
    readonly: boolean;
    device: string;
    inode: string;
  }[] = [];
  for (const [index, target] of targets.entries()) {
    const marker = join(rootPath, "markers", String(index));
    const source = join(rootPath, `substitute-${index}`);
    await writeFile(
      source,
      `open(${JSON.stringify(marker)},'w').write('substituted code executed')\n`,
      { mode: 0o400 },
    );
    const entry = await stat(source, { bigint: true });
    binds.push({
      source,
      target,
      readonly: true,
      device: entry.dev.toString(),
      inode: entry.ino.toString(),
    });
  }
  for (const [source, target, readonly] of [
    [fake, imageRoot, true],
    [work, join(fake, "rea-work"), false],
    [shm, join(fake, "dev/shm"), true],
  ] as const) {
    const entry = await stat(source, { bigint: true });
    binds.push({
      source,
      target,
      readonly,
      device: entry.dev.toString(),
      inode: entry.ino.toString(),
    });
  }
  const request = {
    root: rootPath,
    binds,
    fixed_targets: [...targets, imageRoot],
  };

  return {
    id,
    imageId,
    graph,
    run,
    imageRoot,
    work,
    userdata,
    shm,
    copiedPython,
    targets,
    request,
  };
};
type NamespaceReady = {
  pid: number;
  start_ticks: string;
  prepared_pid: number;
  prepared_start_ticks: string;
  run_token: string;
  private_before_bind: boolean;
  user_ns: string;
  mount_ns: string;
  pid_ns: string;
  executable: string;
};
const launchNamespaceFixture = async ({
  rootPath,
  userFd,
  mountFd,
  signal,
  request,
  observed,
  persist,
  retainSupervisor,
  external,
}: {
  rootPath: string;
  userFd: number;
  mountFd: number;
  signal: AbortSignal;
  request: Awaited<ReturnType<typeof prepareNamespaceFiles>>["request"];
  observed: Record<string, unknown>;
  persist(): Promise<void>;
  retainSupervisor(value: ProviderProcessSupervisor): void;
  external: Awaited<ReturnType<typeof observePodmanSharedHelper>>;
}) => {
  const code = await readFile(
    new URL(
      "../../../tests/fixtures/firmware/podman_metadata_namespace.py",
      import.meta.url,
    ),
    "utf8",
  );
  const runId = `rea-metadata-fixture-${randomUUID()}`;
  const spawned = await spawnOwnedProviderProcess({
    command: "/usr/bin/prlimit",
    arguments: [
      "--as=1073741824",
      "--cpu=5",
      "--core=0",
      "--fsize=1048576",
      "--",
      "/usr/bin/python3",
      "-I",
      "-S",
      "-X",
      "utf8",
      "-c",
      code,
    ],
    runId,
    expectedCommand: null,
    stdin: "pipe",
    inheritedDescriptors: [userFd, mountFd],
    cwd: rootPath,
    hostEnvironment: { PATH: "/usr/bin:/bin" },
    signal,
  });
  const supervisor = new ProviderProcessSupervisor(
    {
      ...spawned,
      ownsProcessLifetime: true,
      cleanup: async () => {
        spawned.process.stdin!.end();
        if (await supervisor!.waitForOutputClose(2000))
          return { cleaned: true as const, signaled: false };
        return {
          cleaned: false as const,
          reason:
            "Exact fixture EOF/child settlement not yet observed; no collateral signal",
        };
      },
    },
    { maxDiagnosticBytes: 65536 },
  );
  retainSupervisor(supervisor);
  observed.launch = { pid: spawned.process.pid, run_token: runId };
  await persist();
  spawned.process.stdin!.write(JSON.stringify(request) + "\n");
  const deadline = performance.now() + 10000;
  while (!supervisor.snapshot().stdout.text.includes("\n")) {
    if (await supervisor.waitForOutputClose(25))
      throw Error(
        `Fixture refused before readiness: ${supervisor.snapshot().stderr.text}`,
      );
    if (performance.now() > deadline) throw Error("Fixture readiness deadline");
  }
  const actual: NamespaceReady = JSON.parse(
    supervisor.snapshot().stdout.text.split("\n")[0]!,
  );
  observed.fixture = actual;
  await persist();
  expect(actual.pid).toBe(spawned.ownership.leaderPid);
  expect(actual.run_token).toBe(runId);
  expect(actual.private_before_bind).toBe(true);
  expect(actual.mount_ns).not.toBe(external.mount_ns);

  return { spawned, supervisor, actual };
};
type MetadataControls = {
  root: PrivateRuntimeRoot;
  store: PodmanExistingStoreProfile;
  identity: Parameters<typeof sourceObserver>[0]["identity"];
  selection: PodmanCreateSelection;
  signal: AbortSignal;
  scope: ArtifactResourceScope;
  metadataOwners: { close(): Promise<void> }[];
  observed: Record<string, unknown>;
  copiedPython: string;
  imageRoot: string;
  userdata: string;
  shm: string;
  work: string;
};
const checkParentReplacement = async ({
  root,
  store,
  identity,
  selection,
  signal,
  scope,
  metadataOwners,
  observed,
  copiedPython,
}: MetadataControls) => {
  // Atomic parent-view replacement after exact descriptor/code admission.
  // The original helper snapshot must still execute; changed executable
  // generation must either retain original execution or refuse before entry.
  for (const [index, target] of [helperPath, copiedPython].entries()) {
    const originalIdentity = await stat(target, { bigint: true });
    const originalBytes = readFileSync(target);
    const backupRoot = await mkdtemp(
      join(dirname(target), ".rea-metadata-replacement-"),
    );
    const backup = join(backupRoot, "original");
    let replaced = false;
    const marker = join(root.path, "markers", `parent-${index}`);
    try {
      const replacementResult = await observer({
        store,
        identity,
        selection,
        signal,
        scope,
        execution: {
          limiter: "/usr/bin/prlimit",
          cwd: root.path,
          environment: { PATH: "/usr/bin:/bin" },
          retainOwner: (owner) => metadataOwners.push(owner),
          retainObservation: (value) => {
            if (
              !replaced &&
              (value as { request?: unknown }).request !== undefined
            ) {
              renameSync(target, backup);
              writeFileSync(
                target,
                `#!/usr/bin/python3\nopen(${JSON.stringify(marker)},'w').write('parent substitution executed')\n`,
                { mode: 0o755 },
              );
              replaced = true;
            }
          },
        },
      }).catch((cause: unknown) => cause);
      observed[`replacement_attempt_${index}`] =
        replacementResult instanceof Error
          ? {
              reason: replacementResult.message,
              cause:
                (replacementResult as Error & { cause?: unknown })
                  .cause instanceof Error
                  ? {
                      message: (replacementResult as Error & { cause: Error })
                        .cause.message,
                      stack: (replacementResult as Error & { cause: Error })
                        .cause.stack,
                    }
                  : String(
                      (replacementResult as Error & { cause?: unknown }).cause,
                    ),
              diagnostics: (
                replacementResult as Error & { diagnostics?: unknown }
              ).diagnostics,
            }
          : replacementResult;
      expect(replaced).toBe(true);
      if (index === 0)
        expect(replacementResult).toMatchObject({
          response: { status: "verified" },
        });
      else
        expect(replacementResult).toMatchObject({
          _tag: "AnalysisCapabilityUnavailableError",
        });
      observed[`parent_replacement_${index}`] =
        replacementResult instanceof Error
          ? {
              reason: replacementResult.message,
              cause:
                (replacementResult as Error & { cause?: unknown })
                  .cause instanceof Error
                  ? {
                      message: (replacementResult as Error & { cause: Error })
                        .cause.message,
                      stack: (replacementResult as Error & { cause: Error })
                        .cause.stack,
                    }
                  : String(
                      (replacementResult as Error & { cause?: unknown }).cause,
                    ),
              diagnostics: (
                replacementResult as Error & { diagnostics?: unknown }
              ).diagnostics,
            }
          : replacementResult;
      await expect(access(marker)).rejects.toThrow();
    } finally {
      if (replaced) renameSync(backup, target);
      await rmdir(backupRoot);
      const restored = await stat(target, { bigint: true });
      expect(restored.dev).toBe(originalIdentity.dev);
      expect(restored.ino).toBe(originalIdentity.ino);
      expect(readFileSync(target)).toEqual(originalBytes);
      observed[`parent_restore_${index}`] = {
        device: restored.dev.toString(),
        inode: restored.ino.toString(),
        bytes: originalBytes.length,
        scope:
          "original inode/bytes restored; rename legitimately changes ctime",
      };
    }
  }
};
const checkNamespaceCancellation = async ({
  root,
  store,
  identity,
  selection,
  scope,
  metadataOwners,
  observed,
}: MetadataControls) => {
  // Cancellation after actual namespace entry, using a separately labelled
  // preloaded blocking fixture. This is ownership evidence, not readiness.
  const cancellationCode = readFileSync(helperPath);
  const ready = join(root.path, "entered-ready");
  try {
    const waitCode =
      "\n    entered=open_fd(" +
      JSON.stringify(ready) +
      ",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);write(entered,str(os.getpid()).encode());close(entered)\n    write(2,b'namespace entered before cancellation\\n')\n    time.sleep(20)";
    writeFileSync(
      helperPath,
      "import time\n" +
        cancellationCode
          .toString()
          .replace(
            "    setgid(0); setuid(0)",
            "    setgid(0); setuid(0)" + waitCode,
          ),
    );
    const cancellation = new AbortController();
    const running = observer({
      store,
      identity,
      selection,
      signal: cancellation.signal,
      scope,
      execution: {
        limiter: "/usr/bin/prlimit",
        cwd: root.path,
        environment: { PATH: "/usr/bin:/bin" },
        retainOwner: (owner) => metadataOwners.push(owner),
      },
    }).catch((cause: unknown) => cause);
    let enteredPid: number | undefined;
    const cancelDeadline = performance.now() + 3000;
    while (enteredPid === undefined) {
      try {
        enteredPid = Number(await readFile(ready, "utf8"));
      } catch (cause) {
        if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
      }
      if (performance.now() > cancelDeadline)
        throw Error("actual post-entry cancellation readiness deadline");
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    cancellation.abort();
    const cancelled = await running;
    expect(cancelled).toMatchObject({
      _tag: "AnalysisCancelledError",
      capturedOutput: {
        stderr: "namespace entered before cancellation\n",
        truncated: false,
      },
    });
    await expect(readFile(`/proc/${enteredPid}/stat`)).rejects.toMatchObject({
      code: "ENOENT",
    });
    observed.namespace_cancellation = {
      pid: enteredPid,
      reason: (cancelled as Error).message,
      scope:
        "instrumented preloaded sleep after actual namespace entry, exact helper process absent",
    };
  } finally {
    writeFileSync(helperPath, cancellationCode);
  }
};
const checkPostEntryTrace = async ({
  root,
  store,
  identity,
  selection,
  signal,
  scope,
  metadataOwners,
  observed,
  imageRoot,
  userdata,
  shm,
  work,
}: MetadataControls) => {
  // Separate instrumentation: original fixed helper plus a parent-installed
  // audit logger. No production certificate is inferred from this trace alone.
  const originalCode = readFileSync(helperPath);
  const prefix = `import sys\ndef metadata_trace(event,args):\n if globals().get('stage')=='entry' and event in {'open','import','compile','exec','ctypes.dlopen','_thread.start_new_thread'}:\n  sys.stderr.write(json.dumps({'event':event,'path':str(args[0]) if args else None})+'\\n')\nsys.addaudithook(metadata_trace)\n`;
  try {
    writeFileSync(
      helperPath,
      Buffer.concat([Buffer.from(prefix), originalCode]),
    );
    const trace = await observer({
      store,
      identity,
      selection,
      signal,
      scope,
      execution: {
        limiter: "/usr/bin/prlimit",
        cwd: root.path,
        environment: { PATH: "/usr/bin:/bin" },
        retainOwner: (owner) => metadataOwners.push(owner),
      },
    });
    expect(trace.response.status).toBe("verified");
    const captured = (
      trace.observation as { captured_output: { stderr: string } }
    ).captured_output;
    const events = captured.stderr
      .trim()
      .split("\n")
      .map((line: string) => JSON.parse(line));
    expect(events.length).toBeGreaterThan(0);
    expect(events.every((value) => value.event === "open")).toBe(true);
    const allowed = new Set([
      "stat",
      "uid_map",
      "gid_map",
      "root",
      imageRoot.slice(1),
      `${userdata}/hosts`.slice(1),
      `${userdata}/hostname`.slice(1),
      `${userdata}/.containerenv`.slice(1),
      shm.slice(1),
      work.slice(1),
      ".",
      "etc/hosts",
      "etc/hostname",
      "run/.containerenv",
      "dev/shm",
      "rea-work",
    ]);
    for (const event of events)
      expect(allowed.has(event.path), event.path).toBe(true);
    observed.instrumented_trace = {
      events,
      certificate: trace.response,
      scope:
        "instrumented exact original body, separate from unchanged-helper proof",
    };
  } finally {
    writeFileSync(helperPath, originalCode);
  }
};

const prepareMetadataNamespaceScenario = async ({
  root,
  selected,
  signal,
  scope,
  handles,
  observed,
  persist,
  retainSupervisor,
}: {
  root: PrivateRuntimeRoot;
  selected: PodmanExistingStoreProfile;
  signal: AbortSignal;
  scope: ArtifactResourceScope;
  handles: OwnedFileHandle[];
  observed: Record<string, unknown>;
  persist(): Promise<void>;
  retainSupervisor(value: ProviderProcessSupervisor): void;
}) => {
  const external = await observePodmanSharedHelper(selected, signal, scope);
  observed.external_before = external;
  const user = await open(`/proc/${external.pid}/ns/user`, constants.O_RDONLY);
  handles.push(new OwnedFileHandle(user));
  const mount = await open(`/proc/${external.pid}/ns/mnt`, constants.O_RDONLY);
  handles.push(new OwnedFileHandle(mount));
  expect(`user:[${(await user.stat({ bigint: true })).ino}]`).toBe(
    external.user_ns,
  );
  expect(`mnt:[${(await mount.stat({ bigint: true })).ino}]`).toBe(
    external.mount_ns,
  );
  const {
    id,
    imageId,
    graph,
    run,
    imageRoot,
    work,
    userdata,
    shm,
    copiedPython,
    targets,
    request,
  } = await prepareNamespaceFiles(root.path, selected);
  observed.request = request;
  await persist();
  const { spawned, actual } = await launchNamespaceFixture({
    rootPath: root.path,
    userFd: user.fd,
    mountFd: mount.fd,
    signal,
    request,
    observed,
    persist,
    external,
    retainSupervisor,
  });
  const generations = [
    { pid: actual.pid, start_ticks: actual.start_ticks },
    { pid: actual.prepared_pid, start_ticks: actual.prepared_start_ticks },
  ];
  await writeFile(join(root.path, "fixture.pid"), String(actual.pid), {
    mode: 0o600,
  });
  const store = {
    ...selected,
    graph_root: graph,
    run_root: run,
    metadata_observer: {
      ...selected.metadata_observer!,
      command: copiedPython,
      resolved_command: copiedPython,
    },
    shared_helper: {
      pid: actual.pid,
      start_ticks: actual.start_ticks,
      uid: process.getuid!(),
      user_ns: actual.user_ns,
      mount_ns: actual.mount_ns,
      pid_ns: actual.pid_ns,
      executable: actual.executable,
      pidfile: join(root.path, "fixture.pid"),
    },
  };
  const identity = {
    id,
    image_id: imageId,
    created: "2026-10-13T00:00:00Z",
    static_dir: null,
    oci_path: null,
    image_root: imageRoot,
    pid: actual.prepared_pid,
    conmon_pid: null,
    running: false,
    status: "initialized",
    exit_code: 0,
  };
  const selection = {
    mounts: [{ role: "work", source: work }],
  } as PodmanCreateSelection;
  return {
    external,
    targets,
    copiedPython,
    imageRoot,
    userdata,
    shm,
    work,
    spawned,
    actual,
    generations,
    store,
    identity,
    selection,
  };
};

const executeAndVerifyMetadataObservation = async ({
  root,
  store,
  identity,
  selection,
  signal,
  scope,
  metadataOwners,
  observed,
  copiedPython,
  imageRoot,
  userdata,
  shm,
  work,
  targets,
}: MetadataControls & { targets: readonly string[] }) => {
  const result = await observer({
    store,
    identity,
    selection,
    signal,
    scope,
    execution: {
      limiter: "/usr/bin/prlimit",
      cwd: root.path,
      environment: { PATH: "/usr/bin:/bin" },
      retainOwner: (owner) => metadataOwners.push(owner),
      retainObservation: (value) => {
        observed.metadata = value;
      },
    },
  });
  expect(result.response.status).toBe("verified");
  expect(result.response.pairs).toHaveLength(6);
  expect(result.response.entry.groups).toEqual([]);
  observed.certificate = result;
  for (let index = 0; index < targets.length; index++)
    await expect(
      access(join(root.path, "markers", String(index))),
    ).rejects.toThrow();
  const controls: MetadataControls = {
    root,
    store,
    identity,
    selection,
    signal,
    scope,
    metadataOwners,
    observed,
    copiedPython,
    imageRoot,
    userdata,
    shm,
    work,
  };
  await checkParentReplacement(controls);
  await checkNamespaceCancellation(controls);
  await checkPostEntryTrace(controls);
  return result;
};

const verifySubstitutionPositiveControl = async (
  root: PrivateRuntimeRoot,
  supervisor: ProviderProcessSupervisor,
  processHandle: Awaited<
    ReturnType<typeof spawnOwnedProviderProcess>
  >["process"],
  targets: readonly string[],
  observed: Record<string, unknown>,
) => {
  // Positive controls prove these exact substitutions are executable code,
  // distinct from the preceding unchanged-helper and retained-snapshot lanes.
  processHandle.stdin!.write("RUN_SUBSTITUTION_CONTROL\n");
  const controlDeadline = performance.now() + 2000;
  while (supervisor.snapshot().stdout.text.split("\n").length < 3) {
    if (performance.now() > controlDeadline)
      throw Error("Substitution control deadline");
    await supervisor.waitForOutputClose(10);
  }
  for (let index = 0; index < targets.length; index++)
    expect(
      await readFile(join(root.path, "markers", String(index)), "utf8"),
    ).toBe("substituted code executed");
  observed.unbound_positive_control = JSON.parse(
    supervisor.snapshot().stdout.text.split("\n")[1]!,
  );
};

it.skipIf(profile === undefined)(
  "executes the unchanged admitted metadata helper in an exclusively owned substituted mount view without consuming substitute code (synthetic prepared root, actual namespaces)",
  async () => {
    const scope = new ArtifactResourceScope();
    const signal = AbortSignal.timeout(30000);
    const selected = JSON.parse(
      await readFile(profile!, "utf8"),
    ) as PodmanExistingStoreProfile;
    const root = await PrivateRuntimeRoot.create({
      prefix: "rea-metadata-namespace-",
    });
    const handles: OwnedFileHandle[] = [];
    const metadataOwners: { close(): Promise<void> }[] = [];
    let supervisor: ProviderProcessSupervisor | undefined;
    let generations: { pid: number; start_ticks: string }[] = [];
    const observed: Record<string, unknown> = {
      lane: moduleRoot ?? "source",
      scope: "actual private namespace; synthetic prepared/image graph only",
      root: root.path,
    };
    const persist = async () => {
      const receipt = process.env.REA_METADATA_NAMESPACE_RECEIPT;
      if (receipt !== undefined)
        await writeFile(receipt, JSON.stringify(observed, null, 2));
    };
    const bundle = {
      path: root.path,
      close: async () => {
        for (const owner of metadataOwners) await owner.close();
        if (supervisor !== undefined) {
          const stopped = await supervisor.stop();
          observed.fixture_stop = stopped;
          if (stopped.status === "incomplete")
            throw Error("Exact fixture process remains retained");
        }
        for (const generation of generations) {
          try {
            const actual = parseLinuxProcessStartTime(
              await readFile(`/proc/${generation.pid}/stat`, "utf8"),
            );
            expect(actual).not.toBe(generation.start_ticks);
          } catch (cause) {
            if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
          }
        }
        for (const handle of [...handles].reverse()) {
          await handle.close();
          handles.splice(handles.indexOf(handle), 1);
        }
        await root.close();
        observed.cleanup =
          "exact process generations, inherited FDs and root released";
      },
    };
    try {
      const prepared = await prepareMetadataNamespaceScenario({
        root,
        selected,
        signal,
        scope,
        handles,
        observed,
        persist,
        retainSupervisor: (value) => {
          supervisor = value;
        },
      });
      generations = prepared.generations;
      await executeAndVerifyMetadataObservation({
        root,
        ...prepared,
        signal,
        scope,
        metadataOwners,
        observed,
      });
      await verifySubstitutionPositiveControl(
        root,
        supervisor!,
        prepared.spawned.process,
        prepared.targets,
        observed,
      );
      observed.external_after = await observePodmanSharedHelper(
        selected,
        signal,
        scope,
      );
      expect(observed.external_after).toEqual(prepared.external);
    } catch (cause) {
      observed.failure = {
        message: (cause as Error).message,
        captured: supervisor?.snapshot(),
      };
      throw cause;
    } finally {
      const released = await scope.release({
        kind: "private-runtime-root",
        resource: root.path,
        root: bundle,
      });
      observed.release = released.kind;
      await persist();
      if (released.kind === "failed") throw released.cause;
      await scope.close();
    }
  },
  40000,
);
