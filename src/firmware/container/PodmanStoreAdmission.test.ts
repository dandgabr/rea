import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { EventEmitter } from "node:events";
import { DatabaseSync } from "node:sqlite";
import { PassThrough } from "node:stream";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { parseLinuxProcessStartTime } from "../../process/ProcessOwnershipObservation.js";
import {
  observePodmanProfileDirectory,
  identifyPodmanProfileFile,
} from "./PodmanProfileFiles.js";
import {
  PODMAN_SOURCE_SEMANTICS,
  podmanExistingStoreProfileSchema,
  type PodmanExistingStoreProfile,
} from "./PodmanStoreProfile.js";
import { observePodmanDatabase } from "./PodmanDatabase.js";
import { launchPodmanDirectClient } from "./PodmanClientCleanup.js";
import { admitPodmanStore } from "./PodmanStoreAdmission.js";
import {
  admitPodmanInvocationSelectors,
  PreparedPodmanTransport,
  podmanImmutableImageSchema,
} from "./PodmanTransport.js";
import type { FirmwareLauncher } from "../FirmwareCommand.js";
import * as firmwareCommand from "../FirmwareCommand.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});
const digest = (bytes: string | Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
/** A simulated preinitialized profile, never a real Podman/provider assertion. */
const podmanStoreFixture = async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-podman-profile-"));
  roots.push(root);
  const scope = new ArtifactResourceScope();
  const signal = new AbortController().signal;
  const dirs = ["graph", "run", "static", "tmp", "volumes", "runtime"];
  for (const dir of dirs) await mkdir(join(root, dir), { mode: 0o700 });
  const graph = join(root, "graph");
  const runtime = join(root, "runtime");
  const staticDir = join(root, "static");
  for (const dir of ["overlay-images", "overlay-containers", "overlay-layers"])
    await mkdir(join(graph, dir), { mode: 0o700 });
  await mkdir(join(runtime, "libpod/tmp"), { recursive: true, mode: 0o700 });
  const metadataPaths = [
    join(staticDir, "db.sql"),
    ...[
      "storage.lock",
      "userns.lock",
      "overlay-images/images.json",
      "overlay-images/images.lock",
      "overlay-containers/containers.json",
      "overlay-containers/containers.lock",
      "overlay-layers/layers.json",
      "overlay-layers/layers.lock",
    ].map((path) => join(graph, path)),
  ];
  for (const path of metadataPaths)
    await writeFile(path, path.endsWith(".json") ? "[]" : "initialized", {
      mode: 0o600,
    });
  const command = join(root, "podman");
  await writeFile(command, "simulated binary, never executed", { mode: 0o700 });
  const storage = join(root, "storage.conf");
  const containers = join(root, "containers.conf");
  await writeFile(
    storage,
    `[storage]\ndriver="overlay"\ngraphroot="${graph}"\nrunroot="${join(root, "run")}"\n[storage.options.overlay]\nmountopt="nodev"\n`,
    { mode: 0o600 },
  );
  await writeFile(
    containers,
    `[engine]\ndatabase_backend="sqlite"\nstatic_dir="${staticDir}"\ntmp_dir="${join(root, "tmp")}"\nvolume_path="${join(root, "volumes")}"\n`,
    { mode: 0o600 },
  );
  const receiptPath = join(root, "receipt.json");
  await writeFile(
    receiptPath,
    JSON.stringify({ authority: "simulated operator initialization receipt" }),
    { mode: 0o600 },
  );
  const pidfile = join(runtime, "libpod/tmp/pause.pid");
  await writeFile(pidfile, `${process.pid}\n`, { mode: 0o600 });
  const processPath = `/proc/${process.pid}`;
  const processStat = await readFile(join(processPath, "stat"), "utf8");
  const uid = process.getuid!();
  const profile: PodmanExistingStoreProfile = {
    profile: "podman-existing-store-v1",
    podman: {
      command,
      resolved_command: command,
      sha256: digest(await readFile(command)),
      version: "5.8.7",
      source_semantic_revision: PODMAN_SOURCE_SEMANTICS,
      binary_source_attestation: "unknown",
    },
    rootless_uid: uid,
    runtime_directory: runtime,
    graph_root: graph,
    run_root: join(root, "run"),
    driver: "overlay",
    storage_options: { overlay_mountopt: "nodev" },
    static_dir: staticDir,
    tmp_dir: join(root, "tmp"),
    volume_path: join(root, "volumes"),
    database: {
      backend: "sqlite",
      path: metadataPaths[0]!,
      initialized_compatible_version: "5.8.7",
      assertion_authority:
        "simulated operator receipt; database attestation unknown",
    },
    configuration_provenance: [
      {
        ...(await identifyPodmanProfileFile(storage, signal, scope)),
        role: "storage",
      },
      {
        ...(await identifyPodmanProfileFile(containers, signal, scope)),
        role: "containers",
      },
    ],
    directory_identities: await Promise.all(
      dirs.map((dir) =>
        observePodmanProfileDirectory(join(root, dir), signal, scope),
      ),
    ),
    initialization_receipt: {
      path: receiptPath,
      sha256: digest(await readFile(receiptPath)),
    },
    native_metadata_observation: {
      observed_at_unix: 1,
      semantics: "historical mutable metadata",
      files: await Promise.all(
        metadataPaths.map((path) =>
          identifyPodmanProfileFile(path, signal, scope),
        ),
      ),
    },
    shared_helper: {
      pid: process.pid,
      start_ticks: parseLinuxProcessStartTime(processStat)!,
      uid: (await stat(processPath)).uid,
      user_ns: await readlink(join(processPath, "ns/user")),
      mount_ns: await readlink(join(processPath, "ns/mnt")),
      pid_ns: await readlink(join(processPath, "ns/pid")),
      executable: await readlink(join(processPath, "exe")),
      pidfile,
    },
  };
  await rm(profile.database.path);
  const initialized = new DatabaseSync(profile.database.path);
  try {
    initialized.exec(
      "CREATE TABLE DBConfig (ID INTEGER, SchemaVersion INTEGER, OS TEXT, StaticDir TEXT, TmpDir TEXT, GraphRoot TEXT, RunRoot TEXT, GraphDriver TEXT, VolumeDir TEXT)",
    );
    initialized
      .prepare("INSERT INTO DBConfig VALUES (1,1,'linux',?,?,?,?,?,?)")
      .run(
        profile.static_dir,
        profile.tmp_dir,
        profile.graph_root,
        profile.run_root,
        profile.driver,
        profile.volume_path,
      );
  } finally {
    initialized.close();
  }
  await chmod(profile.database.path, 0o600);
  profile.native_metadata_observation.files[0] =
    await identifyPodmanProfileFile(profile.database.path, signal, scope);
  const profilePath = join(root, "profile.json");
  await writeFile(profilePath, JSON.stringify(profile), { mode: 0o600 });
  return { root, signal, scope, profilePath, profile, storage, metadataPaths };
};
const fixture = podmanStoreFixture;

it("admits current regular metadata after legitimate in-place DB and atomic index updates without changing stable selectors", async () => {
  const f = await fixture();
  const first = await admitPodmanStore(
    f.profilePath,
    f.profile.podman.command,
    f.signal,
    f.scope,
  );
  const transaction = new DatabaseSync(f.profile.database.path);
  try {
    transaction.exec(
      "CREATE TABLE UpdatedMetadata (ID INTEGER); INSERT INTO UpdatedMetadata VALUES (1)",
    );
  } finally {
    transaction.close();
  }
  const index = f.metadataPaths[3]!;
  await writeFile(`${index}.new`, "[{}]", { mode: 0o600 });
  await rename(`${index}.new`, index);
  const current = await first.recheck(f.signal, f.scope);
  expect(current.native_metadata.files[0]!.sha256).not.toBe(
    f.profile.native_metadata_observation.files[0]!.sha256,
  );
  expect(current.native_metadata.files[3]!.inode).not.toBe(
    f.profile.native_metadata_observation.files[3]!.inode,
  );
  expect(current.shared_helper.authority).toBe(
    "external_shared_infrastructure",
  );
  expect(first.selection.storage_options).toEqual({
    overlay_mountopt: "nodev",
  });
});
it("refuses immutable configuration drift, stale root replacement and absent metadata before any transport", async () => {
  const f = await fixture();
  const admitted = await admitPodmanStore(
    f.profilePath,
    f.profile.podman.command,
    f.signal,
    f.scope,
  );
  await writeFile(
    f.storage,
    `${await readFile(f.storage, "utf8")}# immutable provenance changed\n`,
  );
  await expect(admitted.recheck(f.signal, f.scope)).rejects.toThrow(
    /configuration|provenance/i,
  );
  const g = await fixture();
  await rename(g.profile.run_root, `${g.profile.run_root}.old`);
  await mkdir(g.profile.run_root);
  await expect(
    admitPodmanStore(
      g.profilePath,
      g.profile.podman.command,
      g.signal,
      g.scope,
    ),
  ).rejects.toThrow(/directory|identity/i);
  const h = await fixture();
  await rm(h.metadataPaths[0]!);
  await expect(
    admitPodmanStore(
      h.profilePath,
      h.profile.podman.command,
      h.signal,
      h.scope,
    ),
  ).rejects.toThrow();
});
it("refuses mismatched complete storage options despite a valid selected descriptor digest", async () => {
  const f = await fixture();
  const storageRecord = f.profile.configuration_provenance.find(
    (entry) => entry.role === "storage",
  )!;
  await writeFile(
    f.storage,
    `[storage]\ndriver="overlay"\ngraphroot="${f.profile.graph_root}"\nrunroot="${f.profile.run_root}"\n[storage.options.overlay]\nmountopt="nodev,noexec"\n`,
  );
  Object.assign(
    storageRecord,
    await identifyPodmanProfileFile(f.storage, f.signal, f.scope),
  );
  await writeFile(f.profilePath, JSON.stringify(f.profile));
  await expect(
    admitPodmanStore(
      f.profilePath,
      f.profile.podman.command,
      f.signal,
      f.scope,
    ),
  ).rejects.toThrow(/options|configuration/i);
});

it("refuses incompatible schema, absent DBConfig, wrong DB roots and journal/WAL applicability with zero command launches", async () => {
  for (const fault of ["version", "absent", "roots", "wal"] as const) {
    const f = await fixture();
    if (fault === "wal")
      await writeFile(
        `${f.profile.database.path}-wal`,
        "external transaction sidecar",
      );
    else {
      const db = new DatabaseSync(f.profile.database.path);
      try {
        if (fault === "version") db.exec("UPDATE DBConfig SET SchemaVersion=2");
        if (fault === "absent") db.exec("DROP TABLE DBConfig");
        if (fault === "roots")
          db.exec("UPDATE DBConfig SET GraphRoot='/unrelated'");
      } finally {
        db.close();
      }
    }
    const launcher = vi.fn<FirmwareLauncher>();
    await expect(
      PreparedPodmanTransport.prepare({
        profile: f.profilePath,
        command: f.profile.podman.command,
        limiter: "/usr/bin/prlimit",
        signal: f.signal,
        scope: f.scope,
        launcher,
      }),
    ).rejects.toThrow(/database|DBConfig|SQLite/i);
    expect(launcher).not.toHaveBeenCalled();
  }
});

it("prepares exact owned transport selectors/environment/auth, validates the actual argv and keeps native producer limits separate", async () => {
  const f = await fixture();
  const launcher = vi.fn<FirmwareLauncher>(async (options) => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const process = Object.assign(new EventEmitter(), {
      stdout,
      stderr,
      exitCode: null as number | null,
      signalCode: null,
      kill: () => false,
    });
    setImmediate(() => {
      stdout.end(
        options.arguments.includes("info")
          ? JSON.stringify({
              host: { security: { rootless: true } },
              store: {
                graphDriverName: "overlay",
                graphRoot: f.profile.graph_root,
                runRoot: f.profile.run_root,
                volumePath: f.profile.volume_path,
                configFile: options.hostEnvironment!.CONTAINERS_STORAGE_CONF,
                graphOptions: { "overlay.mountopt": "nodev" },
                graphStatus: { "Native Overlay Diff": "true" },
              },
              version: { Version: "5.8.7" },
            })
          : "podman version 5.8.7\n",
      );
      stderr.end();
      process.exitCode = 0;
      process.emit("exit", 0, null);
      process.emit("close", 0, null);
    });
    return {
      process,
      ownership: {
        runId: options.runId,
        leaderPid: 987654,
        processGroupId: 987654,
      },
      cleanup: async () => ({ cleaned: true, signaled: false }),
    };
  });
  const transport = await PreparedPodmanTransport.prepare({
    profile: f.profilePath,
    command: f.profile.podman.command,
    limiter: "/usr/bin/prlimit",
    signal: f.signal,
    scope: f.scope,
    launcher,
  });
  try {
    await expect(transport.run(["--version"], f.signal)).rejects.toThrow(
      /first prepared transport/i,
    );
    expect(launcher).not.toHaveBeenCalled();
    await transport.run(["info", "--format=json"], f.signal);
    const result = await transport.run(["--version"], f.signal);
    expect(launcher).toHaveBeenCalledTimes(2);
    const issued = launcher.mock.calls[0]![0];
    expect(issued.arguments.slice(0, 4)).toEqual([
      "--core=0",
      "--cpu=120",
      "--",
      f.profile.podman.command,
    ]);
    expect(issued.arguments).toContain("--storage-opt=overlay.mountopt=nodev");
    expect(
      issued.arguments.some(
        (arg) => arg.startsWith("--as=") || arg.startsWith("--fsize="),
      ),
    ).toBe(false);
    expect(issued.hostEnvironment).toEqual(transport.environment);
    expect(issued.hostEnvironment).not.toHaveProperty(
      "CONTAINERS_CONF_OVERRIDE",
    );
    expect(
      JSON.parse(
        await readFile(transport.environment.REGISTRY_AUTH_FILE!, "utf8"),
      ),
    ).toEqual({ auths: {} });
    expect(
      await readFile(
        join(transport.environment.HOME!, ".config/containers/mounts.conf"),
        "utf8",
      ),
    ).toBe("");
    expect(
      (await stat(transport.environment.REGISTRY_AUTH_FILE!)).mode & 0o777,
    ).toBe(0o600);
    const exact = [...transport.arguments, "--version"];
    expect(() =>
      admitPodmanInvocationSelectors(
        exact,
        transport.store,
        join(transport.root_path, "hooks"),
      ),
    ).not.toThrow();
    for (const changed of [
      exact.filter((arg) => !arg.startsWith("--storage-opt=")),
      exact.map((arg) => (arg === f.profile.run_root ? "/unrelated/run" : arg)),
      exact.filter((arg) => arg !== "--remote=false"),
    ])
      expect(() =>
        admitPodmanInvocationSelectors(
          changed,
          transport.store,
          join(transport.root_path, "hooks"),
        ),
      ).toThrow(/selector/i);
    expect(result.captured_output.stdout_sha256).toBe(
      digest("podman version 5.8.7\n"),
    );
    expect(result.captured_output.stdout_utf8_valid).toBe(true);
    const changedInvocation = injectMissingStorageOption(
      f.profile.podman.command,
    );
    try {
      await expect(transport.run(["--version"], f.signal)).rejects.toThrow(
        /selector/i,
      );
      expect(launcher).toHaveBeenCalledTimes(2);
    } finally {
      changedInvocation.mockRestore();
    }
    await writeFile(
      transport.environment.REGISTRY_AUTH_FILE!,
      '{"auths":{"changed":{}}}',
    );
    await expect(transport.run(["--version"], f.signal)).rejects.toThrow(
      /identity/i,
    );
    expect(launcher).toHaveBeenCalledTimes(2);
  } finally {
    await transport.close();
  }
  await expect(stat(transport.root_path)).rejects.toThrow();
});

it("retains actual malformed UTF-8 metadata capture while refusing supported normalization", async () => {
  const f = await fixture();
  const launcher: FirmwareLauncher = async (options) => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const process = Object.assign(new EventEmitter(), {
      stdout,
      stderr,
      exitCode: null as number | null,
      signalCode: null,
      kill: () => false,
    });
    setImmediate(() => {
      stdout.end(
        Buffer.concat([
          Buffer.from("podman version 5.8.7"),
          Buffer.from([0xff]),
        ]),
      );
      stderr.end();
      process.exitCode = 0;
      process.emit("exit", 0, null);
      process.emit("close", 0, null);
    });
    return {
      process,
      ownership: {
        runId: options.runId,
        leaderPid: 987654,
        processGroupId: 987654,
      },
      cleanup: async () => ({ cleaned: true, signaled: false }),
    };
  };
  const transport = await PreparedPodmanTransport.prepare({
    profile: f.profilePath,
    command: f.profile.podman.command,
    limiter: "/usr/bin/prlimit",
    signal: f.signal,
    scope: f.scope,
    launcher,
  });
  try {
    const failure: unknown = await transport
      .probe(f.signal)
      .catch((cause: unknown) => cause);
    expect(failure).toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      capturedOutput: {
        stdout_utf8_valid: false,
        stdout_bytes: 21,
        stdout_sha256: digest(
          Buffer.concat([
            Buffer.from("podman version 5.8.7"),
            Buffer.from([0xff]),
          ]),
        ),
      },
    });
  } finally {
    await transport.close();
  }
});

it("retains primary failed-command bytes and private ownership when the external helper observation fails, then retries cleanup without a new command", async () => {
  const f = await fixture();
  let launches = 0;
  const launcher: FirmwareLauncher = async (options) => {
    launches++;
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const child = Object.assign(new EventEmitter(), {
      stdout,
      stderr,
      exitCode: null as number | null,
      signalCode: null,
      kill: () => false,
    });
    setImmediate(async () => {
      await writeFile(
        f.profile.shared_helper.pidfile,
        "unreadable-association\n",
      );
      stdout.end("actual-failed-client\n");
      stderr.end("producer-not-started\n");
      child.exitCode = 1;
      child.emit("exit", 1, null);
      child.emit("close", 1, null);
    });
    return {
      process: child,
      ownership: {
        runId: options.runId,
        leaderPid: 987654,
        processGroupId: 987654,
      },
      cleanup: async () => ({ cleaned: true, signaled: false }),
    };
  };
  const transport = await PreparedPodmanTransport.prepare({
    profile: f.profilePath,
    command: f.profile.podman.command,
    limiter: "/usr/bin/prlimit",
    signal: f.signal,
    scope: f.scope,
    launcher,
  });
  const failure: unknown = await transport
    .run(["info", "--format=json"], f.signal)
    .catch((cause: unknown) => cause);
  expect(failure).toMatchObject({
    _tag: "ProviderAdapterError",
    cleanupIncomplete: true,
    cleanupResources: [transport.root_path],
    diagnostics: {
      primary_error: expect.objectContaining({ code: expect.any(String) }),
    },
    capturedOutput: {
      stdout: "actual-failed-client\n",
      stdout_sha256: digest("actual-failed-client\n"),
      exit_code: 1,
    },
  });
  await expect(transport.close()).rejects.toMatchObject({
    cleanupIncomplete: true,
  });
  expect((await stat(transport.root_path)).isDirectory()).toBe(true);
  expect(launches).toBe(1);
  await writeFile(f.profile.shared_helper.pidfile, `${process.pid}\n`);
  await transport.close();
  expect(launches).toBe(1);
  await expect(stat(transport.root_path)).rejects.toThrow();
});

it("fuzzes selected bootstrap JSON and actual invocation selectors with seed 0x4e475034, 256 cases and independent zero-launch refusal oracles", async () => {
  const f = await fixture();
  const admitted = await admitPodmanStore(
    f.profilePath,
    f.profile.podman.command,
    f.signal,
    f.scope,
  );
  let state = 0x4e475034;
  const next = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  const hooks = join(f.root, "hooks");
  const valid = [
    "--remote=false",
    "--root",
    f.profile.graph_root,
    "--runroot",
    f.profile.run_root,
    "--storage-driver=overlay",
    "--storage-opt=overlay.mountopt=nodev",
    "--hooks-dir",
    hooks,
    "--version",
  ];
  for (let index = 0; index < 256; index++) {
    const kind = next() % 6;
    const changed = [...valid];
    if (kind === 0) changed.splice(6, 1);
    if (kind === 1) changed[2] = `/unrelated/${next()}`;
    if (kind === 2) changed[4] = `/unrelated/${next()}`;
    if (kind === 3) changed[6] = `--storage-opt=overlay.mountopt=${next()}`;
    if (kind === 4) changed[0] = "--remote=true";
    if (kind === 5) changed[8] = `/unrelated/${next()}`;
    expect(
      () => admitPodmanInvocationSelectors(changed, admitted, hooks),
      `seed=0x4e475034 case=${index} kind=${kind}`,
    ).toThrow();
    expect(() =>
      admitPodmanInvocationSelectors(valid, admitted, hooks),
    ).not.toThrow();
    const json: unknown = JSON.parse(
      JSON.stringify({ ...f.profile, storage_options: { arbitrary: next() } }),
    );
    // An unsupported complete option set is never repaired to the selected default.
    expect(podmanExistingStoreProfileSchema.safeParse(json).success).toBe(
      false,
    );
  }
});

it("cancels a real bounded snapshot parser and retains the exact snapshot owner until only cleanup can settle", async () => {
  const f = await podmanStoreFixture();
  const controller = new AbortController();
  let allowCleanup = false;
  let privateRoot: string | undefined;
  let cleanupParser: (() => Promise<unknown>) | undefined;
  let calls = 0;
  const launcher: FirmwareLauncher = async (options) => {
    calls++;
    privateRoot = options.cwd;
    const spawned = await launchPodmanDirectClient({
      ...options,
      arguments: [
        "--core=0",
        "--cpu=120",
        "--",
        "/usr/bin/python3",
        "-c",
        "import sys,time; sys.stdout.write('parser-observed\\n'); sys.stdout.flush(); time.sleep(30)",
      ],
    });
    cleanupParser = spawned.cleanup;
    setTimeout(() => controller.abort(), 100);
    return {
      ...spawned,
      cleanup: async () =>
        allowCleanup
          ? spawned.cleanup!()
          : { cleaned: false, reason: "injected parser close failure" },
    };
  };
  try {
    const failure = await observePodmanDatabase(
      f.profile,
      controller.signal,
      f.scope,
      launcher,
    ).catch((cause: unknown) => cause);
    expect(failure).toMatchObject({
      cleanupIncomplete: true,
      capturedOutput: {
        stdout_sha256: digest("parser-observed\n"),
        stdout_bytes: 16,
      },
      diagnostics: {
        primary_error: {
          code: "cleanup_incomplete",
          details: { diagnostics: { primary_error: { code: "cancelled" } } },
        },
      },
    });
    expect(privateRoot).toBeDefined();
    expect(await readFile(join(privateRoot!, "db.sql"))).toEqual(
      await readFile(f.profile.database.path),
    );
    expect(calls).toBe(1);
    allowCleanup = true;
    await f.scope.close();
    await expect(stat(privateRoot!)).rejects.toMatchObject({ code: "ENOENT" });
    expect(calls).toBe(1);
  } finally {
    allowCleanup = true;
    await cleanupParser?.();
    await f.scope.close();
  }
}, 5000);

it("retains actual invalid UTF-8 parser bytes instead of treating invalid DBConfig output as initialized", async () => {
  const f = await podmanStoreFixture();
  const launcher: FirmwareLauncher = (options) =>
    launchPodmanDirectClient({
      ...options,
      arguments: [
        "--core=0",
        "--cpu=120",
        "--",
        "/usr/bin/python3",
        "-c",
        "import os; os.write(1,b'\\xff')",
      ],
    });
  const failure = await observePodmanDatabase(
    f.profile,
    f.signal,
    f.scope,
    launcher,
  ).catch((cause: unknown) => cause);
  expect(failure).toMatchObject({
    capturedOutput: {
      stdout_utf8_valid: false,
      stdout_bytes: 1,
      stdout_sha256: digest(Buffer.from([255])),
    },
  });
  await f.scope.close();
});

const injectMissingStorageOption = (command: string) => {
  const original = firmwareCommand.runFirmwareCommand;
  return vi
    .spyOn(firmwareCommand, "runFirmwareCommand")
    .mockImplementation((context) =>
      original(
        context.command === command
          ? {
              ...context,
              args: context.args.filter(
                (arg) => !arg.startsWith("--storage-opt="),
              ),
            }
          : context,
      ),
    );
};

it("fuzzes actual SQLite DBConfig admission with seed 0x44424331, 16 bounded cases, no source mutation and zero Podman launches", async () => {
  let seed = 0x44424331;
  for (let index = 0; index < 16; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const f = await podmanStoreFixture();
    const db = new DatabaseSync(f.profile.database.path);
    try {
      const variant = index % 4;
      if (variant === 0)
        db.prepare("UPDATE DBConfig SET ID=?").run(2 + (seed % 32768));
      else if (variant === 1)
        db.prepare("UPDATE DBConfig SET SchemaVersion=?").run(
          2 + (seed % 32768),
        );
      else if (variant === 2)
        db.prepare("UPDATE DBConfig SET OS=?").run(`unknown-${seed}😀`);
      else
        db.prepare("UPDATE DBConfig SET GraphRoot=?").run(
          `/unselected/${seed}/replacement-�`,
        );
    } finally {
      db.close();
    }
    const before = digest(await readFile(f.profile.database.path));
    const launcher = vi.fn<FirmwareLauncher>();
    const unexpected = await PreparedPodmanTransport.prepare({
      profile: f.profilePath,
      command: f.profile.podman.command,
      limiter: "/usr/bin/prlimit",
      signal: f.signal,
      scope: f.scope,
      launcher,
    }).then(
      async (transport) => {
        await transport.close();
        return true;
      },
      () => false,
    );
    expect(unexpected, `seed-case ${index}`).toBe(false);
    expect(launcher).not.toHaveBeenCalled();
    expect(digest(await readFile(f.profile.database.path))).toBe(before);
    await f.scope.close();
  }
}, 10000);

it("refuses option-like image selectors and admits native immutable reference controls without rewriting values", () => {
  const suffix = "@sha256:" + "a".repeat(64);
  for (const value of [
    "--root=/unselected/store",
    "--runroot=/unselected/run",
    "--storage-driver=overlay",
    "--hooks-dir=/unselected/hooks",
    "--remote=true",
    "/absolute/image",
    "https://registry.test/image",
    "name/UPPER",
    "name/😀",
    "a".repeat(256),
  ]) {
    expect(
      podmanImmutableImageSchema.safeParse(value + suffix).success,
      value,
    ).toBe(false);
  }
  for (const value of [
    "sha256:" + "a".repeat(64),
    ...[
      "name",
      "ghcr.io/user/image",
      "registry.test:5000/team/my__image:Tag_1",
      "LOCALHOST/image",
      "a".repeat(255),
      "a".repeat(255) + ":" + "t".repeat(128),
    ].map((value) => value + suffix),
  ]) {
    expect(podmanImmutableImageSchema.parse(value)).toBe(value);
  }
});

it("validates complete supported command authority with seed0x434d4431,256 bounded suffix mutations after independently valid selected prefixes", async () => {
  const f = await fixture();
  const admitted = await admitPodmanStore(
    f.profilePath,
    f.profile.podman.command,
    f.signal,
    f.scope,
  );
  const hooks = join(f.root, "hooks");
  const prefix = [
    "--remote=false",
    "--root",
    f.profile.graph_root,
    "--runroot",
    f.profile.run_root,
    "--storage-driver=overlay",
    "--storage-opt=overlay.mountopt=nodev",
    "--hooks-dir",
    hooks,
  ];
  const image = "sha256:" + "a".repeat(64);
  const cid = "b".repeat(64);
  for (const control of [
    ["info", "--format=json"],
    ["--version"],
    ["image", "inspect", "--format=json", "--", image],
    ["inspect", "--format=json", "--", cid],
  ])
    expect(() =>
      admitPodmanInvocationSelectors([...prefix, ...control], admitted, hooks),
    ).not.toThrow();
  let seed = 0x434d4431;
  for (let index = 0; index < 256; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const currentImage = "sha256:" + seed.toString(16).padStart(64, "0");
    const option = [
      `--root=/unselected/store-${seed}`,
      `--runroot=/unselected/run-${seed}`,
      "--storage-opt=overlay.mountopt=nosuid",
      `--hooks-dir=/unselected/hooks-${seed}`,
      "--remote=true",
    ][seed % 5]!;
    const variants = [
      [
        "image",
        "inspect",
        "--format=json",
        option + "@sha256:" + seed.toString(16).padStart(64, "0"),
      ],
      ["image", "inspect", "--format=json", currentImage],
      ["image", "inspect", "--format=json", "--", currentImage, option],
      ["info", "--format=json", option],
      ["--version", option],
      ["inspect", "--format=json", "--", cid, option],
      ["image", "inspect", option, "--format=json", "--", image],
      ["create", "--pull=never", currentImage],
    ];
    expect(
      () =>
        admitPodmanInvocationSelectors(
          [...prefix, ...variants[index % 8]!],
          admitted,
          hooks,
        ),
      `case${index}`,
    ).toThrow();
    const identityCommand = [
      "image",
      "inspect",
      "--format=json",
      "--",
      currentImage,
    ];
    expect(() =>
      admitPodmanInvocationSelectors(
        [...prefix, ...identityCommand],
        admitted,
        hooks,
        identityCommand,
      ),
    ).not.toThrow();
    expect(() =>
      admitPodmanInvocationSelectors(
        [...prefix, ...identityCommand],
        admitted,
        hooks,
        ["image", "inspect", "--format=json", "--", image],
      ),
    ).toThrow();
  }
  await f.scope.close();
});

it("retains actionable EEXIST and explicit cancellation through failed setup cleanup with exact cleanup-only retry and zero Podman launches", async () => {
  for (const kind of ["filesystem", "cancellation"] as const) {
    const f = await fixture();
    const controller = new AbortController();
    const original = PrivateRuntimeRoot.create;
    let owned: PrivateRuntimeRoot | undefined;
    let close: (() => Promise<void>) | undefined;
    let closeCalls = 0;
    let failed = true;
    let setupCalls = 0;
    const spy = vi
      .spyOn(PrivateRuntimeRoot, "create")
      .mockImplementation(async (options) => {
        const root = await original.call(PrivateRuntimeRoot, options);
        if (options?.prefix === "rea-firmware-container-") {
          setupCalls++;
          owned = root;
          close = root.close.bind(root);
          if (kind === "filesystem") await mkdir(join(root.path, "hooks"));
          else controller.abort(new Error("explicit setup cancellation"));
          root.close = async () => {
            closeCalls++;
            if (failed) throw Error("injected exact-root close failure");
            await close!();
          };
        }
        return root;
      });
    const launcher = vi.fn<FirmwareLauncher>();
    try {
      const failure = await PreparedPodmanTransport.prepare({
        profile: f.profilePath,
        command: f.profile.podman.command,
        limiter: "/usr/bin/prlimit",
        signal: controller.signal,
        scope: f.scope,
        launcher,
      }).catch((cause: unknown) => cause);
      const projection = projectAnalysisError(
        failure as Parameters<typeof projectAnalysisError>[0],
      );
      expect(projection).toMatchObject({
        code: "cleanup_incomplete",
        details: {
          diagnostics: {
            primary_error:
              kind === "filesystem"
                ? {
                    code: "execution_failure",
                    details: {
                      diagnostics: {
                        system_code: "EEXIST",
                        path: join(owned!.path, "hooks"),
                      },
                    },
                  }
                : { code: "cancelled" },
          },
        },
      });
      expect(launcher).not.toHaveBeenCalled();
      expect(closeCalls).toBe(1);
      expect(setupCalls).toBe(1);
      failed = false;
      await f.scope.close();
      expect(closeCalls).toBe(2);
      expect(setupCalls).toBe(1);
      await expect(stat(owned!.path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      spy.mockRestore();
      failed = false;
      await f.scope.close();
    }
  }
});

const imageLauncher = (f: Awaited<ReturnType<typeof fixture>>) =>
  vi.fn<FirmwareLauncher>(async (options) => {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const child = Object.assign(new EventEmitter(), {
      stdout,
      stderr,
      exitCode: null as number | null,
      signalCode: null,
      kill: () => false,
    });
    setImmediate(() => {
      stdout.end(
        JSON.stringify(
          options.arguments.includes("info")
            ? {
                host: { security: { rootless: true } },
                store: {
                  graphDriverName: "overlay",
                  graphRoot: f.profile.graph_root,
                  runRoot: f.profile.run_root,
                  volumePath: f.profile.volume_path,
                  configFile: options.hostEnvironment!.CONTAINERS_STORAGE_CONF,
                  graphOptions: { "overlay.mountopt": "nodev" },
                  graphStatus: { "Native Overlay Diff": "true" },
                },
                version: { Version: "5.8.7" },
              }
            : [
                {
                  Id: "a".repeat(64),
                  Digest: "sha256:" + "a".repeat(64),
                  RepoDigests: [],
                  Os: "linux",
                  Architecture: "amd64",
                },
              ],
        ),
      );
      stderr.end();
      child.exitCode = 0;
      child.emit("exit", 0, null);
      child.emit("close", 0, null);
    });
    return {
      process: child,
      ownership: {
        runId: options.runId,
        leaderPid: 987654,
        processGroupId: 987654,
      },
      cleanup: async () => ({ cleaned: true, signaled: false }),
    };
  });

it("admits exact delimited image argv but refuses option/data confusion and mutated actual operands before any extra launch", async () => {
  const f = await fixture();
  const launcher = imageLauncher(f);
  const transport = await PreparedPodmanTransport.prepare({
    profile: f.profilePath,
    command: f.profile.podman.command,
    limiter: "/usr/bin/prlimit",
    signal: f.signal,
    scope: f.scope,
    launcher,
  });
  try {
    await transport.run(["info", "--format=json"], f.signal);
    expect(launcher).toHaveBeenCalledTimes(1);
    await expect(
      transport.image(
        "--root=/unselected/store@sha256:" + "a".repeat(64),
        f.signal,
      ),
    ).rejects.toThrow(/immutable/);
    await expect(
      transport.run(
        ["image", "inspect", "--format=json", "sha256:" + "a".repeat(64)],
        f.signal,
      ),
    ).rejects.toThrow(/command/);
    expect(launcher).toHaveBeenCalledTimes(1);
    const selected = "sha256:" + "a".repeat(64);
    const image = await transport.image(selected, f.signal);
    expect(image.image_id).toBe("a".repeat(64));
    expect(launcher.mock.calls[1]![0].arguments.slice(-5)).toEqual([
      "image",
      "inspect",
      "--format=json",
      "--",
      selected,
    ]);
    const original = firmwareCommand.runFirmwareCommand;
    const mutation = vi
      .spyOn(firmwareCommand, "runFirmwareCommand")
      .mockImplementation((context) =>
        original(
          context.command === f.profile.podman.command
            ? { ...context, args: context.args.filter((arg) => arg !== "--") }
            : context,
        ),
      );
    try {
      await expect(transport.image(selected, f.signal)).rejects.toThrow(
        /command/,
      );
      expect(launcher).toHaveBeenCalledTimes(2);
    } finally {
      mutation.mockRestore();
    }
    for (const kind of ["operation", "identity"] as const) {
      const changed = vi
        .spyOn(firmwareCommand, "runFirmwareCommand")
        .mockImplementation((context) =>
          original(
            context.command === f.profile.podman.command
              ? {
                  ...context,
                  args:
                    kind === "operation"
                      ? [...context.args.slice(0, -2), "--version"]
                      : context.args.map((value) =>
                          value === selected
                            ? "sha256:" + "b".repeat(64)
                            : value,
                        ),
                }
              : context,
          ),
        );
      try {
        await expect(
          kind === "operation"
            ? transport.run(["info", "--format=json"], f.signal)
            : transport.image(selected, f.signal),
        ).rejects.toThrow(/command/);
        expect(launcher).toHaveBeenCalledTimes(2);
      } finally {
        changed.mockRestore();
      }
    }
  } finally {
    await transport.close();
    await f.scope.close();
  }
});

it("preserves typed primary setup diagnostics and captured bytes after a failed exact-root close", async () => {
  const f = await fixture();
  const originalCreate = PrivateRuntimeRoot.create;
  const controller = new AbortController();
  let owned: PrivateRuntimeRoot | undefined;
  let originalClose: (() => Promise<void>) | undefined;
  let failed = true;
  let closes = 0;
  let setups = 0;
  const capture = {
    stdout: "selected observation",
    stderr: "",
    truncated: false,
    stdout_bytes: 20,
    stdout_sha256: digest("selected observation"),
  };
  const primary = new AnalysisOutputError(
    "firmware_container_runtime",
    "selected setup failure",
    {
      capturedOutput: capture,
      diagnostics: { marker: "typed setup fact" },
      partialObservation: {
        kind: "firmware",
        result: { selected_store: f.profile.graph_root },
        provenance: { authority: "injected test observation" },
      },
    },
  );
  const create = vi
    .spyOn(PrivateRuntimeRoot, "create")
    .mockImplementation(async (options) => {
      const root = await originalCreate.call(PrivateRuntimeRoot, options);
      if (options?.prefix === "rea-firmware-container-") {
        owned = root;
        setups++;
        controller.abort(primary);
        originalClose = root.close.bind(root);
        root.close = async () => {
          closes++;
          if (failed) throw Error("exact close failure");
          await originalClose!();
        };
      }
      return root;
    });
  const launcher = vi.fn<FirmwareLauncher>();
  try {
    const failure = await PreparedPodmanTransport.prepare({
      profile: f.profilePath,
      command: f.profile.podman.command,
      limiter: "/usr/bin/prlimit",
      signal: controller.signal,
      scope: f.scope,
      launcher,
    }).catch((cause: unknown) => cause);
    expect(failure).toMatchObject({
      cleanupIncomplete: true,
      capturedOutput: capture,
      partialObservation: primary.partialObservation,
      diagnostics: { primary_error: projectAnalysisError(primary) },
    });
    expect(launcher).not.toHaveBeenCalled();
    expect(setups).toBe(1);
    expect(closes).toBe(1);
    failed = false;
    await f.scope.close();
    expect(closes).toBe(2);
    expect(setups).toBe(1);
  } finally {
    create.mockRestore();
    failed = false;
    await f.scope.close();
  }
});

async function assertActualTupleRefusals(
  transport: PreparedPodmanTransport,
  signal: AbortSignal,
  selection: import("./PodmanFixedProgram.js").PodmanExistingProgramSelection,
  launchCount: () => number,
) {
  const boundary = await import("./PodmanFixedProgram.js");
  const program = selection.program;
  const builder = boundary.existingPodmanProgramArguments;
  for (const [before, after] of [
    [selection.containerId, "d".repeat(64)],
    [selection.interpreter, "/unselected/python"],
    [selection.namespaceLimiter, "/unselected/limiter"],
    [program.source, program.source + "\nraise Exception('substituted')"],
    [
      `--env=REA_PROCESS_RUN_ID=${selection.executionToken}`,
      `--env=REA_PROCESS_RUN_ID=${"e".repeat(32)}`,
    ],
    ["--as=1073741824", "--as=2147483648"],
    ["--fsize=1024", "--fsize=2048"],
    ["--interactive", "--privileged"],
  ] as const) {
    const countBefore = launchCount();
    const substitution = vi
      .spyOn(boundary, "existingPodmanProgramArguments")
      .mockImplementation((selected) =>
        builder(selected).map((value) => (value === before ? after : value)),
      );
    try {
      const result = await transport
        .openExistingProgram(selection, signal)
        .catch((cause: unknown) => cause);
      // Drain a defective admitted fixture before asserting, so a killed
      // mutant cannot strand the mock process owner.
      if (result && typeof result === "object" && "stdin" in result) {
        const admitted = result as Awaited<
          ReturnType<PreparedPodmanTransport["openExistingProgram"]>
        >;
        admitted.stdin.end();
        for await (const chunk of admitted.stdout) void chunk;
        await admitted.supervisor.stop();
      }
      expect(result).toMatchObject({
        _tag: "AnalysisCapabilityUnavailableError",
      });
      expect(launchCount()).toBe(countBefore);
    } finally {
      substitution.mockRestore();
    }
  }
}

it("binds an isolated fixed stdin program to the exact existing CID without capturing its binary stdout or granting lifecycle argv", async () => {
  const boundary = await import("./PodmanFixedProgram.js");
  const { FixedPodmanProgram } = boundary;
  const f = await fixture();
  const body = Buffer.from([0x00, 0xff, 0x61]);
  let delivered: Buffer | undefined;
  let launches = 0;
  const launcher: FirmwareLauncher = async (options) => {
    launches++;
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    const stdin = new PassThrough();
    const process = Object.assign(new EventEmitter(), {
      stdout,
      stderr,
      stdin,
      exitCode: null as number | null,
      signalCode: null,
      kill: () => false,
    });
    setImmediate(() => {
      if (options.arguments.includes("exec")) {
        stdin.on("data", (bytes: Buffer) => {
          delivered = bytes;
        });
        stdin.on("end", () => {
          stdout.end(body);
          stderr.end();
          process.exitCode = 0;
          process.emit("exit", 0, null);
          process.emit("close", 0, null);
        });
      } else {
        stdout.end(
          JSON.stringify({
            host: { security: { rootless: true } },
            store: {
              graphDriverName: "overlay",
              graphRoot: f.profile.graph_root,
              runRoot: f.profile.run_root,
              volumePath: f.profile.volume_path,
              configFile: options.hostEnvironment!.CONTAINERS_STORAGE_CONF,
              graphOptions: { "overlay.mountopt": "nodev" },
              graphStatus: { "Native Overlay Diff": "true" },
            },
            version: { Version: "5.8.7" },
          }),
        );
        stderr.end();
        process.exitCode = 0;
        process.emit("exit", 0, null);
        process.emit("close", 0, null);
      }
    });
    return {
      process,
      ownership: {
        runId: options.runId,
        leaderPid: 987654,
        processGroupId: 987654,
      },
      cleanup: async () => ({ cleaned: true, signaled: false }),
    };
  };
  const transport = await PreparedPodmanTransport.prepare({
    profile: f.profilePath,
    command: f.profile.podman.command,
    limiter: "/usr/bin/prlimit",
    signal: f.signal,
    scope: f.scope,
    launcher,
  });
  try {
    await transport.run(["info", "--format=json"], f.signal);
    const program = FixedPodmanProgram.define(
      "controlled-protocol",
      "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())",
    );
    const client = await transport.openExistingProgram(
      {
        containerId: "a".repeat(64),
        imageId: "b".repeat(64),
        interpreter: "/usr/bin/python3",
        namespaceLimiter: "/usr/bin/prlimit",
        producerFileBytes: 1024,
        program,
      },
      f.signal,
    );
    client.stdin.end("private-request-body");
    const raw: Buffer[] = [];
    for await (const chunk of client.stdout)
      raw.push(Buffer.from(chunk as Uint8Array));
    expect(Buffer.concat(raw)).toEqual(body);
    const stopped = await client.supervisor.stop();
    expect(stopped.status).not.toBe("incomplete");
    expect(delivered?.toString()).toBe("private-request-body");
    expect(client.supervisor.snapshot().stdout).toMatchObject({
      bytes: 0,
      observedBytes: 0,
      text: "",
    });
    expect(client.arguments.slice(0, 4)).toEqual([
      "--core=0",
      "--cpu=120",
      "--",
      f.profile.podman.command,
    ]);
    expect(client.arguments).toContain("--as=1073741824");
    expect(client.arguments.indexOf("--as=1073741824")).toBeGreaterThan(
      client.arguments.indexOf("a".repeat(64)),
    );
    expect(client.arguments).not.toContain("create");
    expect(client.arguments).not.toContain("start");
    const selection = {
      containerId: "a".repeat(64),
      imageId: "b".repeat(64),
      interpreter: "/usr/bin/python3",
      namespaceLimiter: "/usr/bin/prlimit",
      producerFileBytes: 1024,
      executionToken: "c".repeat(32),
      program,
    };
    await assertActualTupleRefusals(
      transport,
      f.signal,
      selection,
      () => launches,
    );
    await expect(
      transport.openExistingProgram(
        {
          containerId: "--latest",
          imageId: "b".repeat(64),
          interpreter: "/usr/bin/python3",
          namespaceLimiter: "/usr/bin/prlimit",
          producerFileBytes: 1024,
          program,
        },
        f.signal,
      ),
    ).rejects.toThrow(/identity|selection/i);
  } finally {
    await transport.close();
  }
});

it("admits only the literal existing-service generation template without reading container environments", async () => {
  const { podmanExistingGenerationCommand } =
    await import("./PodmanTransport.js");
  const f = await fixture();
  const spawned: readonly string[][] = [];
  const mutable = spawned as string[][];
  const launcher: FirmwareLauncher = async (options) => {
    mutable.push([...options.arguments]);
    const process = Object.assign(new EventEmitter(), {
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      exitCode: null as number | null,
      signalCode: null,
      kill: () => false,
    });
    setImmediate(() => {
      process.stdout.end(
        options.arguments.includes("info")
          ? JSON.stringify({
              host: { security: { rootless: true } },
              store: {
                graphDriverName: "overlay",
                graphRoot: f.profile.graph_root,
                runRoot: f.profile.run_root,
                volumePath: f.profile.volume_path,
                configFile: options.hostEnvironment!.CONTAINERS_STORAGE_CONF,
                graphOptions: { "overlay.mountopt": "nodev" },
                graphStatus: { "Native Overlay Diff": "true" },
              },
              version: { Version: "5.8.7" },
            })
          : JSON.stringify([
              {
                Id: "a".repeat(64),
                Image: "b".repeat(64),
                State: { Running: true, Pid: 501, StartedAt: "fixture" },
              },
            ]),
      );
      process.stderr.end();
      process.exitCode = 0;
      process.emit("exit", 0, null);
      process.emit("close", 0, null);
    });
    return {
      process,
      ownership: {
        runId: options.runId,
        leaderPid: 987654,
        processGroupId: 987654,
      },
      cleanup: async () => ({ cleaned: true, signaled: false }),
    };
  };
  const transport = await PreparedPodmanTransport.prepare({
    profile: f.profilePath,
    command: f.profile.podman.command,
    limiter: "/usr/bin/prlimit",
    signal: f.signal,
    scope: f.scope,
    launcher,
  });
  try {
    await transport.run(["info", "--format=json"], f.signal);
    const command = podmanExistingGenerationCommand("a".repeat(64));
    const result = await transport.run(command, f.signal);
    expect(result.stdout.text).not.toContain("Env");
    expect(command[1]).toContain(".ID");
    expect(command[1]).not.toContain(".Config");
    expect(spawned.at(-1)?.slice(-4)).toEqual(command);
    const before = spawned.length;
    await expect(
      transport.run(
        ["inspect", "--format={{json .Config.Env}}", "--", "a".repeat(64)],
        f.signal,
      ),
    ).rejects.toThrow();
    expect(spawned.length).toBe(before);
  } finally {
    await transport.close();
  }
});
