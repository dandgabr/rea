import { constants } from "node:fs";
import { open, readlink, realpath, type FileHandle } from "node:fs/promises";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { sameRegularFileState } from "../../filesystem/RegularFile.js";
import { readBoundedFileBytes } from "../../process/BoundedFileBytes.js";
import {
  spawnOwnedProviderProcess,
  type ProviderProcessSupervisor,
} from "../../process/ProviderProcess.js";
import {
  AnalysisError,
  type AnalysisCapturedOutput,
} from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisTimeoutError,
} from "../../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { runFirmwareCommand } from "../FirmwareCommand.js";
import { parseLinuxProcessStartTime } from "../../process/ProcessOwnershipObservation.js";
import {
  observePodmanProfileFile,
  podmanProfileUnavailable,
} from "./PodmanProfileFiles.js";
import { observePodmanSharedHelper } from "./PodmanSharedHelper.js";
import type { PodmanContainerIdentity } from "./OwnedPodmanContainer.js";
import type { PodmanCreateSelection } from "./PodmanLifecycleCommands.js";
import type { PodmanExistingStoreProfile } from "./PodmanStoreProfile.js";

const operation = "firmware_container_runtime";
const decimal = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const descriptor = z.strictObject({
  device: decimal,
  inode: decimal,
  directory: z.boolean(),
});
const generation = z.strictObject({
  pid: z.number().int().positive(),
  start_ticks: decimal,
  user_ns: z.string(),
  mount_ns: z.string(),
});
const pair = z.strictObject({
  role: z.enum([
    "image",
    "hosts",
    "hostname",
    "containerenv",
    "shm",
    "work",
    "input",
    "plugins",
  ]),
  source: z.string(),
  destination: z.string(),
  directory: z.boolean(),
  source_identity: descriptor,
  target_identity: descriptor,
});
const responseSchema = z.strictObject({
  protocol: z.literal("rea-podman-metadata-v1"),
  status: z.enum(["verified", "refused"]),
  stage: z.enum(["parent", "entry"]),
  pairs: z.array(pair).max(8),
  entry: z
    .object({
      uid: z.number().optional(),
      gid: z.number().optional(),
      groups: z.array(z.number()).optional(),
      uid_map: z.string().optional(),
      gid_map: z.string().optional(),
      thread_count: z.number().optional(),
      user_ns: z.string().optional(),
      mount_ns: z.string().optional(),
      groups_before_error: z.string().optional(),
      groups_after_error: z.string().optional(),
      mount_first_error: z.string().optional(),
    })
    .strict(),
  preload: z
    .object({
      version: z.string().optional(),
      prefix: z.string().optional(),
      modules: z.array(z.string()).max(128).optional(),
      thread_count: z.number().optional(),
      host_pid: z.number().optional(),
      host_start_ticks: decimal.optional(),
      run_token: z.string().optional(),
      executable_device: decimal.optional(),
      executable_inode: decimal.optional(),
    })
    .strict(),
  generations: z.strictObject({
    before: z
      .strictObject({ helper: generation, prepared: generation })
      .optional(),
    after: z
      .strictObject({ helper: generation, prepared: generation })
      .optional(),
  }),
  error: z.strictObject({ kind: z.string(), message: z.string() }).optional(),
  cleanup_errors: z
    .array(z.strictObject({ fd: z.number(), reason: z.string() }))
    .max(32)
    .optional(),
});
export type PodmanMetadataResponse = z.infer<typeof responseSchema>;
export interface PodmanMetadataExecutionContext {
  readonly limiter: string;
  readonly cwd: string;
  readonly environment: Readonly<Record<string, string>>;
  retainOwner(owner: { path: string; close(): Promise<void> }): void;
  retainObservation?(observation: unknown): void;
}
const same = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
const demand: (condition: unknown, reason: string) => asserts condition = (
  condition,
  reason,
) => {
  if (!condition) throw podmanProfileUnavailable(reason);
};
/** Fixed executable operand and exact admitted packaged bytes, never a post-entry helper pathname. */
export const podmanMetadataArguments = (code: string): readonly string[] => [
  "-I",
  "-S",
  "-X",
  "utf8",
  "-c",
  code,
];
export const admitPodmanMetadataArguments = (
  actual: readonly string[],
  code: string,
) => {
  demand(
    Buffer.byteLength(code) <= 65536 && !code.includes("\0"),
    "Fixed metadata helper exceeds its64KiB code representation budget",
  );
  demand(
    same(actual, ["-I", "-S", "-X", "utf8", "-c", code]),
    "Actual metadata interpreter arguments differ from admitted fixed bytes",
  );
};

/** One metadata subprocess/descriptor bundle, retained before any effects and closed before dependent CID roots. */
export const observePodmanNamespaceMetadata = async (context: {
  store: PodmanExistingStoreProfile;
  identity: PodmanContainerIdentity;
  selection: PodmanCreateSelection;
  signal: AbortSignal;
  scope: ArtifactResourceScope;
  execution: PodmanMetadataExecutionContext;
}) => {
  const { store, identity, selection, scope, execution } = context;
  const timeout = AbortSignal.timeout(10000);
  const signal = AbortSignal.any([context.signal, timeout]);
  const handles: {
    file: FileHandle;
    owner: OwnedFileHandle;
    resource: string;
  }[] = [];
  const pending = new Set<ProviderProcessSupervisor>();
  let observation: unknown;
  let primary: unknown;
  let captured: AnalysisCapturedOutput | undefined;
  let launched:
    | { readonly pid: number; readonly run_token: string }
    | undefined;
  const bundle = {
    path: `${execution.cwd}/metadata-observer`,
    close: async () => {
      for (const process of [...pending]) {
        const result = await process.stop();
        if (result.status !== "incomplete") pending.delete(process);
      }
      if (pending.size !== 0)
        throw Error("Metadata helper process cleanup remains pending");
      const failures: unknown[] = [];
      for (const entry of [...handles].reverse()) {
        try {
          await entry.owner.close();
          handles.splice(handles.indexOf(entry), 1);
        } catch (cause) {
          failures.push(cause);
        }
      }
      if (failures.length !== 0)
        throw new AggregateError(
          failures,
          "Metadata descriptor cleanup remains pending",
        );
    },
  };
  execution.retainOwner(bundle);
  const scoped = {
    kind: "private-runtime-root" as const,
    resource: bundle.path,
    root: bundle,
  };
  const acquire = async (resource: string, flags: number) => {
    signal.throwIfAborted();
    const file = await open(resource, flags);
    handles.push({ file, owner: new OwnedFileHandle(file), resource });
    signal.throwIfAborted();
    return file;
  };
  try {
    demand(
      process.platform === "linux" && process.arch === "x64",
      "Namespace metadata requires the supported Linux x86_64 ABI",
    );
    const selected = store.metadata_observer;
    demand(
      selected !== undefined,
      "Explicit preloaded Python metadata observer selection is required",
    );
    demand(
      (await realpath(selected.command)) === selected.resolved_command,
      "Selected metadata interpreter resolved identity changed",
    );
    const helper = await observePodmanSharedHelper(store, signal, scope);
    const helperDirectory = await acquire(
      `/proc/${helper.pid}`,
      (1 << 21) | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const preparedDirectory = await acquire(
      `/proc/${identity.pid}`,
      (1 << 21) | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const user = await acquire(
      `/proc/self/fd/${helperDirectory.fd}/ns/user`,
      constants.O_RDONLY,
    );
    const mount = await acquire(
      `/proc/self/fd/${helperDirectory.fd}/ns/mnt`,
      constants.O_RDONLY,
    );
    const userStat = await user.stat({ bigint: true }),
      mountStat = await mount.stat({ bigint: true });
    const helperMap = async (name: "uid_map" | "gid_map") => {
      const file = await acquire(
        `/proc/self/fd/${helperDirectory.fd}/${name}`,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      const bytes = await readBoundedFileBytes(file, 65536, signal);
      demand(
        bytes !== undefined,
        "Selected helper credential map exceeds its metadata budget",
      );
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    };
    const helperUidMap = await helperMap("uid_map"),
      helperGidMap = await helperMap("gid_map");
    demand(
      `user:[${userStat.ino}]` === helper.user_ns &&
        `mnt:[${mountStat.ino}]` === helper.mount_ns,
      "Opened namespace FDs differ from helper generation",
    );
    const statFile = await acquire(
      `/proc/self/fd/${preparedDirectory.fd}/stat`,
      constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW,
    );
    const statBytes = await readBoundedFileBytes(statFile, 65536, signal);
    demand(
      statBytes !== undefined,
      "Anchored prepared stat exceeds its admission budget",
    );
    const prepared = {
      pid: identity.pid,
      start_ticks: statBytes.toString("utf8"),
      user_ns: await readlink(`/proc/self/fd/${preparedDirectory.fd}/ns/user`),
      mount_ns: await readlink(`/proc/self/fd/${preparedDirectory.fd}/ns/mnt`),
    };
    const start = parseLinuxProcessStartTime(prepared.start_ticks);
    demand(
      start !== undefined,
      "Prepared proc-directory generation is unreadable",
    );
    prepared.start_ticks = start;
    const python = await acquire(
      selected.resolved_command,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const pythonBefore = await python.stat({ bigint: true });
    demand(
      pythonBefore.isFile() && (Number(pythonBefore.mode) & 0o111) !== 0,
      "Selected interpreter is not a bounded regular executable",
    );
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(65536);
    for (;;) {
      signal.throwIfAborted();
      const result = await python.read(buffer, 0, buffer.length, null);
      signal.throwIfAborted();
      if (result.bytesRead === 0) break;
      hash.update(buffer.subarray(0, result.bytesRead));
    }
    demand(
      hash.digest("hex") === selected.sha256 &&
        sameRegularFileState(pythonBefore, await python.stat({ bigint: true })),
      "Same-FD metadata interpreter bytes/generation differ from selection",
    );
    const source = await observePodmanProfileFile(
      fileURLToPath(
        new URL(
          "../../../bridge/firmware/podman_namespace_metadata.py",
          import.meta.url,
        ),
      ),
      65536,
      signal,
      scope,
    );
    const code = new TextDecoder("utf-8", { fatal: true }).decode(source.bytes);
    const args = podmanMetadataArguments(code);
    admitPodmanMetadataArguments(args, code);
    const request = {
      protocol: "rea-podman-metadata-v1",
      id: identity.id,
      image_id: identity.image_id,
      graph_root: store.graph_root,
      run_root: store.run_root,
      image_root: identity.image_root,
      helper: {
        pid: helper.pid,
        start_ticks: helper.start_ticks,
        user_ns: helper.user_ns,
        mount_ns: helper.mount_ns,
      },
      prepared,
      namespaces: {
        user: {
          device: userStat.dev.toString(),
          inode: userStat.ino.toString(),
        },
        mount: {
          device: mountStat.dev.toString(),
          inode: mountStat.ino.toString(),
        },
      },
      roles: selection.mounts,
    };
    const input = Buffer.from(JSON.stringify(request));
    demand(
      input.length <= 16384,
      "Fixed metadata request exceeds its16KiB input budget",
    );
    demand(
      same(helper, await observePodmanSharedHelper(store, signal, scope)),
      "Helper generation changed before metadata launch",
    );
    const inheritedDescriptors = [
      user.fd,
      mount.fd,
      helperDirectory.fd,
      preparedDirectory.fd,
      python.fd,
    ];
    observation = {
      interpreter: {
        selected: selected.command,
        resolved: selected.resolved_command,
        sha256: selected.sha256,
      },
      code: source.identity,
      request,
    };
    execution.retainObservation?.(observation);
    const result = await runFirmwareCommand({
      engine: "podman",
      operation,
      command: "/proc/self/fd/7",
      limiter: execution.limiter,
      args,
      cwd: execution.cwd,
      environment: execution.environment,
      signal,
      limitProfile: "metadata-observer",
      protocolInput: input,
      inheritedDescriptors,
      acceptedExitCodes: [1],
      launcher: async (actual) => {
        demand(
          actual.command === execution.limiter &&
            actual.cwd === execution.cwd &&
            actual.signal === signal &&
            actual.expectedCommand === null &&
            actual.platform === undefined &&
            actual.memoryLimitBytes === undefined &&
            actual.windowsVerbatimArguments === undefined &&
            /^rea-firmware-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(
              actual.runId,
            ) &&
            same(actual.hostEnvironment, execution.environment) &&
            same(actual.env, {
              TMPDIR: execution.cwd,
              OMP_NUM_THREADS: "1",
              OPENBLAS_NUM_THREADS: "1",
              RAYON_NUM_THREADS: "1",
              NO_COLOR: "1",
            }) &&
            same(actual.arguments, [
              "--as=1073741824",
              "--fsize=1048576",
              "--core=0",
              "--cpu=5",
              "--",
              "/proc/self/fd/7",
              ...args,
            ]) &&
            same(actual.inheritedDescriptors, inheritedDescriptors) &&
            actual.stdin === "pipe",
          "Actual metadata launch lost fixed command/environment/limits/code/descriptor binding",
        );
        demand(
          actual.arguments.reduce(
            (bytes, argument) => bytes + Buffer.byteLength(argument) + 1,
            0,
          ) +
            Object.entries({
              ...execution.environment,
              ...actual.env,
              REA_PROCESS_RUN_ID: actual.runId,
            }).reduce(
              (bytes, [key, value]) =>
                bytes +
                Buffer.byteLength(key) +
                Buffer.byteLength(value ?? "") +
                2,
              0,
            ) <=
            98304,
          "Metadata argv/environment exceeds its96KiB representation budget",
        );
        demand(
          sameRegularFileState(
            pythonBefore,
            await python.stat({ bigint: true }),
          ),
          "Metadata interpreter generation changed immediately before execution",
        );
        const spawned = await spawnOwnedProviderProcess(actual);
        launched = {
          pid: spawned.ownership.leaderPid,
          run_token: spawned.ownership.runId,
        };
        return spawned;
      },
      retainCleanup: (process) => pending.add(process),
    });
    captured = result.captured_output;
    observation = { ...(observation as object), captured_output: captured };
    execution.retainObservation?.(observation);
    demand(
      result.stdout.utf8Valid === true && result.stdout.bytes <= 65536,
      "Metadata response is invalid UTF8 or exceeds its64KiB representation budget",
    );
    const response = responseSchema.parse(JSON.parse(result.stdout.text));
    observation = { ...(observation as object), response };
    execution.retainObservation?.(observation);
    demand(
      response.status === "verified" && result.exit_code === 0,
      `Namespace metadata observer refused: ${response.error?.message ?? "unknown native reason"}`,
    );
    const expectedGenerations = {
      helper: request.helper,
      prepared: request.prepared,
    };
    demand(
      same(response.generations.before, expectedGenerations) &&
        same(response.generations.after, expectedGenerations),
      "Metadata response generation brackets differ from anchored request",
    );
    demand(
      response.entry.uid === 0 &&
        response.entry.gid === 0 &&
        same(response.entry.groups, []) &&
        response.entry.user_ns === helper.user_ns &&
        response.entry.mount_ns === helper.mount_ns &&
        response.entry.thread_count === 1 &&
        response.preload.thread_count === 1 &&
        response.entry.uid_map === helperUidMap &&
        response.entry.gid_map === helperGidMap &&
        response.preload.host_pid === launched?.pid &&
        response.preload.run_token === launched?.run_token &&
        response.preload.host_start_ticks !== undefined &&
        response.preload.executable_device === pythonBefore.dev.toString() &&
        response.preload.executable_inode === pythonBefore.ino.toString(),
      "Metadata acquired host identity/credentials/single-thread readiness differ from fixed policy",
    );
    const roles = [
      "image",
      "hosts",
      "hostname",
      "containerenv",
      "shm",
      ...selection.mounts.map((mount) => mount.role),
    ];
    demand(
      same(
        response.pairs.map((value) => value.role),
        roles,
      ),
      "Metadata response omitted/added/duplicated fixed pair coverage",
    );
    const userdata = `${store.run_root}/overlay-containers/${identity.id}/userdata/`;
    const expectedPairs = [
      {
        role: "image",
        source: identity.image_root,
        destination: "/",
        directory: true,
      },
      {
        role: "hosts",
        source: `${userdata}hosts`,
        destination: "/etc/hosts",
        directory: false,
      },
      {
        role: "hostname",
        source: `${userdata}hostname`,
        destination: "/etc/hostname",
        directory: false,
      },
      {
        role: "containerenv",
        source: `${userdata}.containerenv`,
        destination: "/run/.containerenv",
        directory: false,
      },
      {
        role: "shm",
        source: `${store.graph_root}/overlay-containers/${identity.id}/userdata/shm`,
        destination: "/dev/shm",
        directory: true,
      },
      ...selection.mounts.map((value) => ({
        role: value.role,
        source: value.source,
        destination: `/rea-${value.role}`,
        directory: true,
      })),
    ];
    for (const [index, value] of response.pairs.entries())
      demand(
        same(
          {
            role: value.role,
            source: value.source,
            destination: value.destination,
            directory: value.directory,
          },
          expectedPairs[index],
        ) &&
          value.source_identity.directory === value.directory &&
          same(value.source_identity, value.target_identity),
        "Metadata reconstructed source map/type/descriptor correspondence differs",
      );
    demand(
      sameRegularFileState(pythonBefore, await python.stat({ bigint: true })) &&
        same(helper, await observePodmanSharedHelper(store, signal, scope)),
      "Metadata interpreter/helper generation changed after observation",
    );
    return { observation, response };
  } catch (cause) {
    primary =
      cause instanceof AnalysisError
        ? cause
        : signal.aborted
          ? new AnalysisCancelledError(operation, { cause })
          : new ProviderAdapterError("podman", operation, {
              cause,
              diagnostics: {
                reason: cause instanceof Error ? cause.message : String(cause),
              },
            });
    if (
      timeout.aborted &&
      !context.signal.aborted &&
      primary instanceof AnalysisError
    ) {
      const previous = primary;
      const deadlineError = new AnalysisTimeoutError(operation, 10000, {
        cause: previous,
      });
      primary = deadlineError;
      if (previous.capturedOutput !== undefined)
        deadlineError.retainCapturedOutput(previous.capturedOutput);
    }
    if (primary instanceof AnalysisError) {
      if (captured !== undefined) primary.retainCapturedOutput(captured);
      if (primary.capturedOutput !== undefined) {
        observation = {
          ...(observation as object),
          captured_output: primary.capturedOutput,
        };
        execution.retainObservation?.(observation);
      }
      primary.retainPartialObservation({
        kind: "firmware",
        result: jsonValueSchema.parse(observation ?? null),
      });
    }
    throw primary;
  } finally {
    const released = await scope.release(scoped);
    if (released.kind === "failed") {
      const failure = new ProviderCleanupError(
        "podman",
        handles.map((entry) => entry.resource),
        {
          reason: "Metadata process/descriptor owner remains retained",
          previous_error: primary instanceof Error ? primary.message : null,
          primary_error:
            primary instanceof AnalysisError
              ? projectAnalysisError(primary)
              : null,
          observation: jsonValueSchema.parse(observation ?? null),
        },
        { operation, cause: released.cause },
      );
      if (
        primary instanceof AnalysisError &&
        primary.capturedOutput !== undefined
      )
        failure.retainCapturedOutput(primary.capturedOutput);
      else if (captured !== undefined) failure.retainCapturedOutput(captured);
      failure.retainPartialObservation({
        kind: "firmware",
        result: jsonValueSchema.parse(observation ?? null),
      });
      throw failure;
    }
  }
};
