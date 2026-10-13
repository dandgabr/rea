import { access, mkdir, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { join } from "node:path";
import { stringify as stringifyToml } from "smol-toml";
import { z } from "zod";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import { randomUUID } from "node:crypto";
import {
  admitPodmanExistingProgram,
  admitExistingPodmanProgramArguments,
  existingPodmanProgramArguments,
  type PodmanExistingProgramSelection,
} from "./PodmanFixedProgram.js";
import {
  runFirmwareCommand,
  type FirmwareLauncher,
} from "../FirmwareCommand.js";
import {
  admitPodmanStore,
  type AdmittedPodmanStore,
  type PodmanStoreObservation,
} from "./PodmanStoreAdmission.js";
import {
  identifyPodmanProfileFile,
  podmanProfileUnavailable,
} from "./PodmanProfileFiles.js";
import { launchPodmanDirectClient } from "./PodmanClientCleanup.js";
import type { PodmanDescriptorIdentity } from "./PodmanStoreProfile.js";
import { observePodmanSharedHelper } from "./PodmanSharedHelper.js";

// Podman c593b672 vendor/go.podman.io/image/v5/docker/reference grammar:
// names <=255 ASCII bytes, optional native tag <=128, immutable lowercase SHA256.
const domainComponent = "(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])";
const imageComponent = "[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*";
const namedImage = new RegExp(
  `^((?:${domainComponent}(?:\\.${domainComponent})*(?::[0-9]+)?/)?${imageComponent}(?:/${imageComponent})*)(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})?@sha256:[a-f0-9]{64}$`,
  "u",
);
export const podmanImmutableImageSchema = z
  .string()
  .max(456)
  .refine((value) => {
    if (/^sha256:[a-f0-9]{64}$/u.test(value)) return true;
    const parsed = namedImage.exec(value);
    return parsed !== null && parsed[1]!.length <= 255;
  });

/** Existing-service metadata excludes caller environment/configuration materialization. */
export const PODMAN_EXISTING_GENERATION_FORMAT =
  '--format=[{"Id":{{json .ID}},"Image":{{json .Image}},"State":{"Running":{{json .State.Running}},"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}}}]';
export const podmanExistingGenerationCommand = (
  containerId: string,
): readonly string[] =>
  Object.freeze([
    "inspect",
    PODMAN_EXISTING_GENERATION_FORMAT,
    "--",
    containerId,
  ]);

/** Only fixed currently supported protocols are admitted; operands always follow '--'. */
const podmanCommandSchema = z.union([
  z.tuple([z.literal("info"), z.literal("--format=json")]),
  z.tuple([z.literal("--version")]),
  z.tuple([
    z.literal("image"),
    z.literal("inspect"),
    z.literal("--format=json"),
    z.literal("--"),
    podmanImmutableImageSchema,
  ]),
  z.tuple([
    z.literal("inspect"),
    z.literal("--format=json"),
    z.literal("--"),
    z.string().regex(/^[a-f0-9]{64}$/u),
  ]),
  z.tuple([
    z.literal("inspect"),
    z.literal(PODMAN_EXISTING_GENERATION_FORMAT),
    z.literal("--"),
    z.string().regex(/^[a-f0-9]{64}$/u),
  ]),
]);
const infoSchema = z.object({
  host: z.object({ security: z.object({ rootless: z.literal(true) }) }),
  store: z.object({
    graphDriverName: z.literal("overlay"),
    graphRoot: z.string(),
    runRoot: z.string(),
    volumePath: z.string(),
    configFile: z.string(),
    graphOptions: z.record(z.string(), z.string()),
    graphStatus: z.object({ "Native Overlay Diff": z.literal("true") }),
  }),
  version: z.object({ Version: z.literal("5.8.7") }),
});

/** Immutable selectors used by every client command, recovery and discovery. */
export const podmanStoreArguments = (
  store: AdmittedPodmanStore,
  hooks: string,
): readonly string[] =>
  Object.freeze([
    "--remote=false",
    "--root",
    store.selection.graph_root,
    "--runroot",
    store.selection.run_root,
    "--storage-driver=overlay",
    ...(store.selection.storage_options.overlay_mountopt === undefined
      ? []
      : [
          `--storage-opt=overlay.mountopt=${store.selection.storage_options.overlay_mountopt}`,
        ]),
    "--hooks-dir",
    hooks,
  ]);

/** Format-aware admission of the actual invocation, independent of its argv builder. */
export const admitPodmanInvocationSelectors = (
  argv: readonly string[],
  store: AdmittedPodmanStore,
  hooks: string,
  expectedCommand?: readonly string[],
  existingProgram?: PodmanExistingProgramSelection,
): void => {
  const seen = new Map<string, string>();
  let index = 0;
  for (; index < argv.length; index++) {
    const value = argv[index]!;
    let key: string;
    let setting: string;
    if (
      value === "--root" ||
      value === "--runroot" ||
      value === "--hooks-dir"
    ) {
      key = value;
      setting = argv[++index] ?? "";
    } else if (
      value.startsWith("--remote=") ||
      value.startsWith("--storage-driver=") ||
      value.startsWith("--storage-opt=")
    ) {
      const equal = value.indexOf("=");
      key = value.slice(0, equal);
      setting = value.slice(equal + 1);
    } else break;
    if (seen.has(key))
      throw podmanProfileUnavailable(
        "Duplicate selected transport selector before spawn",
      );
    seen.set(key, setting);
  }
  const command =
    existingProgram === undefined
      ? podmanCommandSchema.safeParse(argv.slice(index))
      : { success: true as const, data: argv.slice(index) };
  if (existingProgram !== undefined)
    admitExistingPodmanProgramArguments(command.data ?? [], existingProgram);
  if (!command.success)
    throw podmanProfileUnavailable(
      "Actual prepared command has unsupported flags, missing operand delimiter or invalid positional identity before spawn",
    );
  if (
    expectedCommand !== undefined &&
    JSON.stringify(command.data) !== JSON.stringify(expectedCommand)
  )
    throw podmanProfileUnavailable(
      "Actual prepared command changed the selected operation or positional identity before spawn",
    );
  const p = store.selection;
  if (
    seen.get("--remote") !== "false" ||
    seen.get("--root") !== p.graph_root ||
    seen.get("--runroot") !== p.run_root ||
    seen.get("--storage-driver") !== p.driver ||
    seen.get("--hooks-dir") !== hooks ||
    (p.storage_options.overlay_mountopt === undefined
      ? seen.has("--storage-opt")
      : seen.get("--storage-opt") !==
        `overlay.mountopt=${p.storage_options.overlay_mountopt}`)
  )
    throw podmanProfileUnavailable(
      "Actual transport omitted or changed a selected store selector before spawn",
    );
};

/** The generic owner runs fixed adapter protocols, never public raw-argv or ambient Podman defaults. */
export class PreparedPodmanTransport {
  readonly #store: AdmittedPodmanStore;
  readonly #root: PrivateRuntimeRoot;
  readonly #scope: ArtifactResourceScope;
  readonly #launcher: FirmwareLauncher;
  readonly #pending = new Set<ProviderProcessSupervisor>();
  readonly #arguments: readonly string[];
  readonly #environment: Readonly<Record<string, string>>;
  readonly #files: PodmanDescriptorIdentity[] = [];
  readonly #limiter: PodmanDescriptorIdentity;
  #closed = false;
  #boundaryUnverified = false;
  #metadataVerified = false;
  private constructor(
    store: AdmittedPodmanStore,
    root: PrivateRuntimeRoot,
    scope: ArtifactResourceScope,
    limiter: PodmanDescriptorIdentity,
    launcher: FirmwareLauncher,
  ) {
    this.#store = store;
    this.#root = root;
    this.#scope = scope;
    this.#limiter = limiter;
    this.#launcher = launcher;
    this.#arguments = podmanStoreArguments(store, join(root.path, "hooks"));
    this.#environment = Object.freeze({
      PATH: "/usr/local/bin:/usr/bin:/bin",
      HOME: join(root.path, "home"),
      XDG_CONFIG_HOME: join(root.path, "home/.config"),
      XDG_RUNTIME_DIR: store.selection.runtime_directory,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      REGISTRY_AUTH_FILE: join(root.path, "auth.json"),
      CONTAINERS_CONF: join(root.path, "containers.conf"),
      CONTAINERS_STORAGE_CONF: join(root.path, "storage.conf"),
      DBUS_SESSION_BUS_ADDRESS: `unix:path=${store.selection.runtime_directory}/bus`,
    });
  }
  get root_path(): string {
    return this.#root.path;
  }
  get store(): AdmittedPodmanStore {
    return this.#store;
  }
  get arguments(): readonly string[] {
    return this.#arguments;
  }
  get environment(): Readonly<Record<string, string>> {
    return this.#environment;
  }

  static async prepare(context: {
    profile: string;
    command: string;
    limiter: string;
    signal: AbortSignal;
    scope: ArtifactResourceScope;
    launcher?: FirmwareLauncher;
  }): Promise<PreparedPodmanTransport> {
    const store = await admitPodmanStore(
      context.profile,
      context.command,
      context.signal,
      context.scope,
    );
    const limiter = await identifyPodmanProfileFile(
      context.limiter,
      context.signal,
      context.scope,
    );
    await access(context.limiter, constants.X_OK);
    const root = await PrivateRuntimeRoot.create({
      prefix: "rea-firmware-container-",
    });
    const transport = new PreparedPodmanTransport(
      store,
      root,
      context.scope,
      limiter,
      context.launcher ?? launchPodmanDirectClient,
    );
    try {
      await transport.#initialize(context.signal);
      return transport;
    } catch (cause: unknown) {
      const primary = preparationFailure(cause, context.signal);
      const released = await context.scope.release({
        kind: "private-runtime-root",
        resource: root.path,
        root,
      });
      if (released.kind === "failed") {
        const failure = new ProviderCleanupError(
          "podman",
          [root.path],
          {
            reason:
              "Private container transport setup failed and its owner remains pending",
            primary_error: projectAnalysisError(primary),
          },
          {
            operation: "firmware_container_runtime",
            cause: new AggregateError([primary, released.cause]),
          },
        );
        if (primary.capturedOutput !== undefined)
          failure.retainCapturedOutput(primary.capturedOutput);
        if (primary.partialObservation !== undefined)
          failure.retainPartialObservation(primary.partialObservation);
        throw failure;
      }
      throw primary;
    }
  }

  async #initialize(signal: AbortSignal): Promise<void> {
    const p = this.#store.selection;
    const root = this.#root.path;
    for (const path of [
      "hooks",
      "home",
      "home/.config",
      "home/.config/containers",
      "image-tmp",
    ]) {
      signal.throwIfAborted();
      await mkdir(join(root, path), { mode: 0o700 });
    }
    const files: readonly [string, string][] = [
      ["home/.config/containers/mounts.conf", ""],
      ["auth.json", '{"auths":{}}\n'],
      [
        "storage.conf",
        stringifyToml({
          storage: {
            driver: "overlay",
            graphroot: p.graph_root,
            runroot: p.run_root,
            ...(p.storage_options.overlay_mountopt === undefined
              ? {}
              : {
                  options: {
                    overlay: { mountopt: p.storage_options.overlay_mountopt },
                  },
                }),
          },
        }),
      ],
      [
        "containers.conf",
        stringifyToml({
          containers: {
            mounts: [],
            volumes: [],
            devices: [],
            default_capabilities: [],
            env: [],
            env_host: false,
            http_proxy: false,
            pids_limit: -1,
            prepare_volume_on_create: false,
          },
          engine: {
            cgroup_manager: "systemd",
            database_backend: "sqlite",
            hooks_dir: [join(root, "hooks")],
            image_volume_mode: "ignore",
            static_dir: p.static_dir,
            tmp_dir: p.tmp_dir,
            volume_path: p.volume_path,
            image_copy_tmp_dir: join(root, "image-tmp"),
            events_logger: "none",
          },
        }),
      ],
    ];
    for (const [path, bytes] of files) {
      signal.throwIfAborted();
      const absolute = join(root, path);
      await writeFile(absolute, bytes, { mode: 0o600, flag: "wx" });
      this.#files.push(
        await identifyPodmanProfileFile(absolute, signal, this.#scope),
      );
    }
  }

  /** Adapter-only fixed command seam; exact selectors are asserted immediately before launch. */
  async run(args: readonly string[], signal: AbortSignal) {
    if (this.#closed)
      throw podmanProfileUnavailable("Prepared container transport is closed");
    const parsedCommand = podmanCommandSchema.safeParse(args);
    if (!parsedCommand.success)
      throw podmanProfileUnavailable(
        "Prepared command has unsupported flags, missing operand delimiter or invalid positional identity",
      );
    const command = Object.freeze(parsedCommand.data);
    const metadata = command[0] === "info";
    if (!this.#metadataVerified && !metadata)
      throw podmanProfileUnavailable(
        "The first prepared transport must verify the selected existing-store metadata before any version/image/container command",
      );
    const before = await this.#beforeInvocation(signal);
    let result: Awaited<ReturnType<typeof runFirmwareCommand>>;
    try {
      result = await runFirmwareCommand({
        engine: "podman",
        operation: "firmware_container_runtime",
        command: this.#store.selection.podman.resolved_command,
        limiter: this.#limiter.path,
        args: [...this.#arguments, ...command],
        cwd: this.#root.path,
        environment: this.#environment,
        signal,
        launcher: async (options) => {
          if (
            options.command !== this.#limiter.path ||
            options.arguments[0] !== "--core=0" ||
            options.arguments[1] !== "--cpu=120" ||
            options.arguments[2] !== "--" ||
            options.arguments[3] !==
              this.#store.selection.podman.resolved_command
          )
            throw podmanProfileUnavailable(
              "Actual host transport limiter policy changed before spawn",
            );
          admitPodmanInvocationSelectors(
            options.arguments.slice(4),
            this.#store,
            join(this.#root.path, "hooks"),
            command,
          );
          return this.#launcher(options);
        },
        limitProfile: "container-transport",
        retainCleanup: (owner) => this.#pending.add(owner),
      });
    } catch (cause: unknown) {
      await this.#confirmHelperAfterFailure(cause);
      throw cause;
    }
    let after: PodmanStoreObservation;
    try {
      after = await this.#store.recheck(signal, this.#scope);
    } catch (cause: unknown) {
      if (cause instanceof AnalysisError)
        cause.retainCapturedOutput(result.captured_output);
      await this.#confirmHelperAfterFailure(cause);
      throw cause;
    }
    if (metadata) {
      this.#admitMetadata(result);
      this.#metadataVerified = true;
    }
    return { ...result, store_before: before, store_after: after };
  }

  /** Reuse the exact admitted store/config/helper/limiter policy for every fixed invocation. */
  async #beforeInvocation(
    signal: AbortSignal,
  ): Promise<PodmanStoreObservation> {
    if (this.#closed)
      throw podmanProfileUnavailable("Prepared container transport is closed");
    const before = await this.#store.recheck(signal, this.#scope);
    const expected = podmanStoreArguments(
      this.#store,
      join(this.#root.path, "hooks"),
    );
    if (JSON.stringify(this.#arguments) !== JSON.stringify(expected))
      throw podmanProfileUnavailable(
        "Prepared transport omitted or changed a selected store selector before spawn",
      );
    for (const selected of [...this.#files, this.#limiter]) {
      const actual = await identifyPodmanProfileFile(
        selected.path,
        signal,
        this.#scope,
      );
      if (JSON.stringify(actual) !== JSON.stringify(selected))
        throw podmanProfileUnavailable(
          "Owned transport configuration/authentication or limiter identity changed before spawn",
        );
    }
    return before;
  }

  /** Fixed stdin protocol; the adapter owns namespace generation and producer cleanup separately. */
  async openExistingProgram(
    selection: PodmanExistingProgramSelection,
    signal: AbortSignal,
  ) {
    if (!this.#metadataVerified)
      throw podmanProfileUnavailable(
        "Existing execution requires first verified store metadata",
      );
    const admitted = admitPodmanExistingProgram(selection);
    const before = await this.#beforeInvocation(signal);
    const command = existingPodmanProgramArguments(admitted);
    const arguments_ = Object.freeze([
      "--core=0",
      "--cpu=120",
      "--",
      this.#store.selection.podman.resolved_command,
      ...this.#arguments,
      ...command,
    ]);
    const options = {
      command: this.#limiter.path,
      arguments: arguments_,
      runId: `rea-podman-protocol-${randomUUID()}`,
      expectedCommand: null,
      cwd: this.#root.path,
      hostEnvironment: this.#environment,
      stdin: "pipe" as const,
      signal,
    };
    // Bind the complete actual exec tuple, including namespace source/limiter/
    // token, independently of the builder. No synthetic metadata suffix stands
    // in for the operation that will actually be delivered.
    admitPodmanInvocationSelectors(
      [...this.#arguments, ...command],
      this.#store,
      join(this.#root.path, "hooks"),
      undefined,
      admitted,
    );
    const spawned = await this.#launcher(options);
    const supervisor = new ProviderProcessSupervisor(
      {
        ...spawned,
        ownsProcessLifetime: true,
        cleanup:
          spawned.cleanup ??
          (async () => ({
            cleaned: false as const,
            reason:
              "Fixed transport has no direct-client cleanup owner; group signaling is refused",
          })),
      },
      { captureStdout: false, maxDiagnosticBytes: 8 * 1024 * 1024 },
    );
    this.#pending.add(supervisor);
    if (spawned.process.stdin == null || spawned.process.stdout == null) {
      const stopped = await supervisor.stop();
      if (stopped.status !== "incomplete") this.#pending.delete(supervisor);
      throw podmanProfileUnavailable(
        "Fixed stdin protocol client lacks its owned binary streams",
      );
    }
    return {
      stdin: spawned.process.stdin,
      stdout: spawned.process.stdout,
      supervisor,
      arguments: arguments_,
      store_before: before,
      selected_container_id: admitted.containerId,
      selected_image_id: admitted.imageId,
      program: { name: admitted.program.name, sha256: admitted.program.sha256 },
      observeAfter: async (observationSignal: AbortSignal) =>
        this.#beforeInvocation(observationSignal),
    };
  }

  async #confirmHelperAfterFailure(primary: unknown): Promise<void> {
    try {
      await observePodmanSharedHelper(
        this.#store.selection,
        AbortSignal.timeout(30_000),
        this.#scope,
      );
    } catch (cause: unknown) {
      this.#boundaryUnverified = true;
      const failure = new ProviderCleanupError(
        "podman",
        [this.#root.path],
        {
          reason:
            "External helper association could not be observed after transport failure; private transport owner remains pending",
          primary_error:
            primary instanceof AnalysisError
              ? projectAnalysisError(primary)
              : {
                  reason:
                    primary instanceof Error
                      ? primary.message
                      : String(primary),
                },
        },
        {
          operation: "firmware_container_runtime",
          cause: new AggregateError(
            [primary, cause],
            "Transport failure and unresolved helper observation",
            { cause: primary },
          ),
        },
      );
      if (
        primary instanceof AnalysisError &&
        primary.capturedOutput !== undefined
      )
        failure.retainCapturedOutput(primary.capturedOutput);
      throw failure;
    }
  }

  #admitMetadata(info: Awaited<ReturnType<typeof runFirmwareCommand>>): void {
    let parsed: z.infer<typeof infoSchema>;
    try {
      if (info.stdout.utf8Valid !== true) throw new Error("invalid UTF-8");
      parsed = infoSchema.parse(JSON.parse(info.stdout.text));
    } catch {
      throw podmanProfileUnavailable(
        "Selected Podman info is not complete supported native-overlay metadata",
      ).retainCapturedOutput(info.captured_output);
    }
    const p = this.#store.selection;
    const options =
      p.storage_options.overlay_mountopt === undefined
        ? {}
        : { "overlay.mountopt": p.storage_options.overlay_mountopt };
    if (
      parsed.store.graphRoot !== p.graph_root ||
      parsed.store.runRoot !== p.run_root ||
      parsed.store.volumePath !== p.volume_path ||
      parsed.store.configFile !== this.#environment.CONTAINERS_STORAGE_CONF ||
      JSON.stringify(parsed.store.graphOptions) !== JSON.stringify(options)
    )
      throw podmanProfileUnavailable(
        "Observed runtime metadata changed the exact selected roots or complete native-overlay options",
      ).retainCapturedOutput(info.captured_output);
  }

  async probe(signal: AbortSignal): Promise<{
    version: Awaited<ReturnType<PreparedPodmanTransport["run"]>>;
    info: Awaited<ReturnType<PreparedPodmanTransport["run"]>>;
    store: PodmanStoreObservation;
  }> {
    const info = await this.run(["info", "--format=json"], signal);
    const version = await this.run(["--version"], signal);
    if (
      version.stdout.utf8Valid !== true ||
      version.stdout.text.trim() !== "podman version 5.8.7"
    )
      throw podmanProfileUnavailable(
        "Selected Podman observed version does not match the supported bootstrap profile",
      ).retainCapturedOutput(version.captured_output);
    return { version, info, store: version.store_after };
  }

  async image(reference: string, signal: AbortSignal) {
    if (!podmanImmutableImageSchema.safeParse(reference).success)
      throw podmanProfileUnavailable(
        "An immutable already-local image reference is required",
      );
    let result: Awaited<ReturnType<PreparedPodmanTransport["run"]>>;
    try {
      result = await this.run(
        ["image", "inspect", "--format=json", "--", reference],
        signal,
      );
    } catch (cause: unknown) {
      if (cause instanceof ProviderAdapterError && !cause.cleanupIncomplete) {
        const unavailable = podmanProfileUnavailable(
          "Selected immutable image is unavailable in the admitted local store; perform explicit setup separately",
        );
        if (cause.capturedOutput !== undefined)
          unavailable.retainCapturedOutput(cause.capturedOutput);
        throw unavailable;
      }
      throw cause;
    }
    try {
      if (result.stdout.utf8Valid !== true) throw new Error("invalid UTF-8");
      const parsed = z
        .array(
          z.object({
            Id: z.string().regex(/^(?:sha256:)?[a-f0-9]{64}$/u),
            Digest: z.string(),
            RepoDigests: z.array(z.string()).nullable(),
            Os: z.literal("linux"),
            Architecture: z.string(),
          }),
        )
        .length(1)
        .parse(JSON.parse(result.stdout.text))[0]!;
      if (
        reference.startsWith("sha256:")
          ? parsed.Id.replace(/^sha256:/u, "") !== reference.slice(7)
          : !parsed.RepoDigests?.includes(reference)
      )
        throw new Error("selected immutable reference differs");
      return {
        selected_reference: reference,
        image_id: parsed.Id.replace(/^sha256:/u, ""),
        registry_digest: parsed.Digest,
        repo_digests: parsed.RepoDigests,
        architecture: parsed.Architecture,
        os: parsed.Os,
        capture: result,
      };
    } catch (cause: unknown) {
      if (cause instanceof AnalysisError) throw cause;
      throw podmanProfileUnavailable(
        "Already-local image inspection does not establish the selected immutable identity",
      ).retainCapturedOutput(result.captured_output);
    }
  }

  async close(): Promise<void> {
    this.#closed = true;
    for (const owner of [...this.#pending]) {
      const stopped = await owner.stop();
      if (stopped.status !== "incomplete") this.#pending.delete(owner);
    }
    if (this.#pending.size > 0)
      throw new ProviderCleanupError(
        "podman",
        [this.#root.path],
        {
          reason:
            "Direct transport client cleanup remains pending; private configuration is retained",
        },
        { operation: "firmware_container_runtime" },
      );
    if (this.#boundaryUnverified) {
      try {
        await observePodmanSharedHelper(
          this.#store.selection,
          AbortSignal.timeout(30_000),
          this.#scope,
        );
        this.#boundaryUnverified = false;
      } catch (cause: unknown) {
        throw new ProviderCleanupError(
          "podman",
          [this.#root.path],
          {
            reason:
              "External helper observation remains unresolved; no helper was signaled and private configuration is retained",
          },
          { operation: "firmware_container_runtime", cause },
        );
      }
    }
    const released = await this.#scope.release({
      kind: "private-runtime-root",
      resource: this.#root.path,
      root: this.#root,
    });
    if (released.kind === "failed")
      throw new ProviderCleanupError(
        "podman",
        [this.#root.path],
        { reason: "Private transport root cleanup remains pending" },
        { operation: "firmware_container_runtime", cause: released.cause },
      );
  }
}

/** Normalize the producing setup boundary once; arbitrary causes are not public Evidence. */
const preparationFailure = (
  cause: unknown,
  signal: AbortSignal,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (signal.aborted && cause === signal.reason)
    return new AnalysisCancelledError("firmware_container_runtime", { cause });
  const systemField = (key: "code" | "path" | "syscall") =>
    cause instanceof Error &&
    key in cause &&
    typeof Reflect.get(cause, key) === "string"
      ? (Reflect.get(cause, key) as string)
      : null;
  return new ProviderAdapterError("podman", "firmware_container_runtime", {
    cause,
    diagnostics: {
      reason: `Private container transport preparation failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      system_code: systemField("code"),
      path: systemField("path"),
      syscall: systemField("syscall"),
    },
  });
};
