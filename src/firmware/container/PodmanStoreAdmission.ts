import { constants } from "node:fs";
import { access, realpath } from "node:fs/promises";
import { parse as parseToml } from "smol-toml";
import { z } from "zod";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { firmwareFailure } from "../FirmwareFailures.js";
import {
  podmanExistingStoreProfileSchema,
  type PodmanDescriptorIdentity,
  type PodmanExistingStoreProfile,
} from "./PodmanStoreProfile.js";
import {
  decodePodmanProfileText,
  identifyPodmanProfileFile,
  observePodmanProfileDirectory,
  observePodmanProfileFile,
  podmanProfileUnavailable,
} from "./PodmanProfileFiles.js";
import { observePodmanSharedHelper } from "./PodmanSharedHelper.js";
import { observePodmanDatabase } from "./PodmanDatabase.js";

const storageConfig = z.strictObject({
  storage: z.strictObject({
    driver: z.literal("overlay"),
    graphroot: z.string(),
    runroot: z.string(),
    options: z
      .strictObject({
        overlay: z.strictObject({ mountopt: z.string().optional() }).optional(),
      })
      .optional(),
  }),
});
const containersConfig = z.object({
  engine: z.object({
    database_backend: z.literal("sqlite"),
    static_dir: z.string(),
    tmp_dir: z.string(),
    volume_path: z.string(),
  }),
});
const identityMatches = (
  actual: PodmanDescriptorIdentity,
  expected: PodmanDescriptorIdentity,
) =>
  Object.entries(expected).every(
    ([key, value]) =>
      key === "role" || actual[key as keyof PodmanDescriptorIdentity] === value,
  );
const freezeSelection = <T>(value: T): T => {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freezeSelection(child);
    Object.freeze(value);
  }
  return value;
};

/** Stable selectors and a fresh, timestamped observation of mutable native metadata. */
export interface PodmanStoreObservation {
  readonly executable: PodmanDescriptorIdentity;
  readonly configuration: readonly PodmanDescriptorIdentity[];
  readonly native_metadata: {
    readonly observed_at_unix: number;
    readonly semantics: "current runtime-mutating metadata; historical hashes are not pins";
    readonly files: readonly PodmanDescriptorIdentity[];
  };
  readonly shared_helper: Awaited<ReturnType<typeof observePodmanSharedHelper>>;
  readonly database: Awaited<ReturnType<typeof observePodmanDatabase>>;
}

/** Nominal admission result: construction is confined to the pre-transport profile owner. */
export class AdmittedPodmanStore {
  readonly #profile: PodmanExistingStoreProfile;
  readonly profile_identity: PodmanDescriptorIdentity;
  private constructor(
    profile: PodmanExistingStoreProfile,
    identity: PodmanDescriptorIdentity,
  ) {
    this.#profile = freezeSelection(profile);
    this.profile_identity = freezeSelection(identity);
  }
  get selection(): PodmanExistingStoreProfile {
    return this.#profile;
  }

  static async admit(
    profilePath: string,
    command: string,
    signal: AbortSignal,
    scope: ArtifactResourceScope,
  ): Promise<AdmittedPodmanStore> {
    try {
      signal.throwIfAborted();
      if (process.platform !== "linux" || process.getuid === undefined)
        throw podmanProfileUnavailable(
          "The selected Podman bootstrap profile requires Linux rootless identity observation",
        );
      const descriptor = await observePodmanProfileFile(
        profilePath,
        1024 * 1024,
        signal,
        scope,
      );
      let profile: PodmanExistingStoreProfile;
      try {
        profile = podmanExistingStoreProfileSchema.parse(
          JSON.parse(decodePodmanProfileText(descriptor.bytes)),
        );
      } catch (cause: unknown) {
        if (cause instanceof AnalysisError) throw cause;
        throw podmanProfileUnavailable(
          "Selected existing-store profile is not complete supported JSON",
        );
      }
      if (
        command !== profile.podman.command ||
        process.getuid() !== profile.rootless_uid ||
        descriptor.identity.uid !== profile.rootless_uid
      )
        throw podmanProfileUnavailable(
          "Selected command/profile owner must match the explicit rootless identity",
        );
      const admitted = new AdmittedPodmanStore(profile, descriptor.identity);
      await admitted.recheck(signal, scope);
      return admitted;
    } catch (cause: unknown) {
      if (cause instanceof ArtifactReaderFailure)
        throw firmwareFailure(cause, "podman", "firmware_container_runtime");
      if (cause instanceof AnalysisError) throw cause;
      if (signal.aborted && cause === signal.reason)
        throw new AnalysisCancelledError("firmware_container_runtime", {
          cause,
        });
      throw podmanProfileUnavailable(
        `Selected existing-store profile admission failed: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );
    }
  }

  /** Rechecks stable identities, accepting newly observed legitimate DB/index transactions. */
  async recheck(
    signal: AbortSignal,
    scope: ArtifactResourceScope,
  ): Promise<PodmanStoreObservation> {
    try {
      signal.throwIfAborted();
      const selected = this.#profile;
      const currentProfile = await identifyPodmanProfileFile(
        this.profile_identity.path,
        signal,
        scope,
      );
      if (!identityMatches(currentProfile, this.profile_identity))
        throw podmanProfileUnavailable(
          "Selected profile identity changed after admission",
        );
      if (
        (await realpath(selected.podman.command)) !==
        selected.podman.resolved_command
      )
        throw podmanProfileUnavailable(
          "The selected Podman executable resolution changed",
        );
      const executable = await identifyPodmanProfileFile(
        selected.podman.resolved_command,
        signal,
        scope,
      );
      if (executable.sha256 !== selected.podman.sha256)
        throw podmanProfileUnavailable(
          "The selected Podman executable bytes changed",
        );
      await access(selected.podman.resolved_command, constants.X_OK);
      for (const expected of selected.directory_identities) {
        const current = await observePodmanProfileDirectory(
          expected.path,
          signal,
          scope,
        );
        if (
          Object.entries(expected).some(
            ([key, value]) => current[key as keyof typeof current] !== value,
          )
        )
          throw podmanProfileUnavailable(
            `Selected existing directory identity changed: ${expected.path}`,
          );
      }
      const configuration: PodmanDescriptorIdentity[] = [];
      for (const expected of selected.configuration_provenance) {
        const current = await observePodmanProfileFile(
          expected.path,
          1024 * 1024,
          signal,
          scope,
        );
        if (!identityMatches(current.identity, expected))
          throw podmanProfileUnavailable(
            `Selected configuration provenance changed: ${expected.path}`,
          );
        let parsed: unknown;
        try {
          parsed = parseToml(decodePodmanProfileText(current.bytes));
        } catch (cause: unknown) {
          if (cause instanceof AnalysisError) throw cause;
          throw podmanProfileUnavailable(
            "Selected configuration is not complete TOML",
          );
        }
        if (expected.role === "storage") {
          const result = storageConfig.safeParse(parsed);
          if (
            !result.success ||
            result.data.storage.graphroot !== selected.graph_root ||
            result.data.storage.runroot !== selected.run_root ||
            result.data.storage.options?.overlay?.mountopt !==
              selected.storage_options.overlay_mountopt
          )
            throw podmanProfileUnavailable(
              "Storage configuration does not bind the complete selected native-overlay roots/options",
            );
        } else {
          const result = containersConfig.safeParse(parsed);
          if (
            !result.success ||
            result.data.engine.static_dir !== selected.static_dir ||
            result.data.engine.tmp_dir !== selected.tmp_dir ||
            result.data.engine.volume_path !== selected.volume_path
          )
            throw podmanProfileUnavailable(
              "Containers configuration does not bind the explicit initialized SQLite branch",
            );
        }
        configuration.push(current.identity);
      }
      const receipt = await observePodmanProfileFile(
        selected.initialization_receipt.path,
        8 * 1024 * 1024,
        signal,
        scope,
      );
      if (
        receipt.identity.sha256 !== selected.initialization_receipt.sha256 ||
        receipt.identity.uid !== selected.rootless_uid
      )
        throw podmanProfileUnavailable(
          "The selected initialization receipt identity changed",
        );
      // This is operator/probe provenance, never independent binary or database attestation.
      try {
        JSON.parse(decodePodmanProfileText(receipt.bytes));
      } catch (cause: unknown) {
        if (cause instanceof AnalysisError) throw cause;
        throw podmanProfileUnavailable(
          "Selected initialization receipt is not complete JSON",
        );
      }
      const database = await observePodmanDatabase(selected, signal, scope);
      const files: PodmanDescriptorIdentity[] = [];
      for (const expected of selected.native_metadata_observation.files) {
        const current =
          expected.path === selected.database.path
            ? database.source
            : await identifyPodmanProfileFile(expected.path, signal, scope);
        if (
          current.uid !== selected.rootless_uid ||
          (current.path === selected.database.path && current.size === 0)
        )
          throw podmanProfileUnavailable(
            "The explicit initialized native metadata branch is absent or has another owner",
          );
        files.push(current);
      }
      const shared_helper = await observePodmanSharedHelper(
        selected,
        signal,
        scope,
      );
      signal.throwIfAborted();
      return {
        executable,
        configuration,
        native_metadata: {
          observed_at_unix: Date.now() / 1000,
          semantics:
            "current runtime-mutating metadata; historical hashes are not pins",
          files,
        },
        shared_helper,
        database,
      };
    } catch (cause: unknown) {
      if (cause instanceof ArtifactReaderFailure)
        throw firmwareFailure(cause, "podman", "firmware_container_runtime");
      if (cause instanceof AnalysisError) throw cause;
      if (signal.aborted && cause === signal.reason)
        throw new AnalysisCancelledError("firmware_container_runtime", {
          cause,
        });
      throw podmanProfileUnavailable(
        `Existing store admission failed: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      );
    }
  }
}

export const admitPodmanStore = AdmittedPodmanStore.admit;
