import { isAbsolute, join, dirname } from "node:path";
import { z } from "zod";

/** Supported storage semantics, not source attestation of an installed binary. */
export const PODMAN_SOURCE_SEMANTICS =
  "c593b672bf3db1173aebea565ebf1a724ea196dc";
export const podmanRepresentableString = z
  .string()
  .min(1)
  .regex(/^[^\u0000\uD800-\uDFFF]*$/u);
export const podmanAbsolutePath = podmanRepresentableString.refine(isAbsolute, {
  message: "An absolute local identity path is required",
});
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const identityNumber = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const uid = z.number().int().min(0);
const identityFields = {
  path: podmanAbsolutePath,
  device: identityNumber,
  inode: identityNumber,
  uid,
  gid: uid,
  mode: z.string().regex(/^0o[0-7]{3,4}$/u),
};
export const podmanDescriptorIdentitySchema = z.strictObject({
  ...identityFields,
  size: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  sha256: digest,
});
const helperSchema = z.strictObject({
  pid: z.number().int().positive(),
  start_ticks: identityNumber,
  uid,
  user_ns: z.string().regex(/^user:\[[0-9]+\]$/u),
  mount_ns: z.string().regex(/^mnt:\[[0-9]+\]$/u),
  pid_ns: z.string().regex(/^pid:\[[0-9]+\]$/u),
  executable: podmanAbsolutePath,
  pidfile: podmanAbsolutePath,
});
const profile = z.strictObject({
  profile: z.literal("podman-existing-store-v1"),
  podman: z.strictObject({
    command: podmanAbsolutePath,
    resolved_command: podmanAbsolutePath,
    sha256: digest,
    version: z.literal("5.8.7"),
    source_semantic_revision: z.literal(PODMAN_SOURCE_SEMANTICS),
    binary_source_attestation: z.literal("unknown"),
  }),
  rootless_uid: uid.positive(),
  runtime_directory: podmanAbsolutePath,
  graph_root: podmanAbsolutePath,
  run_root: podmanAbsolutePath,
  driver: z.literal("overlay"),
  storage_options: z.strictObject({
    overlay_mountopt: podmanRepresentableString.optional(),
  }),
  static_dir: podmanAbsolutePath,
  tmp_dir: podmanAbsolutePath,
  volume_path: podmanAbsolutePath,
  database: z.strictObject({
    backend: z.literal("sqlite"),
    path: podmanAbsolutePath,
    initialized_compatible_version: z.literal("5.8.7"),
    assertion_authority: podmanRepresentableString,
  }),
  configuration_provenance: z
    .array(
      z.strictObject({
        ...podmanDescriptorIdentitySchema.shape,
        role: z.enum(["storage", "containers"]),
      }),
    )
    .length(2),
  directory_identities: z.array(z.strictObject(identityFields)).min(6).max(32),
  initialization_receipt: z.strictObject({
    path: podmanAbsolutePath,
    sha256: digest,
  }),
  native_metadata_observation: z.strictObject({
    observed_at_unix: z.number().nonnegative(),
    semantics: podmanRepresentableString,
    files: z.array(podmanDescriptorIdentitySchema).length(9),
  }),
  shared_helper: helperSchema,
});

/** Closed bootstrap selection: every required association exists before any transport. */
export const podmanExistingStoreProfileSchema = profile.superRefine(
  (selected, context) => {
    const refuse = (message: string) =>
      context.addIssue({ code: "custom", message });
    const roots = [
      selected.graph_root,
      selected.run_root,
      selected.static_dir,
      selected.tmp_dir,
      selected.volume_path,
      selected.runtime_directory,
    ];
    const directories = new Map(
      selected.directory_identities.map((entry) => [entry.path, entry]),
    );
    if (
      directories.size !== selected.directory_identities.length ||
      roots.some((path) => !directories.has(path))
    )
      refuse(
        "Every selected root requires a unique explicit directory identity",
      );
    if (roots.some((path) => dirname(path) === path))
      refuse("Filesystem root is not a storage or runtime directory");
    if (new Set(roots).size !== roots.length)
      refuse("Store roots and runtime directory must be distinct");
    if (
      selected.directory_identities.some(
        (entry) => entry.uid !== selected.rootless_uid,
      )
    )
      refuse("Directory identity owner must match the selected rootless UID");
    if (selected.database.path !== join(selected.static_dir, "db.sql"))
      refuse(
        "The explicit static-directory SQLite branch must own the selected database",
      );
    if (
      new Set(selected.configuration_provenance.map((entry) => entry.role))
        .size !== 2 ||
      new Set(selected.configuration_provenance.map((entry) => entry.path))
        .size !== 2
    )
      refuse(
        "One distinct storage and containers configuration provenance is required",
      );
    const expectedMetadata = new Set([
      selected.database.path,
      ...[
        "storage.lock",
        "userns.lock",
        "overlay-images/images.json",
        "overlay-images/images.lock",
        "overlay-containers/containers.json",
        "overlay-containers/containers.lock",
        "overlay-layers/layers.json",
        "overlay-layers/layers.lock",
      ].map((path) => join(selected.graph_root, path)),
    ]);
    const actualMetadata = new Set(
      selected.native_metadata_observation.files.map((entry) => entry.path),
    );
    if (
      actualMetadata.size !== expectedMetadata.size ||
      [...actualMetadata].some((path) => !expectedMetadata.has(path))
    )
      refuse(
        "Initialized native metadata must bind the exact supported store branch",
      );
    if (
      selected.shared_helper.uid !== selected.rootless_uid ||
      selected.shared_helper.pidfile !==
        join(selected.runtime_directory, "libpod", "tmp", "pause.pid")
    )
      refuse(
        "The shared helper association must bind the selected per-user runtime directory",
      );
  },
);
export type PodmanExistingStoreProfile = z.infer<
  typeof podmanExistingStoreProfileSchema
>;
export type PodmanDescriptorIdentity = z.infer<
  typeof podmanDescriptorIdentitySchema
>;
