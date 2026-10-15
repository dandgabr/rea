import { expect, it } from "vitest";
import { podmanExistingStoreProfileSchema } from "./PodmanStoreProfile.js";

const file = (path: string) => ({
  path,
  device: "1",
  inode: "2",
  uid: 1000,
  gid: 1000,
  mode: "0o600",
  size: 1,
  sha256: "a".repeat(64),
});
export const selectedStore = () => ({
  profile: "podman-existing-store-v1",
  podman: {
    command: "/usr/bin/podman",
    resolved_command: "/usr/bin/podman",
    sha256: "a".repeat(64),
    version: "5.8.7",
    source_semantic_revision: "c593b672bf3db1173aebea565ebf1a724ea196dc",
    binary_source_attestation: "unknown",
  },
  rootless_uid: 1000,
  runtime_directory: "/run/user/1000",
  graph_root: "/fixture/graph",
  run_root: "/fixture/run",
  driver: "overlay",
  storage_options: { overlay_mountopt: "nodev" },
  static_dir: "/fixture/static",
  tmp_dir: "/fixture/tmp",
  volume_path: "/fixture/volumes",
  database: {
    backend: "sqlite",
    path: "/fixture/static/db.sql",
    initialized_compatible_version: "5.8.7",
    assertion_authority:
      "operator-selected initialization receipt; no database attestation",
  },
  configuration_provenance: [
    { ...file("/fixture/storage.conf"), role: "storage" },
    { ...file("/fixture/containers.conf"), role: "containers" },
  ],
  directory_identities: [
    "/fixture",
    "/fixture/graph",
    "/fixture/run",
    "/fixture/static",
    "/fixture/tmp",
    "/fixture/volumes",
    "/run/user/1000",
  ].map((path) => ({
    path,
    device: "1",
    inode: "2",
    uid: 1000,
    gid: 1000,
    mode: "0o700",
  })),
  initialization_receipt: {
    path: "/fixture/receipt.json",
    sha256: "a".repeat(64),
  },
  native_metadata_observation: {
    observed_at_unix: 1,
    semantics: "timestamped runtime-mutating observations",
    files: [
      file("/fixture/static/db.sql"),
      ...[
        "storage.lock",
        "userns.lock",
        "overlay-images/images.json",
        "overlay-images/images.lock",
        "overlay-containers/containers.json",
        "overlay-containers/containers.lock",
        "overlay-layers/layers.json",
        "overlay-layers/layers.lock",
      ].map((path) => file(`/fixture/graph/${path}`)),
    ],
  },
  shared_helper: {
    pid: 123,
    start_ticks: "456",
    uid: 1000,
    user_ns: "user:[1]",
    mount_ns: "mnt:[2]",
    pid_ns: "pid:[3]",
    executable: "/usr/libexec/catatonit/catatonit",
    pidfile: "/run/user/1000/libpod/tmp/pause.pid",
  },
});

it("preserves deliberately empty or exact typed native-overlay options and historical metadata selection", () => {
  expect(
    podmanExistingStoreProfileSchema.parse(selectedStore()).storage_options,
  ).toEqual({ overlay_mountopt: "nodev" });
  expect(
    podmanExistingStoreProfileSchema.parse({
      ...selectedStore(),
      storage_options: {},
    }).storage_options,
  ).toEqual({});
});
it("rejects incomplete bootstrap, unknown keys, unsupported helpers/options and unrepresentable selectors before any transport", () => {
  const valid = selectedStore();
  const invalid: unknown[] = [
    { ...valid, profile: "podman-default-store" },
    { ...valid, driver: "vfs" },
    { ...valid, rootless_uid: 0 },
    { ...valid, arbitrary_argv: ["--privileged"] },
    { ...valid, initialization_receipt: undefined },
    {
      ...valid,
      native_metadata_observation: {
        ...valid.native_metadata_observation,
        files: [],
      },
    },
    { ...valid, directory_identities: [] },
    { ...valid, configuration_provenance: [] },
    { ...valid, shared_helper: { ...valid.shared_helper, pid: 0 } },
    { ...valid, storage_options: { mount_program: "/usr/bin/fuse-overlayfs" } },
    { ...valid, storage_options: { overlay_mountopt: "nodev\0rw" } },
    { ...valid, storage_options: { overlay_mountopt: "nodev\ud800" } },
    { ...valid, podman: { ...valid.podman, version: "5.8.8" } },
    { ...valid, runtime_directory: "/run/user/other\udfff" },
    { ...valid, database: { ...valid.database, path: "/unrelated/db.sql" } },
    {
      ...valid,
      configuration_provenance: [
        valid.configuration_provenance[0],
        valid.configuration_provenance[0],
      ],
    },
    {
      ...valid,
      native_metadata_observation: {
        ...valid.native_metadata_observation,
        files: [
          ...valid.native_metadata_observation.files,
          file("/etc/unrelated"),
        ],
      },
    },
  ];
  for (const input of invalid)
    expect(
      podmanExistingStoreProfileSchema.safeParse(input).success,
      JSON.stringify(input),
    ).toBe(false);
});

it("admits explicit pinned preloaded metadata interpreter without making it bootstrap-mandatory", () => {
  const metadata_observer = {
    kind: "python-preloaded-v1",
    command: "/usr/bin/python3",
    resolved_command: "/usr/bin/python3.14",
    sha256: "a".repeat(64),
    version: "3.14.8",
  };
  expect(
    podmanExistingStoreProfileSchema.parse(selectedStore()).metadata_observer,
  ).toBeUndefined();
  expect(
    podmanExistingStoreProfileSchema.parse({
      ...selectedStore(),
      metadata_observer,
    }).metadata_observer,
  ).toEqual(metadata_observer);
  for (const change of [
    { kind: "arbitrary" },
    { version: "3.11" },
    { sha256: "x" },
    { args: ["-c", "code"] },
  ])
    expect(
      podmanExistingStoreProfileSchema.safeParse({
        ...selectedStore(),
        metadata_observer: { ...metadata_observer, ...change },
      }).success,
    ).toBe(false);
});
