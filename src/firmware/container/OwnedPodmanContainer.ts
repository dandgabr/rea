import { join } from "node:path";
import { z } from "zod";
import { podmanFullContainerId } from "./PodmanLifecycleCommands.js";
import { podmanProfileUnavailable } from "./PodmanProfileFiles.js";

const inspectionSchema = z
  .array(
    z.object({
      Id: podmanFullContainerId,
      Image: z.string().regex(/^(?:sha256:)?[a-f0-9]{64}$/u),
      Created: z.string().refine((value) => Number.isFinite(Date.parse(value))),
      StaticDir: z.string().optional(),
      OCIConfigPath: z.string().optional(),
      Config: z.object({ Labels: z.record(z.string(), z.string()) }),
      GraphDriver: z
        .object({
          Name: z.literal("overlay"),
          Data: z.object({ MergedDir: z.string().optional() }).optional(),
        })
        .optional(),
      State: z.object({
        Status: z.enum([
          "configured",
          "created",
          "initialized",
          "running",
          "stopped",
          "exited",
        ]),
        Pid: z.number().int().nonnegative(),
        ConmonPid: z.number().int().nonnegative().optional(),
        Running: z.boolean(),
        ExitCode: z.number().int(),
      }),
    }),
  )
  .length(1);

/** Identity interpretation for read-only inspection, independent of stdout/CID discovery. */
export const admitPodmanContainerInspection = (
  value: unknown,
  expected: {
    id: string;
    image_id: string;
    token: string;
    graph_root: string;
    generation?: PodmanContainerIdentity;
    cleanup?: boolean;
  },
): PodmanContainerIdentity => {
  const record = inspectionSchema.parse(value)[0]!;
  const staticDir = join(
    expected.graph_root,
    "overlay-containers",
    expected.id,
    "userdata",
  );
  if (
    record.Id !== expected.id ||
    record.Image.replace(/^sha256:/u, "") !== expected.image_id ||
    record.Config.Labels["rea.firmware.owner"] !== expected.token ||
    (record.StaticDir !== undefined &&
      record.StaticDir !== "" &&
      record.StaticDir !== staticDir) ||
    (record.OCIConfigPath !== undefined &&
      record.OCIConfigPath !== "" &&
      record.OCIConfigPath !== join(staticDir, "config.json"))
  )
    throw podmanProfileUnavailable(
      "Observed container does not bind the exact acquiring token, full CID, image and selected store userdata",
    );
  if (
    record.GraphDriver?.Data?.MergedDir !== undefined &&
    record.GraphDriver.Data.MergedDir !== "" &&
    !new RegExp(
      `^${escapeRegex(expected.graph_root)}/overlay/[a-f0-9]{64}/merged$`,
      "u",
    ).test(record.GraphDriver.Data.MergedDir)
  )
    throw podmanProfileUnavailable(
      "Observed image root is outside the selected native-overlay layer branch",
    );
  const identity = Object.freeze({
    id: record.Id,
    image_id: record.Image.replace(/^sha256:/u, ""),
    created: record.Created,
    static_dir: record.StaticDir ?? null,
    oci_path: record.OCIConfigPath ?? null,
    image_root: record.GraphDriver?.Data?.MergedDir ?? null,
    pid: record.State.Pid,
    conmon_pid: record.State.ConmonPid ?? null,
    running: record.State.Running,
    status: record.State.Status,
    exit_code: record.State.ExitCode,
  });
  if (
    expected.generation !== undefined &&
    (identity.created !== expected.generation.created ||
      (expected.generation.static_dir !== null &&
        expected.generation.static_dir !== "" &&
        identity.static_dir !== expected.generation.static_dir) ||
      (expected.generation.oci_path !== null &&
        expected.generation.oci_path !== "" &&
        identity.oci_path !== expected.generation.oci_path) ||
      (expected.generation.image_root !== null &&
        expected.generation.image_root !== "" &&
        identity.image_root !== expected.generation.image_root &&
        !(
          expected.cleanup === true &&
          (identity.image_root === null || identity.image_root === "") &&
          (identity.status === "exited" || identity.status === "stopped") &&
          !identity.running &&
          identity.pid === 0
        )))
  )
    throw podmanProfileUnavailable(
      "Observed container generation or selected image root changed; lifecycle authority is refused",
    );
  return identity;
};

const escapeRegex = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

export interface PodmanContainerIdentity {
  readonly id: string;
  readonly image_id: string;
  readonly created: string;
  readonly static_dir: string | null;
  readonly oci_path: string | null;
  readonly image_root: string | null;
  readonly pid: number;
  readonly conmon_pid: number | null;
  readonly running: boolean;
  readonly status: string;
  readonly exit_code: number;
}

/**
 * Container execution is intentionally unavailable until read-only admission
 * of a caller-selected running container can prove the complete boundary.
 */
export class OwnedPodmanContainer {
  static async acquire(_context: unknown): Promise<never> {
    throw podmanProfileUnavailable(
      "REA-managed container creation and lifecycle are disabled; caller-selected existing-container admission is not implemented",
    );
  }
}
