import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";

const absoluteLinuxPath = localPathStringSchema.regex(
  /^\//u,
  "Container runtime selection requires an absolute Linux host path",
);

/** Immutable resource selection; the runtime adapter admits its repository grammar. */
export const firmwareContainerImageSchema = z
  .string()
  .regex(
    /^(?:sha256:[a-f0-9]{64}|[^\s@\x00]+@sha256:[a-f0-9]{64})$/u,
    "Select a full lowercase SHA256 image ID or a repository with an immutable SHA256 digest",
  );

/** Caller selection conveys no arbitrary runtime arguments, mounts or environment. */
export const firmwareRuntimeSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("native") }),
  z.strictObject({
    kind: z.literal("container"),
    command: absoluteLinuxPath.describe(
      "Selected local Podman executable; invocation path and resolved identity are retained separately",
    ),
    image: firmwareContainerImageSchema.describe(
      "Already-local immutable image; analysis never pulls or initializes storage",
    ),
    existing_store_profile: absoluteLinuxPath.describe(
      "Explicit operator-prepared existing-store profile, admitted before the first runtime command",
    ),
  }),
]);
