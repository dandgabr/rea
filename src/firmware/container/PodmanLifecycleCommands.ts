import { isAbsolute, resolve, sep } from "node:path";
import { z } from "zod";
import { podmanRepresentableString } from "./PodmanStoreProfile.js";

export const podmanFullContainerId = z.string().regex(/^[a-f0-9]{64}$/u);
export const podmanAcquisitionToken = z.string().regex(/^[a-f0-9]{32}$/u);
const stagingPath = podmanRepresentableString.refine(
  (path) =>
    isAbsolute(path) &&
    path !== sep &&
    resolve(path) === path &&
    !path.includes(":"),
);
const namespacePath = podmanRepresentableString.refine(
  (path) => isAbsolute(path) && resolve(path) === path,
);
const argument = z.string().regex(/^[^\u0000\uD800-\uDFFF]*$/u);
export const podmanCreateSelectionSchema = z
  .strictObject({
    purpose: z.enum(["analysis", "inventory", "readiness"]),
    token: podmanAcquisitionToken,
    cidfile: stagingPath,
    authfile: stagingPath,
    image_id: podmanFullContainerId,
    uid: z.number().int().positive().max(0xffffffff),
    gid: z.number().int().min(0).max(0xffffffff),
    mounts: z
      .array(
        z.strictObject({
          role: z.enum(["input", "work", "plugins"]),
          source: stagingPath,
        }),
      )
      .min(1)
      .max(3),
    invocation: z.strictObject({
      executable: z.literal("/usr/bin/prlimit"),
      arguments: z.array(argument).min(6),
    }),
  })
  .superRefine((selection, context) => {
    const roles = selection.mounts.map((m) => m.role);
    if (
      new Set(roles).size !== roles.length ||
      !roles.includes("work") ||
      (selection.purpose === "analysis" && !roles.includes("input"))
    )
      context.addIssue({
        code: "custom",
        message:
          "Distinct fixed roles require work and analysis requires input",
      });
    for (const a of selection.mounts)
      for (const b of selection.mounts)
        if (
          a !== b &&
          (a.source === b.source || a.source.startsWith(`${b.source}${sep}`))
        )
          context.addIssue({
            code: "custom",
            message:
              "Readonly mounts must be disjoint from the writable work tree",
          });
    const args = selection.invocation.arguments;
    if (
      args[0] !== "--as=1073741824" ||
      args[1] !== "--cpu=120" ||
      args[2] !== "--core=0" ||
      !/^--fsize=[1-9][0-9]*$/u.test(args[3] ?? "") ||
      Number(args[3]?.slice(8)) > 512 * 1024 * 1024 ||
      args[4] !== "--" ||
      !namespacePath.safeParse(args[5]).success
    )
      context.addIssue({
        code: "custom",
        message: "A fixed in-namespace producer limiter is required",
      });
    if (
      args.reduce((total, value) => total + Buffer.byteLength(value) + 1, 0) >
      8 * 1024 * 1024
    )
      context.addIssue({
        code: "custom",
        message: "Prepared argv exceeds its 8MiB representation budget",
      });
  });
/** Internal OCI metadata selection; it has no production command builder. */
export type PodmanCreateSelection = z.infer<typeof podmanCreateSelectionSchema>;
export type PodmanMountRole = PodmanCreateSelection["mounts"][number]["role"];
export const podmanMountDestination = (role: PodmanMountRole) => `/rea-${role}`;

/** No lifecycle command is authorized in production pending existing-container admission. */
export const admitPodmanLifecycleCommand = (
  _command: readonly string[],
): boolean => false;
