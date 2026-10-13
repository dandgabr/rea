import { createHash } from "node:crypto";
import { z } from "zod";
import { podmanAbsolutePath } from "./PodmanStoreProfile.js";
import { podmanProfileUnavailable } from "./PodmanProfileFiles.js";

/** Adapter-owned protocol source, never a public caller command or argv proxy. */
export class FixedPodmanProgram {
  readonly #source: string;
  readonly #name: string;
  readonly #sha256: string;
  private constructor(name: string, source: string) {
    this.#name = name;
    this.#source = source;
    this.#sha256 = createHash("sha256").update(source).digest("hex");
    Object.freeze(this);
  }
  static define(name: string, source: string): FixedPodmanProgram {
    if (
      !/^[a-z][a-z0-9-]*$/u.test(name) ||
      source.includes("\0") ||
      /[\uD800-\uDFFF]/u.test(source)
    )
      throw podmanProfileUnavailable(
        "Fixed protocol program has an unsupported representation",
      );
    return new FixedPodmanProgram(name, source);
  }
  get name(): string {
    return this.#name;
  }
  get source(): string {
    return this.#source;
  }
  get sha256(): string {
    return this.#sha256;
  }
}
const executionSchema = z.strictObject({
  containerId: z.string().regex(/^[a-f0-9]{64}$/u),
  imageId: z.string().regex(/^[a-f0-9]{64}$/u),
  interpreter: podmanAbsolutePath,
  namespaceLimiter: podmanAbsolutePath,
  producerFileBytes: z
    .number()
    .int()
    .min(1)
    .max(512 * 1024 * 1024),
  executionToken: z
    .string()
    .regex(/^[a-f0-9]{32}$/u)
    .optional(),
  program: z.custom<FixedPodmanProgram>(
    (value) => value instanceof FixedPodmanProgram,
  ),
});
export type PodmanExistingProgramSelection = z.infer<typeof executionSchema>;
/** The namespace adapter separately observes the selected service/image generation around each call. */
export const admitPodmanExistingProgram = (
  selection: PodmanExistingProgramSelection,
) => {
  const parsed = executionSchema.safeParse(selection);
  if (!parsed.success)
    throw podmanProfileUnavailable(
      "Existing execution selection does not establish exact supported identities",
    );
  return Object.freeze(parsed.data);
};
/** Fixed protocol invocation; payload is stdin, never interpreted as flags or source. */
export const existingPodmanProgramArguments = (
  selection: PodmanExistingProgramSelection,
): readonly string[] =>
  Object.freeze([
    "exec",
    "--interactive",
    ...(selection.executionToken === undefined
      ? []
      : [`--env=REA_PROCESS_RUN_ID=${selection.executionToken}`]),
    "--",
    selection.containerId,
    selection.namespaceLimiter,
    "--as=1073741824",
    `--fsize=${selection.producerFileBytes}`,
    "--core=0",
    "--cpu=120",
    "--",
    selection.interpreter,
    "-I",
    "-c",
    selection.program.source,
  ]);
