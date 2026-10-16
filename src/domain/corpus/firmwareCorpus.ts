import { z } from "zod";
import { jsonObjectSchema, jsonValueSchema } from "../jsonValue.js";
import { localPathStringSchema } from "../localPath.js";
import { isAbsolute } from "node:path";
const absoluteLocalPathSchema = localPathStringSchema.refine(
  isAbsolute,
  "Use an absolute local path",
);
const isUnicodeScalarString = (value: string): boolean => {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff || !Number.isFinite(next))
        return false;
      index++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
};
const namespacePathScalar = String.raw`(?:[^\x2f\x00\uD800-\uDFFF]|[\uD800-\uDBFF][\uDC00-\uDFFF])`;
const namespacePathNonDotScalar = String.raw`(?:[^\x2e\x2f\x00\uD800-\uDFFF]|[\uD800-\uDBFF][\uDC00-\uDFFF])`;
const namespacePathSegment = String.raw`(?:${namespacePathNonDotScalar}(?:${namespacePathScalar})*|\.${namespacePathNonDotScalar}(?:${namespacePathScalar})*|\.\.${namespacePathScalar}(?:${namespacePathScalar})*)`;
const namespacePath = z
  .string()
  // Keep path shape constraints in the advertised pattern too: Zod refinements
  // are not represented in JSON Schema. The expression works on UTF-16 code
  // units so it can allow valid surrogate pairs while rejecting lone ones.
  .regex(
    new RegExp(
      String.raw`^\x2f(?:${namespacePathSegment}(?:\x2f${namespacePathSegment})*)?$`,
    ),
  )
  .refine(isUnicodeScalarString, "Namespace paths must contain Unicode scalars")
  .refine(
    (value) =>
      value
        .slice(1)
        .split("/")
        .every((segment) => segment !== "." && segment !== ".."),
    "Namespace paths cannot contain dot components",
  )
  .describe(
    "Exact absolute scalar UTF-8 namespace path without dot or empty components",
  );
const nativeHostRuntime = z.strictObject({ kind: z.literal("native") });
const nativeExistingRuntime = z.strictObject({
  kind: z.literal("podman-existing"),
  podman: absoluteLocalPathSchema,
  container_id: z.string().regex(/^[a-f0-9]{64}$/u),
  image_id: z.string().regex(/^[a-f0-9]{64}$/u),
  existing_store_profile: absoluteLocalPathSchema,
  staging_parent: namespacePath,
  namespace_prlimit: namespacePath.default("/usr/bin/prlimit"),
});
/** Independently declared existing service authority; no container lifecycle or caller argv. */
export const factNativeRuntimeSchema = z.discriminatedUnion("kind", [
  nativeHostRuntime,
  nativeExistingRuntime,
]);

/** Explicit caller declaration; status endpoints cannot attest this source identity. */
export const corpusConnectionSchema = z.strictObject({
  endpoint: z
    .string()
    .regex(/^https?:\/\/(?:127\.0\.0\.1|\[::1\])(?::[0-9]+)?\/?$/u)
    .superRefine((value, ctx) => {
      try {
        const url = new URL(value);
        if (
          !["http:", "https:"].includes(url.protocol) ||
          !["127.0.0.1", "[::1]"].includes(url.hostname) ||
          url.username ||
          url.password ||
          url.pathname !== "/" ||
          url.search ||
          url.hash
        )
          throw Error();
      } catch {
        ctx.addIssue({
          code: "custom",
          message:
            "Use a literal loopback HTTP(S) origin without credentials, path, query or fragment",
        });
      }
    }),
  profile: z.enum(["release-4.4.1", "source-54aed90b"]),
  authorization: z
    .string()
    .min(1)
    // ByteString transport and RFC 9110 field-value grammar retain the chosen
    // value: no unsupported code units or normalization of edge whitespace.
    .regex(
      /^[\x21-\x7e\x80-\xff](?:[\t\x20-\x7e\x80-\xff]*[\x21-\x7e\x80-\xff])?$/u,
    )
    .describe(
      "Exact nonempty HTTP Authorization field value: Latin-1 visible/obs-text bytes, interior spaces/tabs allowed; no controls, DEL or edge whitespace.",
    )
    .optional(),
});
export const corpusUidSchema = z
  .string()
  .regex(/^[a-f0-9]{64}_(?:0|[1-9][0-9]*)$/u);
const pathSegment = z
  .string()
  .min(1)
  .regex(/^[^\x2f\x00]+$/u)
  .refine((value) => value !== "." && value !== "..", {
    message: "Path segment cannot be a URL dot segment",
  });
const plugin = pathSegment;
const connection = { connection: corpusConnectionSchema };
const object = { ...connection, uid: corpusUidSchema };
const native = {
  interpreter: namespacePath,
  checkout: namespacePath,
  profile: z.enum(["release-4.4.1", "source-54aed90b"]),
  binding_declaration: z.string().optional(),
  max_output_bytes: z
    .number()
    .int()
    .min(1)
    .max(512 * 1024 * 1024)
    .default(256 * 1024 * 1024),
  max_output_files: z.number().int().min(1).max(100_000).default(10_000),
};
const nativeInput = <Shape extends z.ZodRawShape>(shape: Shape) =>
  z.strictObject({
    ...native,
    ...shape,
    runtime: factNativeRuntimeSchema.optional(),
  });
const comparison = {
  ...connection,
  uids: z
    .array(corpusUidSchema)
    .min(2)
    .refine(
      (values) => new Set(values).size === values.length,
      "Comparison UIDs must be distinct",
    ),
};
/** Named corpus workflows, separate from local artifact inspection and extraction. */
export const firmwareCorpusInputs = {
  inspect_firmware_corpus: z.strictObject(connection),
  search_corpus_objects: z
    .strictObject({
      ...connection,
      kind: z.enum(["firmware", "file"]),
      query: jsonObjectSchema.default({}),
      offset: z.number().int().default(0),
      limit: z.number().int().default(0),
      recursive: z.boolean().default(false),
      inverted: z.boolean().default(false),
    })
    .superRefine((input, ctx) => {
      if (input.kind === "file" && (input.recursive || input.inverted))
        ctx.addIssue({
          code: "custom",
          message: "File search does not support recursive or inverted",
        });
      if (input.recursive && Object.keys(input.query).length === 0)
        ctx.addIssue({
          code: "custom",
          message: "Recursive search requires a nonempty query",
        });
      if (input.inverted && !input.recursive)
        ctx.addIssue({
          code: "custom",
          message: "Inverted search requires recursive",
        });
    }),
  inspect_corpus_object: z
    .strictObject({
      ...object,
      kind: z.enum(["firmware", "file"]),
      summary: z.boolean().default(false),
    })
    .superRefine((input, ctx) => {
      if (input.kind === "file" && input.summary)
        ctx.addIssue({
          code: "custom",
          message: "File summaries are unsupported by the producer",
        });
    }),
  inspect_corpus_analysis: z.strictObject({ ...object, plugin }),
  inspect_corpus_parent_analysis: z.strictObject({
    ...object,
    plugin: z.enum(["file_system_metadata", "qemu_exec"]),
  }),
  inspect_corpus_comparison: z.strictObject(comparison),
  collect_corpus_yara: z.strictObject({
    ...connection,
    search_id: pathSegment,
  }),
  inspect_corpus_statistics: z.strictObject({
    ...connection,
    category: z
      .enum([
        "architecture",
        "crypto_material",
        "elf_executable",
        "exploit_mitigations",
        "file_type",
        "firmware_meta",
        "general",
        "ips_and_uris",
        "known_vulnerabilities",
        "release_date",
        "software_components",
        "unpacking",
      ])
      .optional(),
  }),
  inspect_corpus_gaps: z.strictObject(connection),
  download_corpus_binary: z.strictObject({
    ...object,
    repacked: z.boolean().default(false),
    output_path: absoluteLocalPathSchema,
  }),
  export_corpus_firmware: nativeInput({
    uids: z.array(corpusUidSchema).min(1),
    output_directory: absoluteLocalPathSchema,
  }),
} as const;
export type FirmwareCorpusOperation = keyof typeof firmwareCorpusInputs;
export type FirmwareCorpusInput<
  Name extends FirmwareCorpusOperation = FirmwareCorpusOperation,
> = z.infer<(typeof firmwareCorpusInputs)[Name]>;
export const firmwareCorpusResultSchema = z.strictObject({
  state: z.enum([
    "not-delivered",
    "accepted",
    "completed",
    "failed",
    "unknown",
  ]),
  endpoint: z.string().nullable(),
  profile: z.enum(["release-4.4.1", "source-54aed90b"]),
  http_status: z.number().int().nullable(),
  observed_at: z.string(),
  raw_sha256: z.string().nullable(),
  coverage: z.enum([
    "requested-page",
    "producer-response",
    "archive-preflight",
  ]),
  data: jsonValueSchema,
  diagnostics: z.array(z.string()),
});
