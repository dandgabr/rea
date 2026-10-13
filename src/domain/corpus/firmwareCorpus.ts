import { z } from "zod";
import { jsonObjectSchema, jsonValueSchema } from "../jsonValue.js";
import { localPathStringSchema } from "../localPath.js";
import { isAbsolute } from "node:path";
const absoluteLocalPathSchema = localPathStringSchema.refine(
  isAbsolute,
  "Use an absolute local path",
);

/** Explicit caller declaration; status endpoints cannot attest this source identity. */
export const corpusConnectionSchema = z.strictObject({
  endpoint: z.string().superRefine((value, ctx) => {
    try {
      if (!/^https?:\/\/(?:127\.0\.0\.1|\[::1\])(?::[0-9]+)?\/?$/u.test(value))
        throw Error();
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
    .regex(/^[^\r\n]+$/u)
    .optional(),
});
export const corpusUidSchema = z
  .string()
  .regex(/^[a-f0-9]{64}_(?:0|[1-9][0-9]*)$/u);
const plugin = z
  .string()
  .min(1)
  .regex(/^[^/\x00]+$/u);
const plugins = z
  .array(plugin)
  .refine(
    (values) => new Set(values).size === values.length,
    "Plugin selection must not contain duplicates",
  );
const connection = { connection: corpusConnectionSchema };
const object = { ...connection, uid: corpusUidSchema };
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
const metadata = z.strictObject({
  device_name: z.string(),
  device_part: z.string(),
  device_class: z.string(),
  file_name: z.string(),
  version: z.string(),
  vendor: z.string(),
  release_date: z.iso.date().default("1970-01-01"),
  tags: z.string().default(""),
});
const native = {
  interpreter: absoluteLocalPathSchema,
  checkout: absoluteLocalPathSchema,
  profile: z.enum(["release-4.4.1", "source-54aed90b"]),
  binding_declaration: z.string().optional(),
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
  upload_corpus_firmware: z.strictObject({
    ...connection,
    path: absoluteLocalPathSchema,
    metadata,
    plugins: plugins.refine(
      (values) => !values.includes("unpacker"),
      "Unpacker is a producer dependency, not an upload analysis plugin",
    ),
  }),
  reanalyze_corpus_firmware: z
    .strictObject({
      ...object,
      plugins: plugins.refine(
        (values) => !values.includes("unpacker"),
        "Select re_unpack separately",
      ),
      re_unpack: z.boolean().default(false),
    })
    .refine(
      (input) => input.plugins.length > 0 || input.re_unpack,
      "Select plugins or re_unpack",
    ),
  enqueue_corpus_analysis: z.strictObject({
    ...object,
    plugin,
    force: z.boolean().default(false),
  }),
  start_corpus_comparison: z.strictObject({
    ...comparison,
    redo: z.boolean().default(false),
  }),
  inspect_corpus_comparison: z.strictObject(comparison),
  start_corpus_yara: z.strictObject({
    ...connection,
    rule_file: z.string().min(1),
    uid: corpusUidSchema.optional(),
  }),
  collect_corpus_yara: z.strictObject({
    ...connection,
    search_id: z
      .string()
      .min(1)
      .regex(/^[^/\x00]+$/u),
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
  delete_corpus_firmware: z.strictObject(object),
  export_corpus_firmware: z.strictObject({
    ...native,
    uids: z.array(corpusUidSchema).min(1),
    output_directory: absoluteLocalPathSchema,
  }),
  import_corpus_firmware: z.strictObject({
    ...native,
    archives: z.array(absoluteLocalPathSchema).min(1),
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
