import { z } from "zod";
import { isAbsolute } from "node:path";
import { digestSchema } from "../digests.js";
import { jsonValueSchema, type JsonValue } from "../jsonValue.js";
import { localPathStringSchema } from "../localPath.js";

const bytes = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const range = z.strictObject({ offset: bytes, length: bytes.positive() });
const target = {
  path: localPathStringSchema
    .refine(isAbsolute, {
      message:
        "path must be an absolute local filesystem path (for example /tmp/firmware.bin or C:\\firmware\\firmware.bin)",
    })
    .describe(
      "Absolute local firmware file; never executed. Relative paths are rejected.",
    ),
};

/** Common selection and publication fields; provider adapters own native options. */
export const firmwareSelectionFields = { ...target, range: range.optional() };
export const firmwareExtractionFields = {
  ...firmwareSelectionFields,
  output_directory: localPathStringSchema
    .refine(isAbsolute, { message: "output_directory must be absolute" })
    .describe("Absolute, absent output directory; parent must exist"),
  max_depth: z.number().int().min(1).max(10).default(3),
  max_output_bytes: z
    .number()
    .int()
    .min(1)
    .max(512 * 1024 * 1024)
    .default(256 * 1024 * 1024),
  max_output_files: z.number().int().min(1).max(100_000).default(10_000),
};
const suffix = z
  .string()
  .min(1)
  .refine((value) => !/[\\/\0]/.test(value), {
    message:
      "Suffix must be a nonempty filename suffix without path separators",
  });
const deletion = z.discriminatedUnion("mode", [
  z.strictObject({ mode: z.literal("none") }),
  z.strictObject({ mode: z.literal("all") }),
  z.strictObject({
    mode: z.literal("selected"),
    handlers: z
      .array(
        z
          .string()
          .min(1)
          .refine((value) => value.trim() === value && !value.includes(",")),
      )
      .min(1),
  }),
]);
/** Explicit plugin paths execute trusted Python code before native sandbox setup. */
export const unblobOptionsSchema = z.strictObject({
  workers: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).default(1),
  randomness_depth: bytes.default(0),
  skip_magic: z
    .strictObject({
      mode: z.enum(["append", "replace"]).default("append"),
      values: z.array(z.string()),
    })
    .optional(),
  skip_extensions: z.array(z.string()).min(1).optional(),
  plugins_path: localPathStringSchema
    .refine(isAbsolute)
    .optional()
    .describe(
      "Trusted Python plugin file/tree; imported before Landlock. Installed entrypoints may also execute with unknown inventory.",
    ),
});
export const unblobExtractionOptionsSchema = unblobOptionsSchema.extend({
  keep_extracted_chunks: z.boolean().default(false),
  delete_extracted_files: deletion.default({ mode: "none" }),
  carve_suffix: suffix.default("_extract"),
  extract_suffix: suffix.default("_extract"),
});
export const binwalkRegionInputSchema = z.strictObject({
  ...firmwareSelectionFields,
  provider_id: z.literal("binwalk").default("binwalk"),
});
export const unblobRegionInputSchema = z.strictObject({
  ...firmwareSelectionFields,
  provider_id: z.literal("unblob"),
  options: unblobOptionsSchema.prefault({}),
});
export const unblobExtractionInputSchema = z.strictObject({
  ...firmwareExtractionFields,
  provider_id: z.literal("unblob").default("unblob"),
  options: unblobExtractionOptionsSchema.prefault({}),
});
/** Provider branches are strict; omission preserves the existing engine defaults. */
export const firmwareInputSchemas = {
  inspect_firmware_regions: z.union([
    binwalkRegionInputSchema,
    unblobRegionInputSchema,
  ]),
  extract_firmware: unblobExtractionInputSchema,
} as const;

/** Supported firmware operations. */
export type FirmwareOperation = keyof typeof firmwareInputSchemas;
/** Correlated, validated firmware request. */
export type FirmwareRequest = {
  [Name in FirmwareOperation]: {
    operation: Name;
    input: z.infer<(typeof firmwareInputSchemas)[Name]>;
  };
}[FirmwareOperation];
/** Validate the operation with its exact input contract. */
export const firmwareRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("inspect_firmware_regions"),
    input: firmwareInputSchemas.inspect_firmware_regions,
  }),
  z.strictObject({
    operation: z.literal("extract_firmware"),
    input: firmwareInputSchemas.extract_firmware,
  }),
]);

export const firmwareEngineSchema = z.strictObject({
  name: z.string(),
  version: z.string(),
  executable_path: z.string(),
  executable_sha256: digestSchema,
  source_revision: z.null(),
  worker_count: z.number().int().positive(),
});
export const firmwareSelectionSchema = z.strictObject({
  ...range.shape,
  sha256: digestSchema,
});
const chunk = z.strictObject({
  input_path: z.string(),
  provider_id: z.string(),
  range,
  handler: z.string().nullable(),
  encrypted: z.boolean().nullable(),
  root_file_range: range.nullable(),
  /** The producer reported extraction problems for this chunk. */
  extraction_failed: z.boolean(),
});
/** One unextracted region or failing task/stage, with a supported continuation
 * using already configured capabilities when one exists. */
export const extractionGap = z.strictObject({
  kind: z.enum([
    "missing-extractor-dependency",
    "unknown-chunk-handler",
    "encrypted-chunk",
    "depth-limited",
    "extractor-failure",
    "unpublished-entry",
  ]),
  /** Logical task path from the producer report; `$output/…` for unpublished entries. */
  input_path: z.string(),
  relative_path: z.string().nullable(),
  handler: z.string().nullable(),
  /** Reported chunk or multi-file stage identity; it does not imply a byte range. */
  provider_id: z.string().nullable(),
  range: range.nullable(),
  root_file_range: range.nullable(),
  /** Extractor executables named by the producer; empty when it named none. */
  dependencies: z.array(z.string()),
  /** Lookup key in the result's extraction_continuations table. */
  continuation_id: z.string(),
});

/** Completed firmware result retained when private-runtime cleanup cannot be confirmed. */
export interface FirmwarePartialObservation {
  readonly kind: "firmware";
  readonly result: JsonValue;
  /** Completed producer data, artifact identity and analysis metadata. */
  readonly provenance?: JsonValue;
}

/** Portable results retain reported boundaries, unknowns and extraction lineage. */
export const firmwareResultSchemas = {
  inspect_firmware_regions: z.strictObject({
    engine: firmwareEngineSchema,
    input_size: bytes,
    selection: firmwareSelectionSchema.optional(),
    regions: z.array(
      z.strictObject({
        provider_id: z.string(),
        offset: bytes.describe(
          "Original-file byte offset, adjusted once from the selection",
        ),
        local_offset: bytes
          .describe("Native byte offset within the immutable selected input")
          .optional(),
        reported_size: bytes,
        signature: z.string(),
        description: z.string(),
        reported_confidence: z.number().int().min(0).max(255),
        size_basis: z.literal("provider_reported_validation_unknown"),
      }),
    ),
    coverage: z.literal("signature_scan"),
  }),
  extract_firmware: z.strictObject({
    engine: firmwareEngineSchema,
    selection: firmwareSelectionSchema,
    output_directory: z.string(),
    coverage: z.enum(["complete", "partial"]),
    files: z.array(
      z.strictObject({
        relative_path: z.string(),
        path: z.string(),
        size: bytes,
        sha256: digestSchema,
        reported_sha256: digestSchema.nullable(),
        mime_type: z.string().nullable(),
        analysis_depth: bytes.nullable(),
        runtime_address: z.null(),
        original_file_range: z.null(),
      }),
    ),
    unpublished_entries: z.array(
      z.strictObject({
        relative_path: z.string(),
        kind: z.enum(["symlink", "special"]),
        link_target: z.string().nullable(),
      }),
    ),
    chunks: z.array(chunk),
    derivations: z.array(
      z.strictObject({
        parent_path: z.string(),
        child_path: z.string(),
        provider_blob_id: z.string(),
        handler: z.string().nullable(),
        parent_file_range: range.nullable(),
      }),
    ),
    depth_limited_paths: z.array(z.string()),
    diagnostics: z.array(jsonValueSchema),
    extraction_gaps: z.array(extractionGap),
    /** Each distinct recovery instruction is serialized once, shared by gap ID. */
    extraction_continuations: z.array(
      z.strictObject({ id: z.string(), instruction: z.string() }),
    ),
    published_bytes: bytes,
  }),
} as const;
