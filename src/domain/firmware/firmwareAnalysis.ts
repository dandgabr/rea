import { z } from "zod";
import { isAbsolute } from "node:path";
import { digestSchema } from "../digests.js";
import { jsonValueSchema, type JsonValue } from "../jsonValue.js";
import { localPathStringSchema } from "../localPath.js";
import { firmwareRuntimeSchema } from "./firmwareRuntime.js";
import {
  firmwareTaskSchema,
  firmwareRandomnessSchema,
  firmwareMultiFileSchema,
  firmwareDeletedFileSchema,
} from "./firmwareObservations.js";

const bytes = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
export const FIRMWARE_EXTRACTION_LIMITS = {
  minimumBytes: 4096,
  maximumBytes: 64 * 1024 * 1024,
  maximumEntries: 512,
} as const;
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
    .refine(isAbsolute, {
      message: "output_directory must be an absolute local filesystem path",
    })
    .describe("Absolute, absent output directory; parent must exist"),
  max_depth: z.number().int().min(1).max(10).default(3),
  max_output_bytes: z
    .number()
    .int()
    .min(FIRMWARE_EXTRACTION_LIMITS.minimumBytes)
    .max(FIRMWARE_EXTRACTION_LIMITS.maximumBytes)
    .default(FIRMWARE_EXTRACTION_LIMITS.maximumBytes),
  max_output_files: z
    .number()
    .int()
    .min(1)
    .max(FIRMWARE_EXTRACTION_LIMITS.maximumEntries)
    .default(FIRMWARE_EXTRACTION_LIMITS.maximumEntries),
};
const optionText = z
  .string()
  .refine((value) => !value.includes("\0"), {
    message:
      "Option text cannot contain NUL, which cannot be represented in a native argument",
  })
  .refine((value) => !/[\ud800-\udfff]/u.test(value), {
    message:
      "Option text must contain well-formed Unicode, which can be preserved in native UTF-8 arguments",
  });
const suffix = optionText.min(1).refine((value) => !/[\\/\0]/.test(value), {
  message: "Suffix must be a nonempty filename suffix without path separators",
});
const deletion = z.discriminatedUnion("mode", [
  z.strictObject({ mode: z.literal("none") }),
  z.strictObject({ mode: z.literal("all") }),
  z.strictObject({
    mode: z.literal("selected"),
    handlers: z
      .array(
        optionText
          .min(1)
          .refine((value) => value.trim() === value && !value.includes(",")),
      )
      .min(1),
  }),
]);
export const unblobOptionsSchema = z.strictObject({
  workers: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).default(1),
  randomness_depth: bytes.default(0),
  skip_magic: z
    .strictObject({
      mode: z.enum(["append", "replace"]).default("append"),
      values: z.array(optionText),
    })
    .optional(),
  skip_extensions: z.array(optionText).min(1).optional(),
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
  runtime: firmwareRuntimeSchema.optional(),
});
export const unblobExtractionInputSchema = z.strictObject({
  ...firmwareExtractionFields,
  provider_id: z.literal("unblob").default("unblob"),
  options: unblobExtractionOptionsSchema.prefault({}),
  runtime: firmwareRuntimeSchema.optional(),
});
/** Provider branches are strict; omission preserves the existing engine defaults. */
export const firmwareInputSchemas = {
  inspect_firmware_regions: z
    .union([binwalkRegionInputSchema, unblobRegionInputSchema])
    .meta({
      // Root-object presentation preserves this nested correlation for SDK clients.
      // Each added provider/options branch must extend this declaration as well.
      dependentSchemas: {
        options: {
          properties: { provider_id: { const: "unblob" } },
          required: ["provider_id"],
        },
        runtime: {
          properties: { provider_id: { const: "unblob" } },
          required: ["provider_id"],
        },
      },
      // Draft-07 clients use schema-valued dependencies for the same correlation.
      dependencies: {
        options: {
          properties: { provider_id: { const: "unblob" } },
          required: ["provider_id"],
        },
        runtime: {
          properties: { provider_id: { const: "unblob" } },
          required: ["provider_id"],
        },
      },
    }),
  extract_firmware: unblobExtractionInputSchema,
  inspect_firmware_provider: z.strictObject({
    provider_id: z.literal("unblob"),
    runtime: firmwareRuntimeSchema.optional(),
  }),
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
  z.strictObject({
    operation: z.literal("inspect_firmware_provider"),
    input: firmwareInputSchemas.inspect_firmware_provider,
  }),
]);

export const firmwareEngineSchema = z.strictObject({
  name: z.string(),
  version: z.string(),
  executable_path: z.string(),
  resolved_executable_path: z
    .string()
    .optional()
    .describe(
      "Resolved fingerprinted executable when distinct from the selected invocation path",
    ),
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

/** Inline continuation form retained for native extraction problem rows. */
export const firmwareExtractionGapSchema = z.strictObject({
  kind: z.enum([
    "missing-extractor-dependency",
    "unknown-chunk-handler",
    "encrypted-chunk",
    "depth-limited",
    "extractor-failure",
    "unpublished-entry",
  ]),
  input_path: z.string(),
  relative_path: z.string().nullable(),
  handler: z.string().nullable(),
  provider_id: z.string().nullable(),
  range: range.nullable(),
  root_file_range: range.nullable(),
  dependencies: z.array(z.string()),
  continuation: z.string(),
});

/** Completed firmware result retained when private-runtime cleanup cannot be confirmed. */
export interface FirmwarePartialObservation {
  readonly kind: "firmware";
  readonly result: JsonValue;
  /** Completed producer data, artifact identity and analysis metadata. */
  readonly provenance?: JsonValue;
}

/** Portable results retain reported boundaries, unknowns and extraction lineage. */
export const binwalkRegionResultSchema = z.strictObject({
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
});
const unblobObservationFields = {
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
  tasks: z.array(firmwareTaskSchema),
  randomness: z.array(firmwareRandomnessSchema),
  multifiles: z.array(firmwareMultiFileSchema),
  deleted_files: z.array(firmwareDeletedFileSchema),
  extraction_problems: z.array(
    z.strictObject({
      input_path: z.string(),
      provider_id: z.string().nullable(),
      handler: z.string().nullable(),
      dependencies: z.array(z.string()),
    }),
  ),
};
/** Unblob inspection has native task/chunk semantics, without published artifacts. */
export const unblobRegionResultSchema = z.strictObject({
  provider_id: z.literal("unblob"),
  mode: z.literal("inspection"),
  engine: firmwareEngineSchema.extend({ name: z.literal("unblob") }),
  input_size: bytes,
  selection: firmwareSelectionSchema,
  coverage: z.enum(["complete", "partial"]),
  ...unblobObservationFields,
});
export const firmwareResultSchemas = {
  inspect_firmware_provider: z.strictObject({
    provider_id: z.literal("unblob"),
    engine: firmwareEngineSchema,
    dependencies: z.array(
      z.strictObject({ command: z.string(), reported_installed: z.boolean() }),
    ),
    dependency_readiness: z.enum([
      "reported_installed",
      "reported_missing",
      "unknown",
    ]),
    dependency_inventory_coverage: z.enum(["native_reported", "partial"]),
    unparsed_dependency_lines: z.array(z.string()),
    formats: z.array(
      z.strictObject({
        name: z.string(),
        type: z.string(),
        fully_supported: z.boolean(),
      }),
    ),
    format_inventory_coverage: z.enum([
      "documented_public_handlers",
      "partial",
    ]),
    unparsed_format_lines: z.array(z.string()),
    installed_plugin_inventory: z.literal("unknown"),
    runtime: jsonValueSchema,
  }),
  inspect_firmware_regions: z.union([
    binwalkRegionResultSchema,
    unblobRegionResultSchema,
  ]),
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
    tasks: z.array(firmwareTaskSchema).optional(),
    randomness: z.array(firmwareRandomnessSchema).optional(),
    multifiles: z.array(firmwareMultiFileSchema).optional(),
    deleted_files: z.array(firmwareDeletedFileSchema).optional(),
    extraction_problems: z
      .array(
        z.strictObject({
          input_path: z.string(),
          provider_id: z.string().nullable(),
          handler: z.string().nullable(),
          dependencies: z.array(z.string()),
        }),
      )
      .optional(),
    published_bytes: bytes,
  }),
} as const;

/** Producer facts survive failed publication without asserting committed artifact paths. */
export const firmwareExtractionObservationSchema =
  firmwareResultSchemas.extract_firmware
    .omit({
      output_directory: true,
      files: true,
      published_bytes: true,
    })
    .extend({
      publication_state: z.literal("not_committed"),
      requested_output_directory: z.string(),
    });
