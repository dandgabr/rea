import { z } from "zod";
import { digestSchema } from "../digests.js";
import { jsonValueSchema } from "../jsonValue.js";
const bytes = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const range = z.strictObject({ offset: bytes, length: bytes });
const engine = z.strictObject({
  name: z.literal("binwalk-ng"),
  version: z.literal("4.0.0"),
  executable_path: z.string(),
  executable_sha256: digestSchema,
  source_revision: z.null(),
  worker_count: bytes.positive(),
});
const selection = z.strictObject({
  ...range.shape,
  length: bytes.positive(),
  sha256: digestSchema,
});
const carving = z.strictObject({
  sha256: digestSchema,
  local_range: range,
  original_file_range: range.nullable(),
});
const lineageFields = {
  analysis_depth: bytes.nullable(),
  parent_analysis_file: z.string().nullable(),
  parent_signature_ids: z.array(z.string()),
  runtime_address: z.null(),
  original_file_range: range.nullable(),
  local_range: range.nullable(),
  byte_correspondence: z.enum(["verified", "unknown"]),
  carving_observation: carving.nullable(),
};
const analysis = z.strictObject({
  file_path: z.string(),
  analysis_depth: bytes,
  expected_input_size: bytes,
  examination: z.literal("unknown"),
  diagnostics: z.null(),
  regions: z.array(
    z.strictObject({
      provider_local_id: z.string(),
      offset: bytes,
      reported_size: bytes,
      signature: z.string(),
      description: z.string(),
      reported_confidence: bytes.max(255),
      extraction_declined: z.boolean(),
      local_range: range,
      root_file_range: range.nullable(),
      runtime_address: z.null(),
      size_basis: z.literal("provider_reported_validation_unknown"),
    }),
  ),
  extractions: z.array(
    z.strictObject({
      provider_local_id: z.string(),
      consumed_size: bytes.nullable(),
      success: z.boolean(),
      extractor: z.string(),
      do_not_recurse: z.boolean(),
      output_directory: z.string(),
      diagnostics: z.null(),
    }),
  ),
  coverage: z.enum(["signature_scan", "partial", "none_reported"]),
});
const attempted = z.array(
  z.strictObject({
    file_path: z.string(),
    depth: bytes,
    sha256: digestSchema,
    parent_file: z.string().nullable(),
    returned: z.boolean(),
  }),
);
const file = z
  .strictObject({
    relative_path: z.string(),
    path: z.string(),
    size: bytes,
    sha256: digestSchema,
    ...lineageFields,
  })
  .superRefine((entry, context) => {
    if (
      entry.byte_correspondence === "unknown" &&
      (entry.local_range !== null || entry.original_file_range !== null)
    )
      context.addIssue({
        code: "custom",
        message:
          "Unknown byte correspondence cannot claim verified current ranges",
      });
  });
const common = {
  provider_id: z.literal("binwalk-ng"),
  engine,
  input_size: bytes,
  selection,
  attempted_files: attempted,
};
const scan = {
  ...common,
  analyses: z.array(analysis),
  diagnostics: z.array(z.string()),
  coverage: z.enum(["signature_scan", "partial", "none_reported"]),
};
const extraction = z.strictObject({
  ...scan,
  output_directory: z.string(),
  files: z.array(file),
  unpublished_entries: z.array(
    z.strictObject({
      relative_path: z.string(),
      kind: z.enum(["symlink", "special"]),
      link_target: z.string().nullable(),
      ...lineageFields,
    }),
  ),
  unexamined_files: z.array(
    z.strictObject({
      path: z.string(),
      reason: z.string(),
      depth: bytes.nullable(),
    }),
  ),
  published_bytes: bytes,
});
/** Exact portable facts; producer parser protocols remain in adapters. */
export const binwalkNgResultSchemas = {
  inspect_firmware_regions: z.strictObject(scan),
  extract_firmware: extraction,
  carve_firmware: extraction,
  inspect_firmware_entropy: z.strictObject({
    ...common,
    entropy: z.strictObject({
      algorithm: z.literal("shannon"),
      unit: z.literal("bits_per_byte"),
      nominal_window_bytes: bytes.positive(),
      examined_bytes: bytes.positive(),
      coverage: z.literal("complete"),
      blocks: z.array(
        z.strictObject({
          start: bytes,
          end: bytes,
          entropy: z.number().min(0).max(8),
          root_file_range: range.nullable(),
        }),
      ),
      interpretation: z.null(),
    }),
    png: z.strictObject({
      width: z.literal(2048),
      height: z.literal(1024),
      size: bytes,
      sha256: digestSchema,
      validation: z.literal("png_header"),
      path: z.string().nullable(),
      publication_state: z.enum(["published", "unpublished"]),
    }),
  }),
  inspect_firmware_provider: z.strictObject({
    provider_id: z.literal("binwalk-ng"),
    engine,
    formats: z.array(
      z.strictObject({
        name: z.string(),
        description: z.string(),
        extractor: z.string().nullable(),
        requires_search_all: z.boolean().nullable(),
      }),
    ),
    reported_signature_count: bytes,
    reported_extractable_count: bytes,
    inventory_coverage: z.enum(["native_reported", "partial"]),
    unparsed_lines: z.array(z.string()),
    dependency_readiness: z.literal("unknown"),
    entropy_readiness: z.literal("not_probed"),
    runtime: jsonValueSchema,
  }),
} as const;
