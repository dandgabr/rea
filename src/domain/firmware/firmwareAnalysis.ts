import {
  binwalkNgInputSchemas,
  binwalkNgProviderInputSchema,
  type BinwalkNgRequest,
} from "./binwalkNgAnalysis.js";
import { binwalkNgResultSchemas } from "./binwalkNgResults.js";
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

/** Explicit firmware inspection and extraction intent, independent of engines. */
export const legacyFirmwareInputSchemas = {
  inspect_firmware_regions: z.strictObject(target),
  extract_firmware: z.strictObject({
    ...target,
    output_directory: localPathStringSchema
      .refine(isAbsolute, {
        message: "output_directory must be an absolute local filesystem path",
      })
      .describe("Absolute, absent output directory; parent must exist"),
    range: range
      .optional()
      .describe("Explicit file-byte interval; omit to extract the whole file"),
    max_depth: z
      .number()
      .int()
      .min(1)
      .max(10)
      .default(3)
      .describe("Extraction depth; reaching it yields partial analysis"),
    max_output_bytes: z
      .number()
      .int()
      .min(1)
      .max(512 * 1024 * 1024)
      .default(256 * 1024 * 1024)
      .describe(
        "Staging file-byte budget, checked during extraction; transient overshoot is possible",
      ),
    max_output_files: z
      .number()
      .int()
      .min(1)
      .max(100_000)
      .default(10_000)
      .describe("Staging entry budget, including directories and links"),
  }),
} as const;

/** Provider selection is explicit for ng; omitted-provider legacy inputs remain unchanged. */
export const firmwareInputSchemas = {
  inspect_firmware_regions: z.union([
    legacyFirmwareInputSchemas.inspect_firmware_regions,
    binwalkNgInputSchemas.inspect_firmware_regions,
  ]),
  extract_firmware: z.union([
    legacyFirmwareInputSchemas.extract_firmware,
    binwalkNgInputSchemas.extract_firmware,
  ]),
  carve_firmware: binwalkNgInputSchemas.carve_firmware,
  inspect_firmware_entropy: binwalkNgInputSchemas.inspect_firmware_entropy,
  inspect_firmware_provider: binwalkNgProviderInputSchema,
} as const;
export type FirmwareOperation = keyof typeof firmwareInputSchemas;
export type LegacyFirmwareRequest = {
  [Name in keyof typeof legacyFirmwareInputSchemas]: {
    operation: Name;
    input: z.infer<(typeof legacyFirmwareInputSchemas)[Name]>;
  };
}[keyof typeof legacyFirmwareInputSchemas];
export type FirmwareRequest = {
  [Name in FirmwareOperation]: {
    operation: Name;
    input: z.infer<(typeof firmwareInputSchemas)[Name]>;
  };
}[FirmwareOperation];
/** Narrow only validated requests; no operation-based provider fallback. */
export const isLegacyFirmwareRequest = (
  request: FirmwareRequest,
): request is LegacyFirmwareRequest => !("provider_id" in request.input);
export const isBinwalkNgRequest = (
  request: FirmwareRequest,
): request is BinwalkNgRequest =>
  "provider_id" in request.input && request.input.provider_id === "binwalk-ng";
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
    operation: z.literal("carve_firmware"),
    input: firmwareInputSchemas.carve_firmware,
  }),
  z.strictObject({
    operation: z.literal("inspect_firmware_entropy"),
    input: firmwareInputSchemas.inspect_firmware_entropy,
  }),
  z.strictObject({
    operation: z.literal("inspect_firmware_provider"),
    input: firmwareInputSchemas.inspect_firmware_provider,
  }),
]);

const engine = z.strictObject({
  name: z.string(),
  version: z.string(),
  executable_path: z.string(),
  executable_sha256: digestSchema,
  source_revision: z.null(),
  worker_count: z.literal(1),
});
const selection = z.strictObject({ ...range.shape, sha256: digestSchema });
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
export const legacyFirmwareResultSchemas = {
  inspect_firmware_regions: z.strictObject({
    engine,
    input_size: bytes,
    regions: z.array(
      z.strictObject({
        provider_id: z.string(),
        offset: bytes,
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
    engine,
    selection,
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

/** Results discriminate ng by provider_id while preserving legacy result omission. */
export const firmwareResultSchemas = {
  inspect_firmware_regions: z.union([
    legacyFirmwareResultSchemas.inspect_firmware_regions,
    binwalkNgResultSchemas.inspect_firmware_regions,
  ]),
  extract_firmware: z.union([
    legacyFirmwareResultSchemas.extract_firmware,
    binwalkNgResultSchemas.extract_firmware,
  ]),
  carve_firmware: binwalkNgResultSchemas.carve_firmware,
  inspect_firmware_entropy: binwalkNgResultSchemas.inspect_firmware_entropy,
  inspect_firmware_provider: binwalkNgResultSchemas.inspect_firmware_provider,
} as const;
