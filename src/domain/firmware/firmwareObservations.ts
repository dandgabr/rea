import { z } from "zod";
import { digestSchema } from "../digests.js";

const bytes = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const range = z.strictObject({ offset: bytes, length: bytes });
const hashes = z.strictObject({
  md5: z
    .string()
    .regex(/^[a-f0-9]{32}$/u)
    .nullable(),
  sha1: z
    .string()
    .regex(/^[a-f0-9]{40}$/u)
    .nullable(),
  sha256: digestSchema,
});

/** Task-local observations preserve absent producer metadata as unknown. */
export const firmwareTaskSchema = z.strictObject({
  path: z.string(),
  depth: bytes,
  provider_blob_id: z.string(),
  is_multi_file: z.boolean(),
  stat: z.strictObject({
    size: bytes,
    is_file: z.boolean(),
    is_dir: z.boolean(),
    is_link: z.boolean(),
    link_target: z.string().nullable(),
  }),
  hashes: hashes.nullable(),
  magic: z
    .strictObject({ description: z.string(), mime_type: z.string() })
    .nullable(),
  processing_disposition: z.enum([
    "unexamined_depth_limit",
    "directory_enumerated",
    "directory_enumeration_incomplete",
    "multifile_consumed",
    "empty",
    "nonregular",
    "skipped_magic",
    "skipped_extension",
    "examined_recognized",
    "examined_unrecognized",
    "unknown_processing",
    "unknown_plugin_processing",
  ]),
  disposition_basis: z.literal("pinned_native_control_flow"),
  skip_reasons: z.array(z.enum(["magic", "extension"])),
});
const percentages = {
  unit: z.literal("percent"),
  percentages: z.array(z.number().min(0).max(100)),
  block_size: bytes.positive(),
  mean: z.number().min(0).max(100),
};
/** Native measurements retain their algorithm, unit, window and byte scope. */
export const firmwareRandomnessSchema = z.strictObject({
  input_path: z.string(),
  scope: z.enum(["whole_file", "unknown_chunk"]),
  range,
  root_file_range: range.nullable(),
  shannon: z.strictObject({
    algorithm: z.literal("shannon_entropy"),
    ...percentages,
  }),
  chi_square: z.strictObject({
    algorithm: z.literal("chi_square_probability"),
    ...percentages,
  }),
});
/** Multi-file membership establishes task identity, without byte correspondence. */
export const firmwareMultiFileSchema = z.strictObject({
  input_path: z.string(),
  provider_id: z.string(),
  handler: z.string(),
  name: z.string(),
  constituents: z.array(
    z.strictObject({
      path: z.string(),
      provider_blob_id: z.string().nullable(),
      depth: bytes.nullable(),
      is_multi_file: z.boolean().nullable(),
      reported_hashes: hashes.nullable(),
      original_file_range: z.null(),
    }),
  ),
});
/** Native deletion is a reported disposition, distinct from a published file. */
export const firmwareDeletedFileSchema = z.strictObject({
  path: z.string(),
  handler: z.string(),
  reported_sha256: digestSchema.nullable(),
});
