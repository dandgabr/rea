import { isAbsolute } from "node:path";
import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";

const bytes = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const absolutePath = localPathStringSchema.refine(isAbsolute, {
  message: "An absolute local filesystem path is required",
});
/** Common byte selection, independent of provider protocols. */
export const binwalkNgSelectionFields = {
  path: absolutePath,
  provider_id: z.literal("binwalk-ng"),
  range: z.strictObject({ offset: bytes, length: bytes.positive() }).optional(),
};
const outputFields = {
  output_directory: absolutePath.describe(
    "Absent output directory with an existing parent",
  ),
  max_output_bytes: bytes
    .positive()
    .max(512 * 1024 * 1024)
    .default(256 * 1024 * 1024),
  max_output_files: bytes.positive().max(100_000).default(10_000),
};
const signatureName = z
  .string()
  .min(1)
  .regex(/^[^\uD800-\uDFFF]*$/u, {
    message: "Signature names must be representable as UTF-8",
  })
  .refine((name) => !name.includes(",") && !name.includes("\0"), {
    message: "Signature names cannot contain native list separators or NUL",
  });
export const binwalkNgScanFields = {
  search_all: z.boolean().default(false),
  include: z.array(signatureName).default([]),
  exclude: z.array(signatureName).default([]),
  no_mmap: z.boolean().default(false),
  workers: bytes.positive().default(1),
};
const exclusiveSignatures = (options: {
  include: string[];
  exclude: string[];
}) => options.include.length === 0 || options.exclude.length === 0;
const scanOptions = z
  .strictObject(binwalkNgScanFields)
  .refine(exclusiveSignatures, {
    message: "include and exclude are mutually exclusive",
  });
const extractOptions = z
  .strictObject({
    ...binwalkNgScanFields,
    carve: z.boolean().default(false),
    recursive: z.boolean().default(true),
  })
  .refine(exclusiveSignatures, {
    message: "include and exclude are mutually exclusive",
  });

/** binwalk-ng file workflows; ignored combinations are absent from their exact contracts. */
export const binwalkNgInputSchemas = {
  inspect_firmware_regions: z.strictObject({
    ...binwalkNgSelectionFields,
    options: scanOptions.prefault({}),
  }),
  extract_firmware: z.strictObject({
    ...binwalkNgSelectionFields,
    ...outputFields,
    max_depth: bytes.min(1).max(10).default(3),
    options: extractOptions.prefault({}),
  }),
  carve_firmware: z.strictObject({
    ...binwalkNgSelectionFields,
    ...outputFields,
    options: scanOptions.prefault({}),
  }),
  inspect_firmware_entropy: z.strictObject({
    ...binwalkNgSelectionFields,
    output_directory: absolutePath
      .optional()
      .describe(
        "Optionally publish native entropy.png into this absent directory",
      ),
    max_output_bytes: outputFields.max_output_bytes,
    max_output_files: outputFields.max_output_files,
  }),
} as const;

/** Validated explicit request; public integration adds these branches to the shared router. */
export type BinwalkNgFileRequest = {
  [Name in keyof typeof binwalkNgInputSchemas]: {
    operation: Name;
    input: z.infer<(typeof binwalkNgInputSchemas)[Name]>;
  };
}[keyof typeof binwalkNgInputSchemas];

/** Native format inventory has no firmware subject or fabricated byte selection. */
export const binwalkNgProviderInputSchema = z.strictObject({
  provider_id: z.literal("binwalk-ng"),
});

export type BinwalkNgRequest =
  | BinwalkNgFileRequest
  | {
      operation: "inspect_firmware_provider";
      input: z.infer<typeof binwalkNgProviderInputSchema>;
    };
