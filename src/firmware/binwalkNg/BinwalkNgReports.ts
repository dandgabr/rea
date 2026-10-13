import { z } from "zod";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";

const bytes = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const signatureSchema = z.object({
  id: z.string().min(1),
  offset: bytes,
  size: bytes,
  name: z.string(),
  description: z.string(),
  confidence: z.number().int().min(0).max(255),
  always_display: z.boolean(),
  extraction_declined: z.boolean(),
});
const extractionSchema = z.object({
  size: bytes.nullable(),
  success: z.boolean(),
  extractor: z.string(),
  do_not_recurse: z.boolean(),
  output_directory: z.string(),
});
const analysisSchema = z.array(
  z.object({
    Analysis: z.object({
      file_path: z.string(),
      file_map: z.array(signatureSchema),
      extractions: z.record(z.string(), extractionSchema),
    }),
  }),
);

/** Facts identifying one admitted immutable file, independent of report ordering. */
export interface BinwalkNgFileContext {
  readonly size: number;
  readonly depth: number;
  /** Known only when byte correspondence with original firmware has been proved. */
  readonly rootOffset: number | null;
}

const fail = (reason: string): never => {
  throw new AnalysisOutputError("binwalk-ng", reason);
};

/** Parse native per-file identities; extraction exit status is never inferred from CLI exit 0. */
export const parseBinwalkNgAnalyses = (
  raw: unknown,
  files: ReadonlyMap<string, BinwalkNgFileContext>,
) => {
  const seen = new Set<string>();
  return analysisSchema.parse(raw).map(({ Analysis: analysis }) => {
    const file = files.get(analysis.file_path);
    if (file === undefined)
      return fail(`Report references unowned file: ${analysis.file_path}`);
    if (seen.has(analysis.file_path))
      return fail(`Duplicate analysis file: ${analysis.file_path}`);
    seen.add(analysis.file_path);
    const signatures = new Map<string, z.infer<typeof signatureSchema>>();
    const regions = analysis.file_map.map((hit) => {
      if (signatures.has(hit.id))
        return fail(`Duplicate signature identity in file: ${hit.id}`);
      signatures.set(hit.id, hit);
      if (hit.offset >= file.size || hit.size > file.size - hit.offset)
        return fail(
          `Reported signature lies outside its owning file: ${hit.id}`,
        );
      return {
        provider_local_id: hit.id,
        offset: hit.offset,
        reported_size: hit.size,
        signature: hit.name,
        description: hit.description,
        reported_confidence: hit.confidence,
        extraction_declined: hit.extraction_declined,
        local_range: { offset: hit.offset, length: hit.size },
        root_file_range:
          file.rootOffset === null
            ? null
            : { offset: file.rootOffset + hit.offset, length: hit.size },
        runtime_address: null,
        size_basis: "provider_reported_validation_unknown" as const,
      };
    });
    const extractions = Object.entries(analysis.extractions).map(
      ([id, extraction]) => {
        const hit = signatures.get(id);
        if (hit === undefined)
          return fail(`Extraction has no owning signature: ${id}`);
        if (
          extraction.size !== null &&
          extraction.size > file.size - hit.offset
        )
          return fail(
            `Extraction consumed range lies outside its owning file: ${id}`,
          );
        return {
          provider_local_id: id,
          consumed_size: extraction.size,
          success: extraction.success,
          extractor: extraction.extractor,
          do_not_recurse: extraction.do_not_recurse,
          output_directory: extraction.output_directory,
          // Native JSON discards external-extractor stdout/stderr and detailed errors.
          diagnostics: null,
        };
      },
    );
    return {
      file_path: analysis.file_path,
      analysis_depth: file.depth,
      regions,
      extractions,
      coverage:
        extractions.some((item) => !item.success) ||
        regions.some((item) => item.extraction_declined)
          ? ("partial" as const)
          : regions.length === 0
            ? ("examined_unrecognized" as const)
            : ("signature_scan" as const),
    };
  });
};

const entropySchema = z.array(
  z.object({
    Entropy: z.object({
      file: z.string(),
      blocks: z.array(
        z.object({
          start: bytes,
          end: bytes,
          entropy: z.number().min(0).max(8),
        }),
      ),
    }),
  }),
);

/** Preserve source-native Shannon values and exact measured windows, without interpretation. */
export const parseBinwalkNgEntropy = (
  raw: unknown,
  file: {
    readonly path: string;
    readonly size: number;
    readonly rootOffset: number | null;
  },
) => {
  const records = entropySchema.parse(raw);
  const entropy = records[0]?.Entropy;
  if (records.length !== 1 || entropy?.file !== file.path)
    return fail("Expected one native entropy report for the selected file");
  if (file.size <= 0 || entropy.blocks.length === 0)
    return fail("Native entropy coverage is absent for the nonempty input");
  const window = file.size < 2048 ? file.size : Math.floor(file.size / 2048);
  let end = 0;
  const blocks = entropy.blocks.map((block) => {
    if (block.start !== end)
      return fail("Native entropy coverage is discontinuous");
    if (
      block.end !== Math.min(file.size, block.start + window) ||
      block.end <= block.start
    )
      return fail("Native entropy window does not match the pinned algorithm");
    end = block.end;
    return {
      ...block,
      root_file_range:
        file.rootOffset === null
          ? null
          : {
              offset: file.rootOffset + block.start,
              length: block.end - block.start,
            },
    };
  });
  if (end !== file.size)
    return fail("Native entropy coverage does not cover the selected input");
  return {
    algorithm: "shannon" as const,
    unit: "bits_per_byte" as const,
    nominal_window_bytes: window,
    examined_bytes: end,
    coverage: "complete" as const,
    blocks,
    interpretation: null,
  };
};
