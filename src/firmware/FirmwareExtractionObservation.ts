import { createHash } from "node:crypto";
import {
  firmwareExtractionObservationSchema,
  unblobRegionResultSchema,
  type FirmwarePartialObservation,
} from "../domain/firmware/firmwareAnalysis.js";
import type { z } from "zod";
import type { normalizeUnblobReport } from "./FirmwareReports.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import type { UnpublishedFirmwareEntry } from "./FirmwareFiles.js";

import { firmwareExtractionGaps } from "./FirmwareExtractionGaps.js";

const facts = (normalized: ReturnType<typeof normalizeUnblobReport>) => ({
  coverage: normalized.coverage,
  chunks: normalized.chunks,
  derivations: normalized.derivations,
  depth_limited_paths: normalized.depth_limited_paths,
  diagnostics: normalized.diagnostics,
  tasks: normalized.tasks,
  randomness: normalized.randomness,
  multifiles: normalized.multifiles,
  deleted_files: normalized.deleted_files,
});

/** Own normalized producer facts before acquiring a caller publication tree. */
export const createFirmwareExtractionObservation = (context: {
  outputDirectory: string;
  engine: z.infer<typeof firmwareExtractionObservationSchema>["engine"];
  selection: z.infer<typeof firmwareExtractionObservationSchema>["selection"];
  normalized: ReturnType<typeof normalizeUnblobReport>;
  maxDepth: number;
  unpublished?: readonly Pick<
    UnpublishedFirmwareEntry,
    "relativePath" | "kind" | "linkTarget"
  >[];
}): FirmwarePartialObservation => {
  const instructions = new Map<string, string>();
  const unpublished = context.unpublished ?? [];
  const extractionGaps = firmwareExtractionGaps(
    context.normalized,
    context.maxDepth,
    [],
    unpublished.map(({ relativePath }) => ({ relative_path: relativePath })),
  ).map(({ continuation, ...gap }) => {
    const id = createHash("sha256").update(continuation).digest("hex");
    instructions.set(continuation, id);
    return { ...gap, continuation_id: id };
  });
  return {
    kind: "firmware",
    result: jsonValueSchema.parse(
      firmwareExtractionObservationSchema.parse({
        engine: context.engine,
        selection: context.selection,
        publication_state: "not_committed",
        requested_output_directory: context.outputDirectory,
        ...facts(context.normalized),
        unpublished_entries: unpublished.map(
          ({ relativePath, kind, linkTarget }) => ({
            relative_path: relativePath,
            kind,
            link_target: linkTarget,
          }),
        ),
        extraction_gaps: extractionGaps,
        extraction_continuations: [...instructions].map(
          ([instruction, id]) => ({ id, instruction }),
        ),
      }),
    ),
  };
};

/** Inspection producer facts never acquire artifact publication paths. */
export const createFirmwareInspectionObservation = (context: {
  engine: z.infer<typeof firmwareExtractionObservationSchema>["engine"];
  inputSize: number;
  selection: z.infer<typeof unblobRegionResultSchema>["selection"];
  normalized: ReturnType<typeof normalizeUnblobReport>;
}): FirmwarePartialObservation => ({
  kind: "firmware",
  result: jsonValueSchema.parse(
    unblobRegionResultSchema.parse({
      provider_id: "unblob",
      mode: "inspection",
      engine: context.engine,
      input_size: context.inputSize,
      selection: context.selection,
      ...facts(context.normalized),
    }),
  ),
});
