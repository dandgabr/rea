import {
  firmwareExtractionObservationSchema,
  type FirmwarePartialObservation,
} from "../domain/firmware/firmwareAnalysis.js";
import type { z } from "zod";
import type { normalizeUnblobReport } from "./FirmwareReports.js";
import { jsonValueSchema } from "../domain/jsonValue.js";

/** Own normalized producer facts before acquiring a caller publication tree. */
export const createFirmwareExtractionObservation = (context: {
  outputDirectory: string;
  engine: z.infer<typeof firmwareExtractionObservationSchema>["engine"];
  selection: z.infer<typeof firmwareExtractionObservationSchema>["selection"];
  normalized: ReturnType<typeof normalizeUnblobReport>;
}): FirmwarePartialObservation => ({
  kind: "firmware",
  result: jsonValueSchema.parse(
    firmwareExtractionObservationSchema.parse({
      engine: context.engine,
      selection: context.selection,
      publication_state: "not_committed",
      requested_output_directory: context.outputDirectory,
      coverage: context.normalized.coverage,
      chunks: context.normalized.chunks,
      derivations: context.normalized.derivations,
      depth_limited_paths: context.normalized.depth_limited_paths,
      diagnostics: context.normalized.diagnostics,
      tasks: context.normalized.tasks,
      randomness: context.normalized.randomness,
      multifiles: context.normalized.multifiles,
      deleted_files: context.normalized.deleted_files,
    }),
  ),
});
