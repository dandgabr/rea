import type { z } from "zod";
import { firmwareExtractionGapSchema } from "../domain/firmware/firmwareAnalysis.js";
import type { normalizeUnblobReport } from "./FirmwareReports.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";

type Gap = z.infer<typeof firmwareExtractionGapSchema>;
const empty = {
  relative_path: null,
  handler: null,
  provider_id: null,
  range: null,
  root_file_range: null,
  dependencies: [],
};
/** Recovery belongs to observed stages; only committed verified files support a child continuation. */
export const firmwareExtractionGaps = (
  normalized: ReturnType<typeof normalizeUnblobReport>,
  maxDepth: number,
  published: readonly { relative_path: string; size: number }[] = [],
  unpublished: readonly { relative_path: string }[] = [],
): Gap[] => {
  const rows: Gap[] = [];
  const chunks = new Map(
    normalized.chunks.map((chunk) => [
      JSON.stringify([chunk.input_path, chunk.provider_id]),
      chunk,
    ]),
  );
  for (const problem of normalized.extraction_problems) {
    const chunk = chunks.get(
      JSON.stringify([problem.input_path, problem.provider_id]),
    );
    rows.push({
      ...empty,
      input_path: problem.input_path,
      handler: problem.handler,
      provider_id: problem.provider_id,
      range: chunk?.range ?? null,
      root_file_range: chunk?.root_file_range ?? null,
      dependencies: problem.dependencies,
      kind:
        problem.dependencies.length > 0
          ? "missing-extractor-dependency"
          : "extractor-failure",
      continuation:
        problem.dependencies.length > 0
          ? "REA installs nothing. Add the producer-named dependency to your own selected runtime and rerun extract_firmware on the same input and selection. The affected stage remains unextracted."
          : "Review the producer's extraction diagnostics before rerunning the same input and selection; no automatic replay or alternative extractor is selected.",
    });
  }
  const committed = new Set(
    published.map((file) => `$output/${file.relative_path}`),
  );
  for (const chunk of normalized.chunks) {
    const original = chunk.input_path === "$input";
    if (chunk.handler === null)
      rows.push({
        ...empty,
        input_path: chunk.input_path,
        handler: chunk.handler,
        provider_id: chunk.provider_id,
        range: chunk.range,
        root_file_range: chunk.root_file_range,
        kind: "unknown-chunk-handler",
        continuation: original
          ? "Use inspect_firmware_regions on the same original input for signature hypotheses, or select this original-file range with extract_firmware. A signature is not decoded content."
          : committed.has(chunk.input_path)
            ? "Use the verified published child as a fresh inspect_firmware_regions or extract_firmware input; this chunk's range is child-local and has no known original-file byte correspondence."
            : "No verified committed child path is available for this nested region. Preserve its task-local identity and diagnostics; its original-file byte correspondence is unknown.",
      });
    if (chunk.encrypted === true)
      rows.push({
        ...empty,
        input_path: chunk.input_path,
        handler: chunk.handler,
        provider_id: chunk.provider_id,
        range: chunk.range,
        root_file_range: chunk.root_file_range,
        kind: "encrypted-chunk",
        continuation:
          "REA has no firmware password or decryption continuation. Treat the region as unexamined; encryption does not establish an empty or corrupt filesystem.",
      });
  }
  for (const input_path of normalized.depth_limited_paths) {
    const usable = published.some((file) => {
      const path = `$output/${file.relative_path}`;
      return (
        (path === input_path || path.startsWith(`${input_path}/`)) &&
        file.size > 0 &&
        file.size <= FIRMWARE_LIMITS.inputBytes
      );
    });
    rows.push({
      ...empty,
      input_path,
      kind: "depth-limited",
      continuation:
        maxDepth < 10
          ? "Rerun extract_firmware with a higher max_depth, up to 10, to examine below this task."
          : usable
            ? "The maximum depth 10 is already selected. Continue with a verified nonempty published child within the firmware input limit as a new input; that new extraction restarts its depth budget."
            : "The maximum depth 10 is already selected, and no verified committed child within the firmware input limit is available to restart the depth budget. The task remains unexamined.",
    });
  }
  for (const entry of unpublished)
    rows.push({
      ...empty,
      input_path: `$output/${entry.relative_path}`,
      relative_path: entry.relative_path,
      kind: "unpublished-entry",
      continuation:
        "Retain the link or special entry as metadata; REA publishes only regular files without executable permissions.",
    });
  const sorted = rows.map((row) => firmwareExtractionGapSchema.parse(row));
  return sorted.sort((a, b) => {
    const key = (row: Gap) =>
      JSON.stringify([
        row.input_path,
        row.kind,
        row.provider_id,
        row.relative_path,
      ]);
    return key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0;
  });
};
