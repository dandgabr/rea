import { z } from "incur";
import { FirmwareAnalysisService } from "../application/firmware/FirmwareAnalysisService.js";
import { createFirmwareAnalysisProvider } from "../composition/firmware.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import {
  firmwareInputSchemas,
  unblobOptionsSchema,
  unblobExtractionOptionsSchema,
} from "../domain/firmware/firmwareAnalysis.js";
import { localPathStringSchema } from "../domain/localPath.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { safeParseJson } from "../domain/safeJson.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { FirmwareOperation } from "../domain/firmware/firmwareAnalysis.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";

/** One-shot firmware CLI commands backed by the same workflows as MCP. */
export const registerFirmwareCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
): void => {
  const service = new FirmwareAnalysisService(
    createFirmwareAnalysisProvider(environment),
  );
  const extractInput = firmwareInputSchemas.extract_firmware.shape;
  const range = extractInput.range.unwrap().shape;
  const runtime = z
    .string()
    .optional()
    .describe(
      'Inline JSON runtime selection, for example {"kind":"native"}; caller-container runtime is currently unavailable',
    );
  const selectionOptions = {
    offset: range.offset
      .optional()
      .describe("Selected byte offset; requires length"),
    length: range.length
      .optional()
      .describe("Selected byte length; requires offset"),
  };
  const unblobOptions = {
    workers: unblobOptionsSchema.shape.workers
      .removeDefault()
      .optional()
      .describe("Maximum Unblob worker processes"),
    randomnessDepth: unblobOptionsSchema.shape.randomness_depth
      .removeDefault()
      .optional()
      .describe("Randomness analysis depth"),
    skipMagic: z
      .array(z.string())
      .optional()
      .describe("Repeatable native magic prefix; appended by default"),
    clearSkipMagics: z
      .boolean()
      .optional()
      .describe(
        "Replace native skip magic defaults with the selected prefixes",
      ),
    skipExtension: z
      .array(z.string())
      .optional()
      .describe("Repeatable replacement for native skip extension defaults"),
  };
  const selection = (options: {
    offset?: number | undefined;
    length?: number | undefined;
  }) =>
    options.offset === undefined && options.length === undefined
      ? {}
      : { range: { offset: options.offset, length: options.length } };
  const nativeOptions = (options: {
    workers?: number | undefined;
    randomnessDepth?: number | undefined;
    skipMagic?: string[] | undefined;
    clearSkipMagics?: boolean | undefined;
    skipExtension?: string[] | undefined;
  }) => ({
    ...(options.workers === undefined ? {} : { workers: options.workers }),
    ...(options.randomnessDepth === undefined
      ? {}
      : { randomness_depth: options.randomnessDepth }),
    ...(options.skipMagic === undefined && options.clearSkipMagics !== true
      ? {}
      : {
          skip_magic: {
            mode: options.clearSkipMagics === true ? "replace" : "append",
            values: options.skipMagic ?? [],
          },
        }),
    ...(options.skipExtension === undefined
      ? {}
      : { skip_extensions: options.skipExtension }),
  });
  const execute = (
    name: string,
    operation: FirmwareOperation,
    input: Readonly<Record<string, unknown>>,
  ) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, async () => {
        let selectedInput = input;
        if (typeof input.runtime === "string") {
          const parsed = safeParseJson(input.runtime);
          if (!parsed.ok)
            return projectAnalysisError(
              new AnalysisInputError(operation, undefined, [
                {
                  path: ["runtime"],
                  reason: "invalid_format",
                  expected: "JSON",
                },
              ]),
            );
          selectedInput = { ...input, runtime: parsed.value };
        }
        return finishAnalysisCommand(
          () => service.execute(operation, selectedInput, { signal }),
          service,
          typeof selectedInput.provider_id === "string"
            ? selectedInput.provider_id
            : "unblob",
          operation,
          signal,
        );
      }),
    );
  const path = localPathStringSchema.describe(
    "Local firmware path; never executed",
  );
  cli.command(CLI_COMMANDS.inspectFirmwareProvider, {
    description:
      "Inspect selected tool identity, dependency lookup and native documented formats",
    options: z.object({
      providerId: z.literal("unblob").describe("Selected provider identity"),
      runtime,
    }),
    run: ({ options }) =>
      execute(
        CLI_COMMANDS.inspectFirmwareProvider,
        "inspect_firmware_provider",
        {
          provider_id: options.providerId,
          ...(options.runtime === undefined
            ? {}
            : { runtime: options.runtime }),
        },
      ),
  });
  cli.command(CLI_COMMANDS.inspectFirmwareRegions, {
    description:
      "Inspect firmware signature candidates without extracting them",
    args: z.object({ path }),
    options: z.object({
      providerId: z
        .enum(["binwalk", "unblob"])
        .default("binwalk")
        .describe("Firmware analysis provider"),
      runtime,
      ...selectionOptions,
      ...unblobOptions,
    }),
    run: ({ args, options }) =>
      execute(
        CLI_COMMANDS.inspectFirmwareRegions,
        "inspect_firmware_regions",
        // CLI paths are operator-relative; resolve before shared validation.
        {
          path: absoluteCallerPath(args.path),
          provider_id: options.providerId,
          ...(options.runtime === undefined
            ? {}
            : { runtime: options.runtime }),
          ...selection(options),
          ...(Object.keys(nativeOptions(options)).length === 0
            ? {}
            : { options: nativeOptions(options) }),
        },
      ),
  });
  cli.command(CLI_COMMANDS.extractFirmware, {
    description:
      "Extract selected firmware bytes and return verified files and provenance",
    args: z.object({
      path,
      outputDirectory: localPathStringSchema.describe(
        "Absent output directory; parent must exist",
      ),
    }),
    options: z.object({
      providerId: z
        .literal("unblob")
        .default("unblob")
        .describe("Firmware extraction provider"),
      runtime,
      ...selectionOptions,
      ...unblobOptions,
      keepExtractedChunks:
        unblobExtractionOptionsSchema.shape.keep_extracted_chunks
          .removeDefault()
          .optional()
          .describe("Keep intermediate extracted chunks"),
      deleteExtractedFiles: z
        .enum(["none", "all", "selected"])
        .optional()
        .describe("Select which extracted files to delete"),
      deleteHandler: z
        .array(z.string())
        .optional()
        .describe("Repeatable handler; requires selected deletion mode"),
      carveSuffix: unblobExtractionOptionsSchema.shape.carve_suffix
        .removeDefault()
        .optional()
        .describe("Suffix for carved output files"),
      extractSuffix: unblobExtractionOptionsSchema.shape.extract_suffix
        .removeDefault()
        .optional()
        .describe("Suffix for extracted output files"),
      maxDepth: extractInput.max_depth.describe("Maximum extraction depth"),
      maxOutputBytes: extractInput.max_output_bytes.describe(
        "Maximum total published output bytes",
      ),
      maxOutputFiles: extractInput.max_output_files.describe(
        "Maximum number of published output files",
      ),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.extractFirmware, "extract_firmware", {
        path: absoluteCallerPath(args.path),
        output_directory: absoluteCallerPath(args.outputDirectory),
        provider_id: options.providerId,
        ...(options.runtime === undefined ? {} : { runtime: options.runtime }),
        ...selection(options),
        options: {
          ...nativeOptions(options),
          ...(options.keepExtractedChunks === undefined
            ? {}
            : { keep_extracted_chunks: options.keepExtractedChunks }),
          ...(options.deleteExtractedFiles === undefined &&
          options.deleteHandler === undefined
            ? {}
            : {
                delete_extracted_files: {
                  mode: options.deleteExtractedFiles ?? "none",
                  ...(options.deleteHandler === undefined
                    ? {}
                    : { handlers: options.deleteHandler }),
                },
              }),
          ...(options.carveSuffix === undefined
            ? {}
            : { carve_suffix: options.carveSuffix }),
          ...(options.extractSuffix === undefined
            ? {}
            : { extract_suffix: options.extractSuffix }),
        },
        max_depth: options.maxDepth,
        max_output_bytes: options.maxOutputBytes,
        max_output_files: options.maxOutputFiles,
      }),
  });
};
