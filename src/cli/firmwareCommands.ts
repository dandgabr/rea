import { z } from "incur";
import { FirmwareAnalysisService } from "../application/firmware/FirmwareAnalysisService.js";
import { createFirmwareAnalysisProvider } from "../composition/firmware.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { legacyFirmwareInputSchemas } from "../domain/firmware/firmwareAnalysis.js";
import { binwalkNgScanFields } from "../domain/firmware/binwalkNgAnalysis.js";
import { localPathStringSchema } from "../domain/localPath.js";
import type { FirmwareOperation } from "../domain/firmware/firmwareAnalysis.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";

/** One-shot CLI intent uses the same named contracts and producing owners as MCP. */
export const registerFirmwareCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
): void => {
  const service = new FirmwareAnalysisService(
    createFirmwareAnalysisProvider(environment),
  );
  const extract = legacyFirmwareInputSchemas.extract_firmware.shape;
  const range = extract.range.unwrap().shape;
  const execute = (
    name: string,
    operation: FirmwareOperation,
    input: unknown,
  ) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, () => {
        const requestedProvider =
          input !== null && typeof input === "object" && "provider_id" in input
            ? input.provider_id
            : undefined;
        return finishAnalysisCommand(
          () => service.execute(operation, input, { signal }),
          service,
          typeof requestedProvider === "string"
            ? requestedProvider
            : operation === "inspect_firmware_regions"
              ? "binwalk"
              : "unblob",
          operation,
          undefined,
          signal,
        );
      }),
    );
  const path = localPathStringSchema.describe(
    "Local firmware path; never executed",
  );
  const selectionOptions = {
    offset: range.offset
      .optional()
      .describe("Selected byte offset; requires length"),
    length: range.length
      .optional()
      .describe("Selected byte length; requires offset"),
  };
  const selection = (options: {
    offset?: number | undefined;
    length?: number | undefined;
  }) =>
    options.offset === undefined && options.length === undefined
      ? {}
      : { range: { offset: options.offset, length: options.length } };
  const scanOptions = {
    searchAll: binwalkNgScanFields.search_all
      .removeDefault()
      .optional()
      .describe("Ng only: search all signature offsets"),
    include: binwalkNgScanFields.include
      .removeDefault()
      .optional()
      .describe(
        "Ng only: repeat exact included signature names; conflicts with exclude",
      ),
    exclude: binwalkNgScanFields.exclude
      .removeDefault()
      .optional()
      .describe("Ng only: repeat exact excluded signature names"),
    mmap: binwalkNgScanFields.no_mmap
      .removeDefault()
      .optional()
      .describe("Ng only: use native memory maps; --no-mmap disables them"),
    workers: binwalkNgScanFields.workers
      .removeDefault()
      .optional()
      .describe("Ng only: positive native thread count, default 1"),
  };
  const nativeOptions = (options: {
    searchAll?: boolean | undefined;
    include?: string[] | undefined;
    exclude?: string[] | undefined;
    mmap?: boolean | undefined;
    workers?: number | undefined;
  }) => ({
    ...(options.searchAll === undefined
      ? {}
      : { search_all: options.searchAll }),
    ...(options.include === undefined ? {} : { include: options.include }),
    ...(options.exclude === undefined ? {} : { exclude: options.exclude }),
    ...(options.mmap === undefined ? {} : { no_mmap: !options.mmap }),
    ...(options.workers === undefined ? {} : { workers: options.workers }),
  });
  const outputArgs = {
    path,
    outputDirectory: localPathStringSchema.describe(
      "Absent output directory; parent must exist",
    ),
  };
  const budgetOptions = {
    maxOutputBytes: extract.max_output_bytes,
    maxOutputFiles: extract.max_output_files,
  };
  const unblobBudgetOptions = {
    maxOutputBytes: extract.max_output_bytes.describe(
      "Unblob only: staging file-byte budget",
    ),
    maxOutputFiles: extract.max_output_files.describe(
      "Unblob only: staging entry budget",
    ),
  };
  cli.command(CLI_COMMANDS.inspectFirmwareRegions, {
    description:
      "Inspect default Binwalk3 or explicitly selected binwalk-ng signatures",
    args: z.object({ path }),
    options: z.object({
      provider: z.enum(["binwalk", "binwalk-ng"]).default("binwalk"),
      ...selectionOptions,
      ...scanOptions,
    }),
    run: ({ args, options }) => {
      const selected = {
        path: absoluteCallerPath(args.path),
        ...selection(options),
      };
      const scan = nativeOptions(options);
      return execute(
        CLI_COMMANDS.inspectFirmwareRegions,
        "inspect_firmware_regions",
        options.provider === "binwalk-ng"
          ? { ...selected, provider_id: "binwalk-ng", options: scan }
          : {
              ...selected,
              ...(Object.keys(scan).length === 0 ? {} : { options: scan }),
            },
      );
    },
  });
  cli.command(CLI_COMMANDS.extractFirmware, {
    description:
      "Extract firmware with Unblob; Binwalk-NG extraction is unavailable in this release",
    args: z.object(outputArgs),
    options: z.object({
      provider: z
        .enum(["unblob", "binwalk-ng"])
        .default("unblob")
        .describe(
          "Binwalk-NG is listed for explicit selection but returns capability-unavailable for extraction",
        ),
      ...selectionOptions,
      ...unblobBudgetOptions,
      maxDepth: extract.max_depth.describe(
        "Unblob only: maximum recursive extraction depth",
      ),
    }),
    run: ({ args, options }) => {
      return execute(CLI_COMMANDS.extractFirmware, "extract_firmware", {
        path: absoluteCallerPath(args.path),
        output_directory: absoluteCallerPath(args.outputDirectory),
        ...selection(options),
        max_depth: options.maxDepth,
        max_output_bytes: options.maxOutputBytes,
        max_output_files: options.maxOutputFiles,
        ...(options.provider === "binwalk-ng"
          ? { provider_id: "binwalk-ng" }
          : {}),
      });
    },
  });
  cli.command(CLI_COMMANDS.carveFirmware, {
    description: "Carve native known/unknown regions with binwalk-ng",
    args: z.object(outputArgs),
    options: z.object({
      provider: z.literal("binwalk-ng").default("binwalk-ng"),
      ...selectionOptions,
      ...scanOptions,
      ...budgetOptions,
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.carveFirmware, "carve_firmware", {
        provider_id: options.provider,
        path: absoluteCallerPath(args.path),
        output_directory: absoluteCallerPath(args.outputDirectory),
        ...selection(options),
        options: nativeOptions(options),
        max_output_bytes: options.maxOutputBytes,
        max_output_files: options.maxOutputFiles,
      }),
  });
  cli.command(CLI_COMMANDS.inspectFirmwareEntropy, {
    description:
      "Measure native binwalk-ng Shannon bits per byte and optionally publish its PNG",
    args: z.object({ path }),
    options: z.object({
      provider: z.literal("binwalk-ng").default("binwalk-ng"),
      ...selectionOptions,
      ...budgetOptions,
      outputDirectory: localPathStringSchema
        .optional()
        .describe("Optionally publish entropy.png into this fresh directory"),
    }),
    run: ({ args, options }) =>
      execute(CLI_COMMANDS.inspectFirmwareEntropy, "inspect_firmware_entropy", {
        provider_id: options.provider,
        path: absoluteCallerPath(args.path),
        ...selection(options),
        max_output_bytes: options.maxOutputBytes,
        max_output_files: options.maxOutputFiles,
        ...(options.outputDirectory === undefined
          ? {}
          : { output_directory: absoluteCallerPath(options.outputDirectory) }),
      }),
  });
  cli.command(CLI_COMMANDS.inspectFirmwareProvider, {
    description:
      "Inspect native binwalk-ng formats and selected runtime identity",
    options: z.object({
      provider: z.literal("binwalk-ng").default("binwalk-ng"),
    }),
    run: ({ options }) =>
      execute(
        CLI_COMMANDS.inspectFirmwareProvider,
        "inspect_firmware_provider",
        { provider_id: options.provider },
      ),
  });
};
