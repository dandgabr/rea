import { z } from "incur";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { FirmwareCorpusService } from "../application/corpus/FirmwareCorpusService.js";
import { createFirmwareCorpusProvider } from "../composition/firmwareCorpus.js";
import { FIRMWARE_CORPUS_TOOL_CONTRACTS } from "../contracts/corpus/firmwareCorpusToolContracts.js";
import { parseCliJsonInput } from "../cliJsonInput.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { isCliOperationFailure, logCliCommand } from "../cliLogging.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";

export const registerFirmwareCorpusCommands = (
  cli: CliInstance,
  logger: Logger,
  createService: () => FirmwareCorpusService = () =>
    new FirmwareCorpusService(createFirmwareCorpusProvider()),
): void => {
  for (const contract of FIRMWARE_CORPUS_TOOL_CONTRACTS) {
    const command = CLI_COMMANDS[contract.name];
    cli.command(command, {
      description: contract.description,
      args: z.object({
        inputJson: z
          .string()
          .describe(
            "Exact named workflow JSON or JSON file path; artifact/native paths must be absolute",
          ),
      }),
      run: ({ args }) =>
        withCommandCancellation((signal) =>
          logCliCommand(
            logger,
            command,
            async () => {
              const parsed = await parseCliJsonInput(
                args.inputJson,
                contract.name,
              );
              if (!parsed.ok) return parsed.error;
              const service = createService();
              const result = await service.execute(
                contract.name,
                parsed.value,
                { signal },
              );
              try {
                await service.close();
              } catch (cause) {
                const cleanup =
                  cause instanceof AnalysisError
                    ? cause
                    : new ProviderCleanupError(
                        "fact-core",
                        [],
                        {
                          reason: "Corpus owner cleanup could not be confirmed",
                        },
                        { cause, operation: contract.name },
                      );
                if (result.ok) cleanup.retainPartialObservation(result.value);
                return projectAnalysisError(
                  result.ok
                    ? cleanup
                    : analysisErrorWithCleanupFailure(
                        result.error,
                        cleanup,
                        contract.name,
                      ),
                );
              }
              return result.ok
                ? result.value
                : projectAnalysisError(result.error);
            },
            (value) => {
              if (
                typeof value !== "object" ||
                value === null ||
                !("normalized_result" in value)
              )
                return isCliOperationFailure(value);
              const result = value.normalized_result;
              return (
                typeof result === "object" &&
                result !== null &&
                "state" in result &&
                ["failed", "unknown", "not-delivered"].includes(
                  String(result.state),
                )
              );
            },
          ),
        ),
    });
  }
};
