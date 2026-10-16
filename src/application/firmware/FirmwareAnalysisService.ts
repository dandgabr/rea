import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { FirmwareAnalysisPort } from "./FirmwareAnalysisPort.js";
import {
  firmwareRequestSchema,
  type FirmwareOperation,
} from "../../domain/firmware/firmwareAnalysis.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";

/** Shared CLI/MCP validation and Evidence composition for arbitrary firmware files. */
export class FirmwareAnalysisService {
  constructor(readonly provider: FirmwareAnalysisPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  /** Execute an explicit inspection or extraction and preserve its producing identity. */
  async execute(
    operation: FirmwareOperation,
    input: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError(operation));
    const parsed = firmwareRequestSchema.safeParse({ operation, input });
    if (!parsed.success)
      return err(new AnalysisInputError(operation, { cause: parsed.error }));
    const executed = await this.provider.execute(parsed.data, options);
    if (!executed.ok) return executed;
    const execution = executed.value;
    if (execution.subject === null && operation !== "inspect_firmware_provider")
      return err(
        new AnalysisOutputError(
          operation,
          "Firmware execution did not bind its source artifact",
        ),
      );
    return completeProviderEvidence(
      createEvidence(execution.subject ?? undefined, execution.provider, {
        operation,
        parameters: jsonObjectSchema.parse(parsed.data.input),
        result: execution.result,
        rawResult: execution.rawResult,
        locations: execution.locations,
        limitations: execution.limitations,
        confidence: "observed",
        ...(operation === "inspect_firmware_provider"
          ? {
              subjectUnavailableReason:
                "Provider inventory describes the selected tool; no firmware artifact was analyzed.",
            }
          : {}),
      }),
      options?.signal,
    );
  }
}
