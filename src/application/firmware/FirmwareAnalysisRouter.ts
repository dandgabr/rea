import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { FirmwareRequest } from "../../domain/firmware/firmwareAnalysis.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import { err } from "../../domain/result.js";
import type { FirmwareAnalysisPort } from "./FirmwareAnalysisPort.js";

/** Dispatch exact requests to registered firmware providers without knowing their protocols. */
export class FirmwareAnalysisRouter implements FirmwareAnalysisPort {
  constructor(
    readonly providers: Readonly<Record<string, FirmwareAnalysisPort>>,
  ) {}
  execute(request: FirmwareRequest, options?: ExecutionOptions) {
    const provider = this.providers[request.input.provider_id];
    return provider === undefined
      ? Promise.resolve(
          err(
            new AnalysisCapabilityUnavailableError(
              request.input.provider_id,
              request.operation,
              "Selected firmware provider is not registered",
            ),
          ),
        )
      : provider.execute(request, options);
  }
  async close(): Promise<void> {
    const results = await Promise.allSettled(
      [...new Set(Object.values(this.providers))].map((provider) =>
        provider.close?.(),
      ),
    );
    const failures = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (failures.length === 1) throw failures[0];
    if (failures.length > 0)
      throw new AggregateError(failures, "Firmware provider cleanup failed");
  }
}
