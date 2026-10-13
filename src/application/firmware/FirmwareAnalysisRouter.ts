import type { FirmwareAnalysisPort } from "./FirmwareAnalysisPort.js";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  isLegacyFirmwareRequest,
  type FirmwareRequest,
} from "../../domain/firmware/firmwareAnalysis.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../../domain/analysisErrorCleanup.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import { err } from "../../domain/result.js";
/** Route a validated explicit provider choice; omitted legacy requests keep their defaults. */
export class FirmwareAnalysisRouter implements FirmwareAnalysisPort {
  constructor(
    readonly providers: Readonly<Record<string, FirmwareAnalysisPort>>,
  ) {}
  execute(
    request: FirmwareRequest,
    options?: ExecutionOptions,
  ): ReturnType<FirmwareAnalysisPort["execute"]> {
    const id = isLegacyFirmwareRequest(request)
      ? request.operation === "extract_firmware"
        ? "unblob"
        : "binwalk"
      : request.input.provider_id;
    const provider = this.providers[id];
    return provider === undefined
      ? Promise.resolve(
          err(
            new AnalysisCapabilityUnavailableError(
              id,
              request.operation,
              "The explicitly selected firmware provider is not configured",
            ),
          ),
        )
      : provider.execute(request, options);
  }
  async close(): Promise<void> {
    const failures: unknown[] = [];
    for (const provider of new Set(Object.values(this.providers))) {
      try {
        await provider.close?.();
      } catch (cause: unknown) {
        failures.push(cause);
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) {
      const typed = failures.map((cause) =>
        cause instanceof AnalysisError
          ? cause
          : new ProviderCleanupError(
              "firmware",
              [],
              {
                reason: cause instanceof Error ? cause.message : String(cause),
              },
              { operation: "close_firmware", cause },
            ),
      );
      let primary = typed[0];
      if (primary === undefined) return;
      for (const cleanup of typed.slice(1))
        primary = analysisErrorWithCleanupFailure(
          primary,
          cleanup,
          "close_firmware",
        );
      throw primary;
    }
  }
}
