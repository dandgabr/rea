import type { FirmwareAnalysisPort } from "../application/firmware/FirmwareAnalysisPort.js";
import type { FirmwareLauncher } from "../firmware/FirmwareCommand.js";
import { FirmwareAnalysisRouter } from "../application/firmware/FirmwareAnalysisRouter.js";
import { FirmwareProvider } from "../firmware/FirmwareProvider.js";

/** Construct one firmware provider without launching or acquiring an engine. */
export const createFirmwareAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
  launcher?: FirmwareLauncher,
): FirmwareAnalysisPort => {
  const provider = new FirmwareProvider(environment, launcher);
  return new FirmwareAnalysisRouter({ binwalk: provider, unblob: provider });
};
