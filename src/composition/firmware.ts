import { FirmwareAnalysisRouter } from "../application/firmware/FirmwareAnalysisRouter.js";
import { BinwalkNgProvider } from "../firmware/binwalkNg/BinwalkNgProvider.js";
import type { FirmwareAnalysisPort } from "../application/firmware/FirmwareAnalysisPort.js";
import type { FirmwareLauncher } from "../firmware/FirmwareCommand.js";
import { FirmwareProvider } from "../firmware/FirmwareProvider.js";

/** Construct the selected firmware router without launching or acquiring an engine. */
export const createFirmwareAnalysisProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
  launcher?: FirmwareLauncher,
): FirmwareAnalysisPort => {
  const legacy = new FirmwareProvider(environment, launcher);
  return new FirmwareAnalysisRouter({
    binwalk: legacy,
    unblob: legacy,
    "binwalk-ng": new BinwalkNgProvider(environment, launcher),
  });
};
