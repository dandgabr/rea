import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { FirmwareCorpusService } from "../application/corpus/FirmwareCorpusService.js";
import type { Logger } from "pino";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { FIRMWARE_CORPUS_TOOL_CONTRACTS } from "../contracts/corpus/firmwareCorpusToolContracts.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Every handler owns its named contract; inventory order is irrelevant. */
export const registerFirmwareCorpusTools = (
  server: EvidenceMcpServer,
  service: FirmwareCorpusService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    service,
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  for (const contract of FIRMWARE_CORPUS_TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
};
