import type { McpServer } from "@modelcontextprotocol/server";

import type { CutterBridgeService } from "../cutter/CutterBridgeService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import { ok } from "../domain/result.js";
import type { Logger } from "../logger.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { toCallToolResult, toEvidenceToolResult } from "./toolResult.js";

/** Register Cutter discovery and command tools against their named contracts. */
export const registerCutterTools = (
  server: McpServer,
  service: CutterBridgeService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
): void => {
  const list = toolContract("list_cutter_sessions");
  const command = toolContract("cutter_command");
  server.registerTool(list.name, toolRegistrationOptions(list), async () => {
    const result = await logToolExecution(logger, list.name, async () =>
      ok(await service.listSessions()),
    );
    if (!result.ok) return toCallToolResult(result, list);
    return toCallToolResult(
      {
        ok: true,
        value: { ...result.value, sessions: [...result.value.sessions] },
      },
      list,
    );
  });
  server.registerTool(
    command.name,
    toolRegistrationOptions(command),
    async (input) => {
      const result = await logToolExecution(logger, command.name, () =>
        service.execute(input),
      );
      if (!result.ok) return toCallToolResult(result, command);
      return toEvidenceToolResult(
        result.value,
        command,
        recordEvidence?.(result.value),
      );
    },
  );
};
