import type { McpServer, ServerContext } from "@modelcontextprotocol/server";

import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import type { Logger } from "../logger.js";
import type { RizinDebugSessionManager } from "../rizin/RizinDebugSessionManager.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { toCallToolResult, toEvidenceToolResult } from "./toolResult.js";

/** Register persistent Rizin debugger operations on the existing REA MCP server. */
export const registerRizinDebugTools = (
  server: McpServer,
  manager: RizinDebugSessionManager,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
): void => {
  const start = toolContract("start_rizin_debug_session");
  const command = toolContract("rizin_debug_command");
  const status = toolContract("rizin_debug_session_status");
  const close = toolContract("close_rizin_debug_session");
  server.registerTool(
    start.name,
    toolRegistrationOptions(start),
    async (input, context: ServerContext) => {
      const result = await logToolExecution(logger, start.name, () =>
        manager.start(
          {
            path: input.path,
            ...(input.backend === undefined ? {} : { backend: input.backend }),
          },
          context.mcpReq.signal,
        ),
      );
      return result.ok
        ? toCallToolResult({ ok: true, value: result.value }, start)
        : toCallToolResult(result, start);
    },
  );
  server.registerTool(
    command.name,
    toolRegistrationOptions(command),
    async (input) => {
      const result = await logToolExecution(logger, command.name, () =>
        manager.execute(input.session_id, input.command),
      );
      if (!result.ok) return toCallToolResult(result, command);
      return toEvidenceToolResult(
        result.value.evidence,
        command,
        recordEvidence?.(result.value.evidence),
      );
    },
  );
  server.registerTool(
    status.name,
    toolRegistrationOptions(status),
    async (input) => {
      const result = manager.status(input.session_id);
      if (result === undefined)
        return toCallToolResult(
          { ok: false, error: new AnalysisInputError(status.name) },
          status,
        );
      return toCallToolResult(
        {
          ok: true,
          value: { ...result, recent_output: [...result.recent_output] },
        },
        status,
      );
    },
  );
  server.registerTool(
    close.name,
    toolRegistrationOptions(close),
    async (input) => {
      const result = await logToolExecution(logger, close.name, () =>
        manager.close(input.session_id),
      );
      return result.ok
        ? toCallToolResult({ ok: true, value: result.value }, close)
        : toCallToolResult(result, close);
    },
  );
};
