import type { McpServer, ServerContext } from "@modelcontextprotocol/server";

import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { FridaInstrumentationService } from "../application/frida/FridaInstrumentationService.js";
import type { FridaInstrumentationPort } from "../application/frida/FridaInstrumentationPort.js";
import type { FridaRemoteConnection } from "../application/frida/FridaInstrumentationPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import type { Logger } from "../logger.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { toCallToolResult, toEvidenceToolResult } from "./toolResult.js";

/** Register Frida device discovery and persistent instrumentation operations. */
export const registerFridaTools = (
  server: McpServer,
  provider: FridaInstrumentationPort,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
): void => {
  const service = new FridaInstrumentationService(provider);
  const listDevices = toolContract("list_frida_devices");
  const listProcesses = toolContract("list_frida_processes");
  const start = toolContract("start_frida_session");
  const load = toolContract("load_frida_script");
  const resume = toolContract("resume_frida_session");
  const unload = toolContract("unload_frida_script");
  const status = toolContract("frida_session_status");
  const close = toolContract("close_frida_session");
  const instrument = toolContract("instrument_with_frida");

  server.registerTool(
    listDevices.name,
    toolRegistrationOptions(listDevices),
    async (input) => {
      const result = await logToolExecution(logger, listDevices.name, () =>
        service.listDevices(remoteConnection(input.remote)),
      );
      return result.ok
        ? toCallToolResult(
            {
              ok: true,
              value: jsonValueSchema.parse({
                devices: result.value.devices.map((device) => ({
                  device_id: device.deviceId,
                  name: device.name,
                  type: device.type,
                })),
                cleanup_error: result.value.cleanupError,
              }),
            },
            listDevices,
          )
        : toCallToolResult(result, listDevices);
    },
  );
  server.registerTool(
    listProcesses.name,
    toolRegistrationOptions(listProcesses),
    async (input) => {
      const remote = remoteConnection(input.remote);
      const result = await logToolExecution(logger, listProcesses.name, () =>
        service.listProcesses({
          ...(input.device_id === undefined
            ? {}
            : { deviceId: input.device_id }),
          ...(remote === undefined ? {} : { remote }),
        }),
      );
      return result.ok
        ? toCallToolResult(
            {
              ok: true,
              value: jsonValueSchema.parse({
                device_id: result.value.deviceId,
                processes: result.value.processes,
                cleanup_error: result.value.cleanupError,
              }),
            },
            listProcesses,
          )
        : toCallToolResult(result, listProcesses);
    },
  );
  server.registerTool(
    start.name,
    toolRegistrationOptions(start),
    async (input, context: ServerContext) => {
      const remote = remoteConnection(input.remote);
      const selected = {
        ...(input.device_id === undefined ? {} : { deviceId: input.device_id }),
        ...(remote === undefined ? {} : { remote }),
      };
      const result = await logToolExecution(logger, start.name, () =>
        input.mode === "attach"
          ? service.startSession(
              {
                ...selected,
                mode: input.mode,
                pid: input.pid,
              },
              context.mcpReq.signal,
            )
          : service.startSession(
              {
                ...selected,
                mode: input.mode,
                program: input.program,
                ...(input.argv === undefined ? {} : { argv: input.argv }),
              },
              context.mcpReq.signal,
            ),
      );
      if (!result.ok) return toCallToolResult(result, start);
      return toCallToolResult(
        {
          ok: true,
          value: jsonValueSchema.parse(sessionOutput(result.value)),
        },
        start,
      );
    },
  );
  server.registerTool(
    load.name,
    toolRegistrationOptions(load),
    async (input) => {
      const result = await logToolExecution(logger, load.name, () =>
        service.loadScript(
          input.session_id,
          input.source_kind === "inline"
            ? { sourceKind: "inline", source: input.source }
            : { sourceKind: "file", path: input.path },
        ),
      );
      if (!result.ok) return toCallToolResult(result, load);
      return toEvidenceToolResult(
        result.value,
        load,
        recordEvidence?.(result.value),
      );
    },
  );
  server.registerTool(
    resume.name,
    toolRegistrationOptions(resume),
    async (input) => {
      const result = await logToolExecution(logger, resume.name, () =>
        service.resumeSession(input.session_id),
      );
      return result.ok
        ? toCallToolResult({ ok: true, value: { state: "running" } }, resume)
        : toCallToolResult(result, resume);
    },
  );
  server.registerTool(
    unload.name,
    toolRegistrationOptions(unload),
    async (input) => {
      const result = await logToolExecution(logger, unload.name, () =>
        service.unloadScript(input.session_id, input.script_id),
      );
      return result.ok
        ? toCallToolResult({ ok: true, value: { unloaded: true } }, unload)
        : toCallToolResult(result, unload);
    },
  );
  server.registerTool(
    status.name,
    toolRegistrationOptions(status),
    async (input) => {
      const evidence = service.statusEvidence(input.session_id);
      if (evidence === undefined)
        return toCallToolResult(
          {
            ok: false,
            error: new AnalysisInputError(status.name),
          },
          status,
        );
      return toEvidenceToolResult(evidence, status, recordEvidence?.(evidence));
    },
  );
  server.registerTool(
    close.name,
    toolRegistrationOptions(close),
    async (input) => {
      const result = await logToolExecution(logger, close.name, () =>
        service.closeSession(input.session_id),
      );
      return result.ok
        ? toCallToolResult(
            { ok: true, value: { target_state: "unknown" } },
            close,
          )
        : toCallToolResult(result, close);
    },
  );
  server.registerTool(
    instrument.name,
    toolRegistrationOptions(instrument),
    async (input, context: ServerContext) => {
      const remote = remoteConnection(input.remote);
      const selected = {
        ...(input.device_id === undefined ? {} : { deviceId: input.device_id }),
        ...(remote === undefined ? {} : { remote }),
      };
      const source =
        input.source_kind === "inline"
          ? { sourceKind: "inline" as const, source: input.source }
          : { sourceKind: "file" as const, path: input.path };
      const result = await logToolExecution(logger, instrument.name, () =>
        service.instrument(
          input.mode === "attach"
            ? {
                ...selected,
                mode: "attach",
                pid: input.pid,
                source,
                durationMs: input.duration_ms,
              }
            : {
                ...selected,
                mode: "spawn",
                program: input.program,
                ...(input.argv === undefined ? {} : { argv: input.argv }),
                source,
                durationMs: input.duration_ms,
              },
          context.mcpReq.signal,
        ),
      );
      if (!result.ok) return toCallToolResult(result, instrument);
      return toEvidenceToolResult(
        result.value.evidence,
        instrument,
        recordEvidence?.(result.value.evidence),
      );
    },
  );
};

const remoteConnection = (
  input:
    | {
        readonly address: string;
        readonly token?: string | undefined;
        readonly certificate?: string | undefined;
        readonly origin?: string | undefined;
        readonly keepalive_interval?: number | undefined;
      }
    | undefined,
): FridaRemoteConnection | undefined =>
  input === undefined
    ? undefined
    : {
        address: input.address,
        ...(typeof input.token === "string" ? { token: input.token } : {}),
        ...(typeof input.certificate === "string"
          ? { certificate: input.certificate }
          : {}),
        ...(typeof input.origin === "string" ? { origin: input.origin } : {}),
        ...(typeof input.keepalive_interval === "number"
          ? { keepaliveInterval: input.keepalive_interval }
          : {}),
      };

const sessionOutput = (session: {
  readonly sessionId: string;
  readonly deviceId: string;
  readonly target: string;
  readonly pid: number;
  readonly mode: "attach" | "spawn";
  readonly state: "paused" | "running" | "detached";
}) => ({
  session_id: session.sessionId,
  device_id: session.deviceId,
  target: session.target,
  pid: session.pid,
  mode: session.mode,
  state: session.state,
});
