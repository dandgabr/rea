import { setTimeout as delay } from "node:timers/promises";

import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  FridaDeviceSelector,
  FridaInstrumentationPort,
  FridaRemoteConnection,
  FridaScriptObservation,
  FridaScriptSource,
  FridaSessionStatus,
  StartFridaSessionInput,
} from "./FridaInstrumentationPort.js";

/** Shared CLI/MCP workflows for Frida's device and instrumentation operations. */
export class FridaInstrumentationService {
  readonly #provider: FridaInstrumentationPort;

  constructor(provider: FridaInstrumentationPort) {
    this.#provider = provider;
  }

  listDevices(remote?: FridaRemoteConnection) {
    return this.#provider.listDevices(remote);
  }

  listProcesses(selector: FridaDeviceSelector) {
    return this.#provider.listProcesses(selector);
  }

  async startSession(input: StartFridaSessionInput, signal?: AbortSignal) {
    const started = await this.#provider.startSession(input);
    if (!started.ok || !signal?.aborted) return started;
    const closed = await this.#provider.closeSession(started.value.sessionId);
    return err(
      new AnalysisCancelledError("start_frida_session", {
        cause: signal.reason,
        ...(closed.ok
          ? {}
          : {
              cleanup: {
                reason: closed.error.message,
                resources: [started.value.sessionId],
              },
            }),
      }),
    );
  }

  async loadScript(
    sessionId: string,
    source: FridaScriptSource,
  ): Promise<Result<Evidence, AnalysisError>> {
    const loaded = await this.#provider.loadScript(sessionId, source);
    return loaded.ok
      ? ok(
          fridaEvidence(
            "load_frida_script",
            scriptOutput(loaded.value),
            sessionId,
          ),
        )
      : loaded;
  }

  resumeSession(sessionId: string) {
    return this.#provider.resumeSession(sessionId);
  }

  unloadScript(sessionId: string, scriptId: string) {
    return this.#provider.unloadScript(sessionId, scriptId);
  }

  status(sessionId: string): FridaSessionStatus | undefined {
    return this.#provider.status(sessionId);
  }

  statusEvidence(sessionId: string): Evidence | undefined {
    const status = this.#provider.status(sessionId);
    return status === undefined
      ? undefined
      : fridaEvidence(
          "frida_session_status",
          sessionStatusOutput(status),
          sessionId,
        );
  }

  async instrument(
    input: StartFridaSessionInput & {
      readonly source: FridaScriptSource;
      readonly durationMs: number;
    },
    signal?: AbortSignal,
  ): Promise<
    Result<
      { readonly evidence: Evidence; readonly cleanupError: string | null },
      AnalysisError
    >
  > {
    const started = await this.startSession(input, signal);
    if (!started.ok) return started;
    const loaded = await this.#provider.loadScript(
      started.value.sessionId,
      input.source,
    );
    if (!loaded.ok) {
      const closed = await this.#provider.closeSession(started.value.sessionId);
      return closed.ok
        ? loaded
        : err(
            withCleanupFailure(
              loaded.error,
              closed.error.message,
              started.value.sessionId,
            ),
          );
    }
    if (started.value.mode === "spawn") {
      const resumed = await this.#provider.resumeSession(
        started.value.sessionId,
      );
      if (!resumed.ok) {
        const closed = await this.#provider.closeSession(
          started.value.sessionId,
        );
        return closed.ok
          ? resumed
          : err(
              withCleanupFailure(
                resumed.error,
                closed.error.message,
                started.value.sessionId,
              ),
            );
      }
    }
    try {
      await delay(input.durationMs, undefined, { signal });
    } catch (cause: unknown) {
      const closed = await this.#provider.closeSession(started.value.sessionId);
      return err(
        new AnalysisCancelledError("instrument_with_frida", {
          cause,
          ...(closed.ok
            ? {}
            : {
                cleanup: {
                  reason: closed.error.message,
                  resources: [started.value.sessionId],
                },
              }),
        }),
      );
    }
    const status = this.#provider.status(started.value.sessionId);
    const observation = status ?? {
      ...started.value,
      scripts: [],
      messages: loaded.value.messages,
      messagesTruncated: loaded.value.messagesTruncated,
    };
    const closed = await this.#provider.closeSession(started.value.sessionId);
    const cleanupError = closed.ok ? null : closed.error.message;
    const evidence = fridaEvidence(
      "instrument_with_frida",
      {
        ...sessionStatusOutput(observation),
        source_kind: loaded.value.sourceKind,
        source_path: loaded.value.sourcePath,
        source_sha256: loaded.value.sourceSha256,
        cleanup_error: cleanupError,
      },
      started.value.sessionId,
    );
    return ok({
      evidence,
      cleanupError,
    });
  }

  closeSession(sessionId: string) {
    return this.#provider.closeSession(sessionId);
  }

  closeAll(): Promise<void> {
    return this.#provider.closeAll();
  }
}

const fridaEvidence = (
  operation: string,
  result: unknown,
  sessionId: string,
): Evidence =>
  createEvidence(
    undefined,
    { id: "frida", name: "Frida", version: null },
    {
      predicateType: "rea.frida.instrumentation-observation",
      operation,
      parameters: { session_id: sessionId },
      result: jsonValueSchema.parse(result),
      confidence: "observed",
      authority: "external-service",
      environment: null,
      limitations: [
        "The target operating system and architecture were not reported by this observation.",
      ],
    },
  );

const withCleanupFailure = (
  original: AnalysisError,
  cleanupReason: string,
  sessionId: string,
): AnalysisError =>
  new AnalysisCapabilityUnavailableError(
    "frida",
    "instrument_with_frida",
    `${original.message}; cleanup failed: ${cleanupReason}`,
    {
      cause: original,
      cleanup: {
        reason: cleanupReason,
        resources: [sessionId],
      },
    },
  );

const scriptOutput = (script: FridaScriptObservation) => ({
  script_id: script.scriptId,
  source_kind: script.sourceKind,
  source_path: script.sourcePath,
  source_sha256: script.sourceSha256,
  messages: script.messages,
  messages_truncated: script.messagesTruncated,
});

const sessionStatusOutput = (status: FridaSessionStatus) => ({
  session_id: status.sessionId,
  state: status.state,
  target: status.target,
  pid: status.pid,
  scripts: status.scripts.map((script) => ({
    script_id: script.scriptId,
    name: script.name,
  })),
  messages: status.messages,
  messages_truncated: status.messagesTruncated,
});
