import { randomUUID } from "node:crypto";
import { resolve } from "node:path";

import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import {
  closeOwnedDebuggerSessions,
  stopOwnedDebuggerProcess,
} from "../process/ownedDebuggerSession.js";

const FRAME_TIMEOUT_MS = 120_000;
const STARTUP_TIMEOUT_MS = 30_000;
const MAX_FRAME_BYTES = 16 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_QUEUED_FRAME_BYTES = 4 * 1024 * 1024;
const MAX_QUEUED_FRAMES = 4096;
const MIN_QUEUED_FRAME_CHARGE_BYTES = 64;
const MAX_COMMAND_FRAMES = 4096;
const MAX_RECENT_FRAME_BYTES = 16 * 1024;
const MAX_DIAGNOSTIC_BYTES = 64 * 1024;

export const RIZIN_DEBUGGER_PROVIDER_IDENTITY = {
  id: "rizin.debugger",
  name: "Rizin debugger",
  version: null,
} as const;

interface RizinDebugSession {
  readonly id: string;
  readonly launched: SpawnedOwnedProviderProcess;
  readonly supervisor: ProviderProcessSupervisor;
  readonly frames: Array<{
    readonly text: string;
    readonly queueChargeBytes: number;
  }>;
  readonly frameWaiters: Array<{
    readonly resolve: (frame: string) => void;
    readonly reject: (cause: Error) => void;
  }>;
  readonly backend: string | null;
  readonly history: string[];
  queuedFrameBytes: number;
  historyTruncated: boolean;
  buffer: Buffer;
  ready: boolean;
  exited: boolean;
  commandTail: Promise<void>;
  protocolError: string | undefined;
}

/** Owns persistent Rizin debugger processes independently from BinarySession. */
export class RizinDebugSessionManager {
  readonly #sessions = new Map<string, RizinDebugSession>();
  readonly #command: string;
  readonly #frameTimeoutMs: number;

  constructor(
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
    options: { readonly frameTimeoutMs?: number } = {},
  ) {
    this.#command = environment.REA_RIZIN_COMMAND ?? "rizin";
    this.#frameTimeoutMs = options.frameTimeoutMs ?? FRAME_TIMEOUT_MS;
  }

  async start(
    input: { readonly path: string; readonly backend?: string },
    signal?: AbortSignal,
  ): Promise<
    Result<
      { readonly session_id: string; readonly backend: string | null },
      AnalysisError
    >
  > {
    const id = randomUUID();
    const arguments_ = [
      "-N",
      "-0",
      "-d",
      ...(input.backend === undefined ? [] : ["-D", input.backend]),
      resolve(input.path),
    ];
    let launched: SpawnedOwnedProviderProcess;
    try {
      launched = await spawnOwnedProviderProcess({
        command: this.#command,
        arguments: arguments_,
        runId: id,
        stdin: "pipe",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause) {
      if (signal?.aborted)
        return err(
          new AnalysisCancelledError("start_rizin_debug_session", { cause }),
        );
      return err(
        new AnalysisCapabilityUnavailableError(
          "rizin",
          "start_rizin_debug_session",
          cause instanceof Error
            ? cause.message
            : "Unable to start Rizin debugger",
        ),
      );
    }
    const session: RizinDebugSession = {
      id,
      launched,
      backend: input.backend ?? null,
      supervisor: new ProviderProcessSupervisor(
        { process: launched.process, ownsProcessLifetime: false },
        {
          captureStdout: false,
          maxDiagnosticBytes: MAX_DIAGNOSTIC_BYTES,
        },
      ),
      frames: [],
      frameWaiters: [],
      history: [],
      queuedFrameBytes: 0,
      historyTruncated: false,
      buffer: Buffer.alloc(0),
      ready: false,
      exited: false,
      commandTail: Promise.resolve(),
      protocolError: undefined,
    };
    this.#sessions.set(id, session);
    launched.process.stdout?.on("data", (chunk: Buffer | string) =>
      this.#receive(session, Buffer.from(chunk)),
    );
    launched.process.stdin?.on("error", (cause: Error) =>
      this.#failProtocol(
        session,
        `Rizin stdin stream failed: ${cause.message}`,
      ),
    );
    launched.process.stdin?.once("close", () => {
      if (!session.exited && session.protocolError === undefined)
        this.#failProtocol(session, "Rizin stdin stream closed unexpectedly.");
    });
    launched.process.once("exit", () => {
      session.exited = true;
      for (const waiter of session.frameWaiters)
        waiter.reject(
          new Error("Rizin exited before completing the NUL-framed response"),
        );
      session.frameWaiters.length = 0;
    });
    try {
      await waitForFrame(session, STARTUP_TIMEOUT_MS, signal);
      if (signal?.aborted)
        throw new AnalysisCancelledError("start_rizin_debug_session");
      session.ready = true;
      return ok({ session_id: id, backend: input.backend ?? null });
    } catch (cause) {
      const stopped = await stopDebuggerOnly(session);
      if (stopped.status !== "incomplete") this.#sessions.delete(id);
      if (signal?.aborted || cause instanceof AnalysisCancelledError)
        return err(
          new AnalysisCancelledError("start_rizin_debug_session", { cause }),
        );
      if (session.protocolError !== undefined)
        return err(
          new AnalysisCapabilityUnavailableError(
            "rizin",
            "start_rizin_debug_session",
            session.protocolError,
            { cause },
          ),
        );
      if (stopped.status === "incomplete")
        return err(
          new AnalysisCapabilityUnavailableError(
            "rizin",
            "start_rizin_debug_session",
            `Rizin startup failed and its owned process could not be confirmed stopped: ${stopped.reason}`,
            { cause },
          ),
        );
      return err(
        new AnalysisTimeoutError(
          "start_rizin_debug_session",
          STARTUP_TIMEOUT_MS,
          { cause },
        ),
      );
    }
  }

  async execute(
    sessionId: string,
    command: string,
    signal?: AbortSignal,
  ): Promise<
    Result<
      { readonly result: RizinDebugCommandResult; readonly evidence: Evidence },
      AnalysisError
    >
  > {
    const session = this.#sessions.get(sessionId);
    if (
      session === undefined ||
      !session.ready ||
      session.exited ||
      session.protocolError !== undefined
    )
      return err(new AnalysisInputError("rizin_debug_command"));
    if (signal?.aborted)
      return err(new AnalysisCancelledError("rizin_debug_command"));
    let release: (() => void) | undefined;
    let commandSent = false;
    const previous = session.commandTail;
    session.commandTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      await waitForTurn(previous, signal);
      if (signal?.aborted)
        return err(new AnalysisCancelledError("rizin_debug_command"));
      if (session.frames.length > 0) {
        const message =
          "Unsolicited Rizin frames arrived before a command; command output can no longer be safely correlated.";
        this.#failProtocol(session, message);
        return err(
          new AnalysisCapabilityUnavailableError(
            "rizin",
            "rizin_debug_command",
            message,
          ),
        );
      }
      const marker = `__REA_COMMAND_COMPLETE_${randomUUID().replaceAll("-", "")}__`;
      commandSent = true;
      const stdin = session.launched.process.stdin;
      if (
        stdin === null ||
        stdin === undefined ||
        stdin.destroyed ||
        !stdin.writable
      ) {
        this.#failProtocol(session, "Rizin stdin stream is closed.");
      } else {
        try {
          stdin.write(
            `${command}\n!echo ${marker}\n`,
            "utf8",
            (cause?: Error | null) => {
              if (cause)
                this.#failProtocol(
                  session,
                  `Rizin stdin write failed: ${cause.message}`,
                );
            },
          );
        } catch (cause) {
          this.#failProtocol(
            session,
            `Rizin stdin write failed: ${cause instanceof Error ? cause.message : "unknown error"}`,
          );
        }
      }
      if (session.protocolError !== undefined)
        throw new Error(session.protocolError);
      const output = await waitForCommandFrames(
        session,
        marker,
        this.#frameTimeoutMs,
        signal,
      );
      const result = {
        command,
        output,
        output_scope: "command_and_interleaved_session_output" as const,
        backend: session.backend,
      };
      const evidence = createEvidence(
        undefined,
        RIZIN_DEBUGGER_PROVIDER_IDENTITY,
        {
          predicateType: "rea.debugger.command-observation",
          operation: "rizin_debug_command",
          parameters: { session_id: sessionId, command },
          result,
          rawResult: result,
          subjectUnavailableReason:
            "The current debugger target identity is not established by the Rizin session identifier.",
          limitations: [
            "Rizin commands and debugger effects depend on the loaded IO plugin and target.",
            "Output contains all NUL frames through an explicit command-completion marker; backend output interleaved before that marker cannot be distinguished from command output.",
            "The command is unrestricted and may access local files, the shell, network, or mutate the target.",
          ],
        },
      );
      return ok({ result, evidence });
    } catch (cause) {
      if (signal?.aborted || cause instanceof AnalysisCancelledError) {
        if (!commandSent)
          return err(
            new AnalysisCancelledError("rizin_debug_command", { cause }),
          );
        session.protocolError =
          "A Rizin command was cancelled; the owned session was stopped because command output can no longer be correlated safely.";
        const stopped = await stopDebuggerOnly(session);
        if (stopped.status === "incomplete")
          return err(
            new AnalysisCapabilityUnavailableError(
              "rizin",
              "rizin_debug_command",
              `Cancellation was requested, but the owned Rizin process could not be confirmed stopped: ${stopped.reason}`,
              { cause: new AnalysisCancelledError("rizin_debug_command") },
            ),
          );
        return err(
          new AnalysisCancelledError("rizin_debug_command", { cause }),
        );
      }
      if (session.protocolError !== undefined)
        return err(
          new AnalysisCapabilityUnavailableError(
            "rizin",
            "rizin_debug_command",
            session.protocolError,
            { cause },
          ),
        );
      if (session.exited)
        return err(
          new AnalysisCapabilityUnavailableError(
            "rizin",
            "rizin_debug_command",
            "Rizin exited before returning a NUL-framed command result",
            { cause },
          ),
        );
      session.protocolError =
        "Rizin did not return the current command-completion marker; the session was stopped to prevent late output from being attributed to a later command.";
      session.launched.process.kill("SIGTERM");
      return err(
        new AnalysisTimeoutError("rizin_debug_command", this.#frameTimeoutMs, {
          cause,
        }),
      );
    } finally {
      release?.();
    }
  }

  status(sessionId: string):
    | {
        readonly session_id: string;
        readonly state: "ready" | "closed";
        readonly recent_output: readonly string[];
        readonly recent_output_truncated: boolean;
        readonly diagnostics_truncated: boolean;
      }
    | undefined {
    const session = this.#sessions.get(sessionId);
    return session === undefined
      ? undefined
      : {
          session_id: session.id,
          state:
            session.exited || session.protocolError !== undefined
              ? "closed"
              : session.ready
                ? "ready"
                : "closed",
          recent_output: [...session.history],
          recent_output_truncated: session.historyTruncated,
          diagnostics_truncated:
            session.supervisor.snapshot().diagnosticTruncated === true,
        };
  }

  async close(
    sessionId: string,
  ): Promise<Result<{ readonly target_state: "unknown" }, AnalysisError>> {
    const session = this.#sessions.get(sessionId);
    if (session === undefined)
      return err(new AnalysisInputError("close_rizin_debug_session"));
    const stopped = await stopDebuggerOnly(session);
    if (stopped.status === "incomplete")
      return err(
        new AnalysisCapabilityUnavailableError(
          "rizin",
          "close_rizin_debug_session",
          stopped.reason,
        ),
      );
    this.#sessions.delete(sessionId);
    return ok({ target_state: "unknown" });
  }

  async closeAll(): Promise<void> {
    return closeOwnedDebuggerSessions(
      this.#sessions,
      stopDebuggerOnly,
      "Rizin",
    );
  }

  #receive(session: RizinDebugSession, chunk: Buffer): void {
    let offset = 0;
    while (offset < chunk.length) {
      const boundary = chunk.indexOf(0, offset);
      const end = boundary < 0 ? chunk.length : boundary;
      const piece = chunk.subarray(offset, end);
      if (session.buffer.length + piece.length > MAX_FRAME_BYTES) {
        this.#failProtocol(
          session,
          "Rizin emitted an NUL frame exceeding the 16 MiB protocol limit.",
        );
        return;
      }
      session.buffer = Buffer.concat([session.buffer, piece]);
      if (boundary < 0) return;
      const frame = session.buffer.toString("utf8");
      const frameBytes = session.buffer.length;
      session.buffer = Buffer.alloc(0);
      const waiter = session.frameWaiters.shift();
      const historyFrame =
        frameBytes > MAX_RECENT_FRAME_BYTES
          ? `${frame.slice(0, MAX_RECENT_FRAME_BYTES)}[recent frame truncated]`
          : frame;
      if (frameBytes > MAX_RECENT_FRAME_BYTES) session.historyTruncated = true;
      session.history.push(historyFrame);
      if (session.history.length > 64) {
        session.history.splice(0, session.history.length - 64);
        session.historyTruncated = true;
      }
      if (waiter !== undefined) waiter.resolve(frame);
      else {
        const queueChargeBytes = Math.max(
          frameBytes,
          MIN_QUEUED_FRAME_CHARGE_BYTES,
        );
        if (
          session.frames.length >= MAX_QUEUED_FRAMES ||
          session.queuedFrameBytes + queueChargeBytes > MAX_QUEUED_FRAME_BYTES
        ) {
          this.#failProtocol(
            session,
            "Rizin produced unsolicited frames exceeding the bounded queue limit.",
          );
          return;
        }
        session.frames.push({ text: frame, queueChargeBytes });
        session.queuedFrameBytes += queueChargeBytes;
      }
      offset = boundary + 1;
    }
  }

  #failProtocol(session: RizinDebugSession, message: string): void {
    session.protocolError = message;
    session.buffer = Buffer.alloc(0);
    for (const waiter of session.frameWaiters)
      waiter.reject(new Error(message));
    session.frameWaiters.length = 0;
    session.launched.process.kill("SIGTERM");
  }
}

export interface RizinDebugCommandResult {
  readonly command: string;
  readonly output: string;
  readonly output_scope: "command_and_interleaved_session_output";
  readonly backend: string | null;
}

const waitForCommandFrames = async (
  session: RizinDebugSession,
  marker: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<string> => {
  const deadline = Date.now() + timeoutMs;
  const output: string[] = [];
  let outputBytes = 0;
  let frameCount = 0;
  for (;;) {
    const remaining = deadline - Date.now();
    if (remaining <= 0)
      throw new Error(
        "Timed out waiting for Rizin's command-completion marker",
      );
    const frame = await waitForFrame(session, remaining, signal);
    frameCount += 1;
    if (frameCount > MAX_COMMAND_FRAMES) {
      const message =
        "Rizin emitted more than 4096 frames for one command; the session was stopped because output correlation is ambiguous.";
      session.protocolError = message;
      session.launched.process.kill("SIGTERM");
      throw new Error(message);
    }
    const markerIndex = frame.indexOf(marker);
    if (markerIndex >= 0) {
      const beforeMarker = frame.slice(0, markerIndex).trimEnd();
      if (beforeMarker.length > 0) {
        outputBytes += Buffer.byteLength(beforeMarker, "utf8");
        if (outputBytes > MAX_COMMAND_OUTPUT_BYTES) {
          const message =
            "Rizin command output exceeded the 16 MiB command limit.";
          session.protocolError = message;
          session.launched.process.kill("SIGTERM");
          throw new Error(message);
        }
        output.push(beforeMarker);
      }
      return output.join("\n");
    }
    outputBytes += Buffer.byteLength(frame, "utf8");
    if (outputBytes > MAX_COMMAND_OUTPUT_BYTES) {
      const message = "Rizin command output exceeded the 16 MiB command limit.";
      session.protocolError = message;
      session.launched.process.kill("SIGTERM");
      throw new Error(message);
    }
    output.push(frame);
  }
};

const waitForFrame = (
  session: RizinDebugSession,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<string> => {
  if (signal?.aborted)
    return Promise.reject(new AnalysisCancelledError("rizin_debug_command"));
  const queued = session.frames.shift();
  if (queued !== undefined) {
    session.queuedFrameBytes -= queued.queueChargeBytes;
    return Promise.resolve(queued.text);
  }
  if (session.exited)
    return Promise.reject(
      new Error("Rizin process exited before the next NUL frame"),
    );
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      const index = session.frameWaiters.indexOf(waiter);
      if (index >= 0) session.frameWaiters.splice(index, 1);
    };
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new AnalysisCancelledError("rizin_debug_command"));
    };
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error("Timed out waiting for the next Rizin NUL frame"));
    }, timeoutMs);
    const waiter = {
      resolve: (frame: string): void => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(frame);
      },
      reject: (cause: Error): void => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(cause);
      },
    };
    session.frameWaiters.push(waiter);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
};

const waitForTurn = (
  previous: Promise<void>,
  signal?: AbortSignal,
): Promise<void> => {
  if (signal === undefined) return previous;
  if (signal.aborted)
    return Promise.reject(new AnalysisCancelledError("rizin_debug_command"));
  return new Promise<void>((resolve, reject) => {
    const onAbort = (): void =>
      reject(new AnalysisCancelledError("rizin_debug_command"));
    signal.addEventListener("abort", onAbort, { once: true });
    previous.then(
      () => {
        signal.removeEventListener("abort", onAbort);
        resolve();
      },
      (cause: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(cause);
      },
    );
  });
};

/** Stop only the directly owned debugger process, never its process group or target. */
const stopDebuggerOnly = async (
  session: RizinDebugSession,
): ReturnType<typeof stopOwnedDebuggerProcess> =>
  stopOwnedDebuggerProcess(session, "Rizin debugger");
