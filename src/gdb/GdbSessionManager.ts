import { randomUUID } from "node:crypto";

import {
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

const STARTUP_TIMEOUT_MS = 10_000;
const COMMAND_TIMEOUT_MS = 120_000;
const MAX_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_MI_LINE_BYTES = 16 * 1024 * 1024;
const MAX_RECENT_MI_LINE_BYTES = 64 * 1024;

export const GDB_PROVIDER_IDENTITY = {
  id: "gnu.gdb",
  name: "GNU GDB",
  version: null,
} as const;

interface PendingCommand {
  readonly token: number;
  readonly lines: string[];
  outputBytes: number;
  outputTruncated: boolean;
  readonly resolve: (result: GdbCommandResult) => void;
  readonly reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
}

export interface GdbCommandResult {
  readonly command: string;
  readonly mi: string;
  readonly records: readonly string[];
  readonly console: string;
  readonly target: string;
  readonly log: string;
  readonly process_exit_observed?: boolean;
  readonly output_truncated: boolean;
}

interface GdbSession {
  readonly id: string;
  readonly miVersion: "mi3" | "mi2";
  readonly launched: SpawnedOwnedProviderProcess;
  readonly supervisor: ProviderProcessSupervisor;
  readonly pending: Map<number, PendingCommand>;
  readonly lines: string[];
  buffer: string;
  ready: boolean;
  exited: boolean;
  nextToken: number;
  startupResolve: (() => void) | undefined;
  startupReject: ((error: Error) => void) | undefined;
  commandTail: Promise<void>;
  protocolError: string | undefined;
  recentRecordsTruncated: boolean;
}

/** Owns persistent GDB/MI sessions independently from the active binary target. */
export class GdbSessionManager {
  readonly #sessions = new Map<string, GdbSession>();
  readonly #command: string;

  constructor(
    options: {
      readonly environment?: Readonly<NodeJS.ProcessEnv>;
    } = {},
  ) {
    this.#command =
      options.environment?.REA_GDB_COMMAND ??
      process.env.REA_GDB_COMMAND ??
      "gdb";
  }

  async start(
    signal?: AbortSignal,
  ): Promise<
    Result<
      { readonly session_id: string; readonly mi_version: "mi3" | "mi2" },
      AnalysisError
    >
  > {
    const id = randomUUID();
    const mi3 = await this.#startProtocol(id, "mi3", signal);
    return mi3.ok || signal?.aborted || this.#sessions.has(id)
      ? mi3
      : this.#startProtocol(id, "mi2", signal);
  }

  async #startProtocol(
    id: string,
    miVersion: "mi3" | "mi2",
    signal?: AbortSignal,
  ): Promise<
    Result<
      { readonly session_id: string; readonly mi_version: "mi3" | "mi2" },
      AnalysisError
    >
  > {
    let launched: SpawnedOwnedProviderProcess;
    try {
      launched = await spawnOwnedProviderProcess({
        command: this.#command,
        arguments: ["--nx", "--quiet", `--interpreter=${miVersion}`],
        runId: randomUUID(),
        stdin: "pipe",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause) {
      return err(
        new AnalysisCapabilityUnavailableError(
          "gdb",
          "start_gdb_session",
          cause instanceof Error ? cause.message : "Unable to start GDB",
        ),
      );
    }
    const supervisor = new ProviderProcessSupervisor(
      { process: launched.process, ownsProcessLifetime: false },
      { captureStdout: false },
    );
    const session: GdbSession = {
      id,
      miVersion,
      launched,
      supervisor,
      pending: new Map(),
      lines: [],
      buffer: "",
      ready: false,
      exited: false,
      nextToken: 1,
      startupResolve: undefined,
      startupReject: undefined,
      commandTail: Promise.resolve(),
      protocolError: undefined,
      recentRecordsTruncated: false,
    };
    launched.process.stdout?.setEncoding("utf8");
    launched.process.stdout?.on("data", (chunk: string | Buffer) =>
      this.#receive(session, String(chunk)),
    );
    launched.process.once("exit", () => {
      session.exited = true;
      for (const pending of session.pending.values()) {
        if (pending.timer !== undefined) clearTimeout(pending.timer);
        pending.reject(
          new Error("GDB exited before completing the MI command"),
        );
      }
      session.pending.clear();
      session.startupReject?.(new Error("GDB exited during startup"));
    });
    let startupTimer: ReturnType<typeof setTimeout> | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        session.startupResolve = resolve;
        session.startupReject = reject;
        startupTimer = setTimeout(
          () =>
            reject(
              new Error(
                "GDB did not emit the MI prompt before the startup deadline",
              ),
            ),
          STARTUP_TIMEOUT_MS,
        );
        startupTimer.unref();
      });
      session.ready = true;
      const autoLoad = await this.#request(session, "-gdb-set auto-load off");
      if (!/^\d+\^done(?:,|$)/u.test(autoLoad.mi)) {
        session.protocolError = `GDB rejected the required automatic-loading disable command (${autoLoad.mi || "no MI result"}); the session was not started.`;
        throw new Error(session.protocolError);
      }
      this.#sessions.set(id, session);
      return ok({ session_id: id, mi_version: miVersion });
    } catch (cause) {
      const stopped = await stopDebuggerOnly(session);
      if (stopped.status === "incomplete") {
        this.#sessions.set(id, session);
        return err(
          new AnalysisCapabilityUnavailableError(
            "gdb",
            "start_gdb_session",
            `GDB startup failed and its owned process could not be confirmed stopped: ${stopped.reason}`,
            { cause },
          ),
        );
      }
      const error = signal?.aborted
        ? new AnalysisCapabilityUnavailableError(
            "gdb",
            "start_gdb_session",
            "GDB startup was cancelled",
            { cause },
          )
        : session.protocolError !== undefined
          ? new AnalysisCapabilityUnavailableError(
              "gdb",
              "start_gdb_session",
              session.protocolError,
              { cause },
            )
          : new AnalysisTimeoutError("start_gdb_session", STARTUP_TIMEOUT_MS, {
              cause,
            });
      return err(error);
    } finally {
      if (startupTimer !== undefined) clearTimeout(startupTimer);
    }
  }

  async execute(
    sessionId: string,
    command: string,
  ): Promise<
    Result<
      { readonly result: GdbCommandResult; readonly evidence: Evidence },
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
      return err(
        new AnalysisInputError("gdb_console", undefined, [
          {
            path: ["session_id"],
            reason: "invalid_value",
            message: "GDB session is unavailable or closed.",
          },
        ]),
      );
    return this.#serialize(session, async () => {
      if (session.exited || session.protocolError !== undefined)
        return err(new AnalysisInputError("gdb_console"));
      try {
        const result = await this.#request(
          session,
          `-interpreter-exec console ${miQuote(command)}`,
        );
        const evidence = createEvidence(
          undefined,
          { id: "gnu.gdb", name: "GNU GDB", version: null },
          {
            predicateType: "rea.debugger.console-observation",
            operation: "gdb_console",
            parameters: { session_id: sessionId, command },
            result: {
              command,
              mi: result.mi,
              records: [...result.records],
              console: result.console,
              target: result.target,
              log: result.log,
              output_truncated: result.output_truncated,
            },
            rawResult: {
              command,
              mi: result.mi,
              records: [...result.records],
              console: result.console,
              target: result.target,
              log: result.log,
              output_truncated: result.output_truncated,
            },
            subjectUnavailableReason:
              "The active GDB inferior identity is not established by the debugger session identifier.",
            limitations: [
              "MI records are preserved raw; their semantics depend on GDB version and target.",
              "The unrestricted GDB console can access local shell, filesystem, network, and target controls.",
            ],
          },
        );
        return ok({ result, evidence });
      } catch (cause) {
        if (session.protocolError !== undefined)
          return err(
            new AnalysisCapabilityUnavailableError(
              "gdb",
              "gdb_console",
              session.protocolError,
              { cause },
            ),
          );
        if (session.exited) {
          const result: GdbCommandResult = {
            command,
            mi: "",
            records: [...session.lines],
            console: session.lines
              .filter((line) => line.startsWith("~"))
              .join("\n"),
            target: session.lines
              .filter((line) => line.startsWith("@"))
              .join("\n"),
            log: session.lines
              .filter((line) => line.startsWith("&"))
              .join("\n"),
            process_exit_observed: true,
            output_truncated: false,
          };
          const evidence = createEvidence(
            undefined,
            { id: "gnu.gdb", name: "GNU GDB", version: null },
            {
              predicateType: "rea.debugger.console-observation",
              operation: "gdb_console",
              parameters: { session_id: sessionId, command },
              result: {
                command: result.command,
                mi: result.mi,
                records: [...result.records],
                console: result.console,
                target: result.target,
                log: result.log,
                process_exit_observed: true,
                output_truncated: false,
              },
              rawResult: {
                command: result.command,
                mi: result.mi,
                records: [...result.records],
                console: result.console,
                target: result.target,
                log: result.log,
                process_exit_observed: true,
                output_truncated: false,
              },
              subjectUnavailableReason:
                "The active GDB inferior identity is not established by the debugger session identifier.",
              limitations: [
                "GDB exited before returning a correlated MI result record; all retained MI and stream records are returned raw.",
              ],
            },
          );
          return ok({ result, evidence });
        }
        return err(
          new AnalysisTimeoutError("gdb_console", COMMAND_TIMEOUT_MS, {
            cause,
          }),
        );
      }
    });
  }

  status(sessionId: string):
    | {
        readonly session_id: string;
        readonly mi_version: "mi3" | "mi2";
        readonly state: "ready" | "closed";
        readonly recent_mi_records: readonly string[];
        readonly recent_mi_records_truncated: boolean;
      }
    | undefined {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) return undefined;
    return {
      session_id: session.id,
      mi_version: session.miVersion,
      state:
        session.exited || session.protocolError !== undefined
          ? "closed"
          : session.ready
            ? "ready"
            : "closed",
      recent_mi_records: [...session.lines],
      recent_mi_records_truncated: session.recentRecordsTruncated,
    };
  }

  async close(
    sessionId: string,
  ): Promise<
    Result<
      { readonly target_state: "none_observed" | "unknown" },
      AnalysisError
    >
  > {
    const session = this.#sessions.get(sessionId);
    if (session === undefined)
      return err(new AnalysisInputError("close_gdb_session"));
    if (session.exited) {
      this.#sessions.delete(sessionId);
      session.supervisor.dispose();
      return ok({ target_state: "unknown" });
    }
    return this.#serialize(session, async () => {
      if (session.exited) {
        this.#sessions.delete(sessionId);
        session.supervisor.dispose();
        return ok({ target_state: "unknown" });
      }
      let targetState: "none_observed" | "unknown" = "unknown";
      try {
        const groups = await this.#request(
          session,
          "-list-thread-groups --recurse 1",
        );
        if (!/^\d+\^done(?:,|$)/u.test(groups.mi))
          throw new Error(
            "GDB could not confirm its live thread groups before shutdown.",
          );
        const hasLiveTarget =
          /\bpid=(?:"[^"]+"|[0-9]+)/u.test(groups.mi) ||
          /\bthreads=\[(?!\s*\])/u.test(groups.mi);
        if (hasLiveTarget)
          return err(
            new AnalysisInputError("close_gdb_session", undefined, [
              {
                path: ["session_id"],
                reason: "invalid_value",
                message:
                  "Live GDB thread groups remain. Use the unrestricted console to select a disposition for each inferior, then close the debugger session.",
              },
            ]),
          );
        targetState = "none_observed";
        await this.#request(session, "-gdb-exit");
      } catch {
        // If MI synchronization is lost, stop only the owned debugger process.
      }
      const stopped = await stopDebuggerOnly(session);
      if (stopped.status === "incomplete")
        return err(
          new AnalysisCapabilityUnavailableError(
            "gdb",
            "close_gdb_session",
            stopped.reason,
          ),
        );
      this.#sessions.delete(sessionId);
      return ok({ target_state: targetState });
    });
  }

  async closeAll(): Promise<void> {
    return closeOwnedDebuggerSessions(this.#sessions, stopDebuggerOnly, "GDB");
  }

  async #serialize<Value>(
    session: GdbSession,
    operation: () => Promise<Value>,
  ): Promise<Value> {
    const previous = session.commandTail;
    let release: (() => void) | undefined;
    session.commandTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }

  #receive(session: GdbSession, data: string): void {
    const combined = session.buffer + data;
    session.buffer = "";
    const parts = combined.split(/\r?\n/u);
    if (!combined.endsWith("\n")) session.buffer = parts.pop() ?? "";
    if (Buffer.byteLength(session.buffer, "utf8") > MAX_MI_LINE_BYTES) {
      this.#failProtocol(
        session,
        "GDB emitted a partial MI line exceeding the 16 MiB protocol limit.",
      );
      return;
    }
    const lines = parts.filter((line) => line.length > 0);
    if (
      lines.some((line) => Buffer.byteLength(line, "utf8") > MAX_MI_LINE_BYTES)
    ) {
      this.#failProtocol(
        session,
        "GDB emitted an MI line exceeding the 16 MiB protocol limit.",
      );
      return;
    }
    for (const line of lines) {
      if (Buffer.byteLength(line, "utf8") > MAX_RECENT_MI_LINE_BYTES) {
        session.lines.push(
          `${line.slice(0, MAX_RECENT_MI_LINE_BYTES)}[recent record truncated]`,
        );
        session.recentRecordsTruncated = true;
      } else session.lines.push(line);
    }
    if (session.lines.length > 256)
      session.lines.splice(0, session.lines.length - 256);
    if (combined.includes("(gdb)")) session.startupResolve?.();
    for (const line of lines) {
      for (const pending of session.pending.values()) {
        const lineBytes = Buffer.byteLength(line, "utf8") + 1;
        if (pending.outputBytes + lineBytes <= MAX_COMMAND_OUTPUT_BYTES) {
          pending.lines.push(line);
          pending.outputBytes += lineBytes;
        } else pending.outputTruncated = true;
      }
      const match = /^(\d+)\^(done|running|connected|error|exit)(?:,|$)/u.exec(
        line,
      );
      if (match === null) continue;
      const token = Number(match[1]);
      const pending = session.pending.get(token);
      if (pending === undefined) continue;
      if (pending.timer !== undefined) clearTimeout(pending.timer);
      session.pending.delete(token);
      const records = [...pending.lines];
      pending.resolve({
        command: "",
        mi: line,
        records,
        console: records.filter((record) => record.startsWith("~")).join("\n"),
        target: records.filter((record) => record.startsWith("@")).join("\n"),
        log: records.filter((record) => record.startsWith("&")).join("\n"),
        output_truncated: pending.outputTruncated,
      });
    }
  }

  #failProtocol(session: GdbSession, message: string): void {
    session.protocolError = message;
    for (const pending of session.pending.values()) {
      if (pending.timer !== undefined) clearTimeout(pending.timer);
      pending.reject(new Error(message));
    }
    session.pending.clear();
    session.startupReject?.(new Error(message));
    session.launched.process.kill("SIGTERM");
  }

  #request(session: GdbSession, command: string): Promise<GdbCommandResult> {
    if (
      session.exited ||
      session.launched.process.stdin === null ||
      session.launched.process.stdin === undefined
    )
      return Promise.reject(new Error("GDB MI input stream is closed"));
    const token = session.nextToken++;
    return new Promise<GdbCommandResult>((resolve, reject) => {
      const pending: PendingCommand = {
        token,
        lines: [],
        resolve,
        reject,
        timer: undefined,
        outputBytes: 0,
        outputTruncated: false,
      };
      pending.timer = setTimeout(() => {
        session.pending.delete(token);
        session.protocolError =
          "A GDB MI command timed out; untagged stream output can no longer be safely correlated with later commands.";
        session.launched.process.kill("SIGTERM");
        reject(new Error(`GDB MI command timed out: ${command}`));
      }, COMMAND_TIMEOUT_MS);
      session.pending.set(token, pending);
      session.launched.process.stdin?.write(`${token}${command}\n`, "utf8");
    }).then((result) => ({ ...result, command }));
  }
}

const miQuote = (value: string): string =>
  `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("\r", "\\r").replaceAll("\n", "\\n")}"`;

/** Terminate only the directly owned debugger process, never its process group or inferiors. */
const stopDebuggerOnly = async (
  session: GdbSession,
): ReturnType<typeof stopOwnedDebuggerProcess> =>
  stopOwnedDebuggerProcess(session, "GDB");
