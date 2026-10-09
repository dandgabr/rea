import { expect, it } from "vitest";

import type { FridaInstrumentationPort } from "./FridaInstrumentationPort.js";
import { FridaInstrumentationService } from "./FridaInstrumentationService.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";

it("cleans up a session and returns typed cancellation after a pending start", async () => {
  let finishStart: (() => void) | undefined;
  let markStartCalled: (() => void) | undefined;
  const startGate = new Promise<void>((resolve) => {
    finishStart = resolve;
  });
  const startCalled = new Promise<void>((resolve) => {
    markStartCalled = resolve;
  });
  const closed: string[] = [];
  const provider: FridaInstrumentationPort = {
    async listDevices() {
      return { ok: true, value: { devices: [], cleanupError: null } };
    },
    async listProcesses() {
      return {
        ok: true,
        value: { deviceId: "local", processes: [], cleanupError: null },
      };
    },
    async startSession() {
      markStartCalled?.();
      await startGate;
      return {
        ok: true,
        value: {
          sessionId: "00000000-0000-4000-8000-000000000001",
          deviceId: "local",
          target: "fixture",
          pid: 10,
          mode: "attach",
          state: "running",
        },
      };
    },
    async loadScript() {
      return {
        ok: false,
        error: new AnalysisInputError("load_frida_script"),
      };
    },
    async resumeSession() {
      return { ok: true, value: null };
    },
    async unloadScript() {
      return { ok: true, value: null };
    },
    status() {
      return undefined;
    },
    async closeSession(sessionId) {
      closed.push(sessionId);
      return { ok: true, value: null };
    },
    async closeAll() {},
  };
  const service = new FridaInstrumentationService(provider);
  const controller = new AbortController();
  const pending = service.startSession(
    { mode: "attach", deviceId: "local", pid: 10 },
    controller.signal,
  );
  await startCalled;
  controller.abort(new Error("caller cancelled"));
  finishStart?.();

  const result = await pending;
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
  expect(closed).toEqual(["00000000-0000-4000-8000-000000000001"]);
});
