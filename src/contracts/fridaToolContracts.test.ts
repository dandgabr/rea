import { describe, expect, it } from "vitest";

import { TOOL_CONTRACTS } from "./toolContracts.js";
import { isValidFridaRemoteAddress } from "./fridaRemoteAddress.js";

describe("Frida tool contracts", () => {
  it("publishes the Frida device, process, and session operations", () => {
    expect(TOOL_CONTRACTS.map(({ name }) => name)).toEqual(
      expect.arrayContaining([
        "list_frida_devices",
        "list_frida_processes",
        "start_frida_session",
        "load_frida_script",
        "resume_frida_session",
        "unload_frida_script",
        "frida_session_status",
        "close_frida_session",
        "instrument_with_frida",
      ]),
    );
  });

  it("declares target authority for every operation that changes instrumentation", () => {
    for (const name of [
      "start_frida_session",
      "load_frida_script",
      "resume_frida_session",
      "unload_frida_script",
      "close_frida_session",
      "instrument_with_frida",
    ] as const) {
      const contract = TOOL_CONTRACTS.find(
        (candidate) => candidate.name === name,
      );
      expect(contract?.effects.mutatesTarget).toBe(true);
      expect(contract?.effects.idempotent).toBe(false);
    }
  });

  it("accepts Frida host addresses and rejects URL-like or malformed endpoints", () => {
    expect(isValidFridaRemoteAddress("127.0.0.1:27042")).toBe(true);
    expect(isValidFridaRemoteAddress("frida-target.example")).toBe(true);
    expect(isValidFridaRemoteAddress("[::1]:27042")).toBe(true);
    expect(isValidFridaRemoteAddress("tcp://127.0.0.1:27042")).toBe(false);
    expect(isValidFridaRemoteAddress("127.0.0.1:70000")).toBe(false);
    expect(isValidFridaRemoteAddress("127.0.0.1:0")).toBe(false);
    expect(isValidFridaRemoteAddress("127.0.0.1:")).toBe(false);
    expect(isValidFridaRemoteAddress("frida-target/path")).toBe(false);
    expect(isValidFridaRemoteAddress("user@frida-target")).toBe(false);
  });
});
