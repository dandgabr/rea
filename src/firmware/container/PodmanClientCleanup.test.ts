import { expect, it, vi } from "vitest";
import type {
  ProcessOwnershipHost,
  ProcessTableEntry,
} from "../../process/ProcessOwnership.js";
import { podmanDirectClientCleanup } from "./PodmanClientCleanup.js";
import { launchPodmanDirectClient } from "./PodmanClientCleanup.js";
import * as ownershipObservation from "../../process/ProcessOwnershipObservation.js";
import { runFirmwareCommand } from "../FirmwareCommand.js";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";

const owned = {
  runId: "rea-test-client",
  leaderPid: 500,
  processGroupId: 500,
  expectedParentPid: 400,
};
const entry: ProcessTableEntry = {
  pid: 500,
  parentPid: 400,
  processGroupId: 500,
  uid: 1000,
  state: "S",
  command: "podman",
};
const hostFixture = () => {
  let current: ProcessTableEntry | undefined = entry;
  let identity = "linux:start:100";
  let runId = owned.runId;
  const host: ProcessOwnershipHost = {
    listProcesses: async () => [
      ...(current === undefined ? [] : [current]),
      { ...entry, pid: 501, parentPid: 500, command: "shared helper" },
    ],
    environment: async () => ({ REA_PROCESS_RUN_ID: runId }),
    processIdentities: async (entries) =>
      new Map(
        entries.map(({ pid }) => [
          pid,
          { state: "readable" as const, identity },
        ]),
      ),
    signalGroup: vi.fn(() => {
      throw Error("Group authority is forbidden");
    }),
  };
  return {
    host,
    remove: () => {
      current = undefined;
    },
    changeParent: () => {
      current = { ...entry, parentPid: 999 };
    },
    reuse: () => {
      identity = "linux:start:101";
    },
    changeToken: () => {
      runId = "someone-else";
    },
  };
};
it("signals only the direct captured client and leaves a shared-helper descendant untouched", async () => {
  const f = hostFixture();
  const send = vi.fn((pid: number) => {
    expect(pid).toBe(500);
    f.remove();
  });
  expect(
    await podmanDirectClientCleanup(
      owned,
      { state: "readable", identity: "linux:start:100" },
      f.host,
      send,
    )(),
  ).toEqual({ cleaned: true, signaled: true });
  expect(send).toHaveBeenCalledExactlyOnceWith(500, "SIGTERM");
  expect(f.host.signalGroup).not.toHaveBeenCalled();
});
it("refuses changed parent, start identity, token and unreadable startup identity without any signal", async () => {
  for (const fault of ["parent", "reuse", "token", "unreadable"] as const) {
    const f = hostFixture();
    if (fault === "parent") f.changeParent();
    if (fault === "reuse") f.reuse();
    if (fault === "token") f.changeToken();
    const send = vi.fn();
    const result = await podmanDirectClientCleanup(
      owned,
      fault === "unreadable"
        ? { state: "unavailable", reason: "read denied" }
        : { state: "readable", identity: "linux:start:100" },
      f.host,
      send,
    )();
    expect(result.cleaned, fault).toBe(false);
    expect(send).not.toHaveBeenCalled();
    expect(f.host.signalGroup).not.toHaveBeenCalled();
  }
});
it("settles an exited direct client without guessing ownership of a live reused PID", async () => {
  const f = hostFixture();
  f.remove();
  const send = vi.fn();
  expect(
    await podmanDirectClientCleanup(owned, undefined, f.host, send)(),
  ).toEqual({ cleaned: true, signaled: false });
  expect(send).not.toHaveBeenCalled();
});
it("attaches shared supervision before asynchronous identity admission so a real fast client retains close and source capture", async () => {
  const original = ownershipObservation.observeProcessStartIdentity;
  const spy = vi
    .spyOn(ownershipObservation, "observeProcessStartIdentity")
    .mockImplementationOnce(async (...args) => {
      await new Promise((resolve) => setTimeout(resolve, 75));
      return original(...args);
    });
  try {
    const result = await runFirmwareCommand({
      engine: "podman-client-fixture",
      operation: "firmware_container_runtime",
      command: "/usr/bin/python3",
      limiter: "/usr/bin/prlimit",
      args: ["-c", "print('fast-client-source')"],
      cwd: tmpdir(),
      environment: { PATH: "/usr/bin:/bin" },
      signal: AbortSignal.timeout(1500),
      launcher: launchPodmanDirectClient,
      limitProfile: "container-transport",
      retainCleanup: () => {
        throw Error("unexpected unresolved direct-client cleanup");
      },
    });
    expect(result.exit_code).toBe(0);
    expect(result.captured_output).toMatchObject({
      stdout: "fast-client-source\n",
      stdout_sha256: createHash("sha256")
        .update("fast-client-source\n")
        .digest("hex"),
      stdout_utf8_valid: true,
    });
  } finally {
    spy.mockRestore();
  }
}, 2000);
