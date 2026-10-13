import { setTimeout as delay } from "node:timers/promises";
import type { FirmwareLauncher } from "../FirmwareCommand.js";
import { spawnOwnedProviderProcess } from "../../process/ProviderProcess.js";
import type {
  OwnedProcessGroup,
  ProcessCleanupResult,
  ProcessIdentityObservation,
  ProcessOwnershipHost,
} from "../../process/ProcessOwnership.js";
import {
  observeProcessStartIdentity,
  signalProcessWithStartIdentity,
  systemProcessOwnershipHost,
} from "../../process/ProcessOwnershipObservation.js";
import { launcherIdentityFailure } from "../../process/ProcessOwnershipIdentity.js";

/** Cleanup authority covers only the captured direct client, never a group, token sweep or shared helper. */
export const podmanDirectClientCleanup =
  (
    ownership: OwnedProcessGroup,
    initial: ProcessIdentityObservation | undefined,
    host: ProcessOwnershipHost = systemProcessOwnershipHost,
    sendSignal: (pid: number, signal: NodeJS.Signals) => void = process.kill,
  ) =>
  async (): Promise<ProcessCleanupResult> => {
    let signaled = false;
    const observe = async () => {
      const entries = await host.listProcesses();
      const process = entries.find(
        (entry) =>
          entry.pid === ownership.leaderPid && !entry.state.startsWith("Z"),
      );
      if (process === undefined) return "gone" as const;
      if (
        initial?.state !== "readable" ||
        launcherIdentityFailure(process, ownership) !== null
      )
        return "unverified" as const;
      const current = await observeProcessStartIdentity(
        ownership.leaderPid,
        host,
        ownership.runId,
      );
      if (current === undefined) return "gone" as const;
      return current.state === "readable" &&
        current.identity === initial.identity
        ? ("verified" as const)
        : ("unverified" as const);
    };
    try {
      for (const signal of ["SIGTERM", "SIGKILL"] as const) {
        const current = await observe();
        if (current === "gone") return { cleaned: true, signaled };
        if (current !== "verified" || initial?.state !== "readable")
          return {
            cleaned: false,
            reason:
              "The captured direct Podman client identity cannot be revalidated; no group or helper was signaled",
          };
        const result = await signalProcessWithStartIdentity(
          ownership.leaderPid,
          initial.identity,
          signal,
          { host, sendSignal },
        );
        if (result === "gone") return { cleaned: true, signaled };
        if (result !== "signaled")
          return {
            cleaned: false,
            reason:
              "The direct Podman client start identity changed or became unreadable before signaling",
          };
        signaled = true;
        const until = Date.now() + (signal === "SIGTERM" ? 250 : 1000);
        do {
          if ((await observe()) === "gone") return { cleaned: true, signaled };
          await delay(25);
        } while (Date.now() < until);
      }
      return {
        cleaned: false,
        reason:
          "The captured direct Podman client remains live after identity-bound termination",
      };
    } catch (cause: unknown) {
      return {
        cleaned: false,
        reason: `Direct Podman client cleanup is unverified: ${cause instanceof Error ? cause.message : String(cause)}`,
      };
    }
  };

export const launchPodmanDirectClient: FirmwareLauncher = async (options) => {
  const spawned = await spawnOwnedProviderProcess(options);
  // Do not delay supervisor attachment: a fast client may close while identity is read.
  const initial = observeProcessStartIdentity(
    spawned.ownership.leaderPid,
    systemProcessOwnershipHost,
    spawned.ownership.runId,
  ).catch((cause: unknown): ProcessIdentityObservation => ({
    state: "unavailable",
    reason: cause instanceof Error ? cause.message : String(cause),
  }));
  return {
    ...spawned,
    cleanup: async () =>
      podmanDirectClientCleanup(spawned.ownership, await initial)(),
  };
};
