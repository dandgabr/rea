import { lstat, readlink } from "node:fs/promises";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { parseLinuxProcessStartTime } from "../../process/ProcessOwnershipObservation.js";
import type { PodmanExistingStoreProfile } from "./PodmanStoreProfile.js";
import {
  decodePodmanProfileText,
  observePodmanProfileFile,
  podmanProfileUnavailable,
} from "./PodmanProfileFiles.js";

/** External per-user infrastructure: observation never grants lifecycle or signal authority. */
export const observePodmanSharedHelper = async (
  selected: PodmanExistingStoreProfile,
  signal: AbortSignal,
  scope: ArtifactResourceScope,
) => {
  const expected = selected.shared_helper;
  const pidfile = await observePodmanProfileFile(
    expected.pidfile,
    64,
    signal,
    scope,
  );
  const rawPid = decodePodmanProfileText(pidfile.bytes).trim();
  if (
    !/^[1-9][0-9]*$/u.test(rawPid) ||
    Number(rawPid) !== expected.pid ||
    pidfile.identity.uid !== selected.rootless_uid
  )
    throw podmanProfileUnavailable(
      "The selected runtime has no stable, previously initialized per-user helper association",
    );
  const processPath = `/proc/${expected.pid}`;
  const before = await observePodmanProfileFile(
    `${processPath}/stat`,
    64 * 1024,
    signal,
    scope,
  );
  signal.throwIfAborted();
  const [metadata, user_ns, mount_ns, pid_ns, executable] = await Promise.all([
    lstat(processPath),
    readlink(`${processPath}/ns/user`),
    readlink(`${processPath}/ns/mnt`),
    readlink(`${processPath}/ns/pid`),
    readlink(`${processPath}/exe`),
  ]);
  const after = await observePodmanProfileFile(
    `${processPath}/stat`,
    64 * 1024,
    signal,
    scope,
  );
  const confirmedPidfile = await observePodmanProfileFile(
    expected.pidfile,
    64,
    signal,
    scope,
  );
  const start = parseLinuxProcessStartTime(
    decodePodmanProfileText(before.bytes),
  );
  if (
    confirmedPidfile.identity.uid !== selected.rootless_uid ||
    decodePodmanProfileText(confirmedPidfile.bytes).trim() !== rawPid ||
    start === undefined ||
    start !==
      parseLinuxProcessStartTime(decodePodmanProfileText(after.bytes)) ||
    start !== expected.start_ticks ||
    metadata.uid !== expected.uid ||
    user_ns !== expected.user_ns ||
    mount_ns !== expected.mount_ns ||
    pid_ns !== expected.pid_ns ||
    executable !== expected.executable
  )
    throw podmanProfileUnavailable(
      "The external shared helper start/UID/namespaces/runtime association is stale or unreadable",
    );
  signal.throwIfAborted();
  return {
    ...expected,
    authority: "external_shared_infrastructure" as const,
    pidfile: pidfile.identity,
  };
};
