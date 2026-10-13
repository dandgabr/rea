import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";

/** Adapter-owned namespace command; caller options remain individual native tokens. */
export const unblobContainerCommand = (
  args: readonly string[],
  outputBytes = FIRMWARE_LIMITS.reportBytes,
): readonly string[] => [
  "/usr/bin/prlimit",
  `--as=${FIRMWARE_LIMITS.addressSpaceBytes}`,
  `--fsize=${outputBytes}`,
  "--core=0",
  "--cpu=120",
  "--",
  "/usr/local/bin/unblob",
  ...args,
];
