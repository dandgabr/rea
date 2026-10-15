import { expect, it } from "vitest";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";
import { unblobContainerCommand } from "./UnblobContainerCommand.js";
import { unblobExecutionOptions } from "./UnblobOptions.js";
import { firmwareRequestSchema } from "../domain/firmware/firmwareAnalysis.js";

it("places the actual producer limits inside the container while preserving caller native options", () => {
  const request = firmwareRequestSchema.parse({
    operation: "extract_firmware",
    input: {
      path: "/caller/fw.bin",
      output_directory: "/caller/output",
      options: {
        workers: 9,
        skip_magic: { mode: "replace", values: ["--force", "two words"] },
        keep_extracted_chunks: true,
        delete_extracted_files: { mode: "selected", handlers: ["gzip"] },
      },
    },
  });
  const native = unblobExecutionOptions(request);
  const argv = unblobContainerCommand(
    [...native.args, "--report", "/rea-work/report.json", "/rea-input/fw.bin"],
    1234567,
  );
  expect(argv.slice(0, 7)).toEqual([
    "/usr/bin/prlimit",
    `--as=${FIRMWARE_LIMITS.addressSpaceBytes}`,
    "--fsize=1234567",
    "--core=0",
    "--cpu=120",
    "--",
    "/usr/local/bin/unblob",
  ]);
  expect(argv.slice(7)).toEqual([
    "--process-num",
    "9",
    "--randomness-depth",
    "0",
    "--clear-skip-magics",
    "--skip-magic=--force",
    "--skip-magic=two words",
    "--depth",
    "3",
    "--keep-extracted-chunks",
    "--delete-extracted-files=selected:gzip",
    "--carve-suffix=_extract",
    "--extract-suffix=_extract",
    "--report",
    "/rea-work/report.json",
    "/rea-input/fw.bin",
  ]);
  expect(native.args).not.toContainEqual(
    expect.stringContaining("--plugins-path"),
  );
});

it("also bounds version and dependency producers with the report file budget", () => {
  expect(unblobContainerCommand(["--version"])).toEqual([
    "/usr/bin/prlimit",
    `--as=${FIRMWARE_LIMITS.addressSpaceBytes}`,
    `--fsize=${FIRMWARE_LIMITS.reportBytes}`,
    "--core=0",
    "--cpu=120",
    "--",
    "/usr/local/bin/unblob",
    "--version",
  ]);
});
