import { Cli } from "incur";
import pino from "pino";
import { expect, it, onTestFinished } from "vitest";
import { registerFirmwareCommands } from "../../../src/cli/firmwareCommands.js";

const invoke = async (args: string[]) => {
  const exitCode = process.exitCode;
  onTestFinished(() => {
    process.exitCode = exitCode;
  });
  const cli = Cli.create("firmware-test", { version: "1" });
  registerFirmwareCommands(cli, pino({ level: "silent" }), {});
  let output = "";
  await cli.serve([...args, "--json"], {
    stdout: (text) => {
      output += text;
    },
    exit: () => undefined,
  });
  return JSON.parse(output) as unknown;
};

it("selects explicit Unblob inspection through real CLI parsing rather than the legacy default", async () => {
  const result = await invoke([
    "inspect-firmware-regions",
    "/tmp/firmware-options.bin",
    "--provider-id",
    "unblob",
    "--offset",
    "64",
    "--length",
    "20",
    "--workers",
    "2",
    "--randomness-depth",
    "1",
    "--skip-magic",
    "PNG",
    "--skip-magic=--force",
    "--clear-skip-magics",
    "--skip-extension",
    ".rlib",
  ]);
  expect(result).toMatchObject({
    code: "capability_unavailable",
    message: expect.stringContaining("absolute REA_UNBLOB_COMMAND"),
  });
});

it("rejects invalid worker selection instead of dropping it at the CLI boundary", async () => {
  const result = await invoke([
    "extract-firmware",
    "/tmp/input.bin",
    "/tmp/fresh-output",
    "--workers",
    "0",
  ]);
  expect(JSON.stringify(result)).toMatch(/workers|greater than|positive/u);
  expect(JSON.stringify(result)).not.toContain("REA_UNBLOB_COMMAND");
  expect(JSON.stringify(result)).not.toContain("Unknown option");
});

it("exposes named provider inventory without a firmware positional argument", async () => {
  expect(
    await invoke(["inspect-firmware-provider", "--provider-id", "unblob"]),
  ).toMatchObject({
    code: "capability_unavailable",
    message: expect.stringContaining("absolute REA_UNBLOB_COMMAND"),
  });
});

it("does not expose Unblob's caller-selected plugin path in the CLI", async () => {
  const result = await invoke([
    "inspect-firmware-provider",
    "--provider-id",
    "unblob",
    "--plugins-path",
    "/tmp/plugin.py",
  ]);
  expect(result).toMatchObject({ code: "UNKNOWN" });
  expect(JSON.stringify(result)).not.toContain("plugin.py");
});
