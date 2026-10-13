import { Cli } from "incur";
import { Ajv2020 } from "ajv/dist/2020.js";
import pino from "pino";
import { expect, it, onTestFinished } from "vitest";
import { registerFirmwareCommands } from "../../../src/cli/firmwareCommands.js";

const selected = {
  kind: "container",
  command: "/usr/bin/podman",
  image: `sha256:${"a".repeat(64)}`,
  existing_store_profile: "/tmp/operator-store.json",
};

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

it.each([
  ["inspect-firmware-provider", "--provider-id", "unblob"],
  ["inspect-firmware-regions", "/tmp/input.bin", "--provider-id", "unblob"],
  ["extract-firmware", "/tmp/input.bin", "/tmp/fresh-output"],
])(
  "preserves selected container through actual %s CLI parsing",
  async (...args) => {
    expect(
      await invoke([...args, "--runtime", JSON.stringify(selected)]),
    ).toMatchObject({
      code: "capability_unavailable",
      message: expect.stringContaining("native fallback is refused"),
    });
  },
);

it("refuses malformed, mutable or authority-expanding inline runtime JSON", async () => {
  for (const value of [
    "{",
    JSON.stringify({ ...selected, image: "latest" }),
    JSON.stringify({ ...selected, args: ["--privileged"] }),
  ]) {
    const result = JSON.stringify(
      await invoke([
        "inspect-firmware-provider",
        "--provider-id",
        "unblob",
        "--runtime",
        value,
      ]),
    );
    expect(result).not.toContain("native fallback is refused");
    expect(result).not.toContain("REA_UNBLOB_COMMAND");
    expect(JSON.parse(result)).toMatchObject({
      code: "invalid_request",
      category: "invalid_input",
    });
  }
});

it("rejects runtime on legacy inspection rather than falling back to Binwalk", async () => {
  const result = JSON.stringify(
    await invoke([
      "inspect-firmware-regions",
      "/tmp/input.bin",
      "--runtime",
      JSON.stringify(selected),
    ]),
  );
  expect(result).not.toContain("REA_BINWALK_COMMAND");
  expect(result).not.toContain("native fallback is refused");
  expect(result).toMatch(/invalid_request|Invalid/u);
});

it("advertises the actual inline string representation and preserves native omission", async () => {
  for (const command of [
    "inspect-firmware-provider",
    "inspect-firmware-regions",
    "extract-firmware",
  ]) {
    const advertised = await invoke([command, "--schema"]);
    expect(advertised).toMatchObject({
      options: {
        properties: {
          runtime: {
            type: "string",
            description: expect.stringContaining("JSON"),
          },
        },
      },
    });
    const options = Reflect.get(advertised as object, "options") as object;
    const properties = Reflect.get(options, "properties") as object;
    const validate = new Ajv2020({ strict: false }).compile(
      Reflect.get(properties, "runtime") as object,
    );
    expect(validate(JSON.stringify(selected))).toBe(true);
    expect(validate(selected)).toBe(false);
  }
  expect(
    await invoke([
      "inspect-firmware-provider",
      "--provider-id",
      "unblob",
      "--runtime",
      '{"kind":"native"}',
    ]),
  ).toMatchObject({
    message: expect.stringContaining("REA_UNBLOB_COMMAND"),
  });
  expect(
    await invoke(["inspect-firmware-provider", "--provider-id", "unblob"]),
  ).toMatchObject({
    message: expect.stringContaining("REA_UNBLOB_COMMAND"),
  });
});
