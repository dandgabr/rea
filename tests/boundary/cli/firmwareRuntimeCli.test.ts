import { Cli } from "incur";
import { Ajv2020 } from "ajv/dist/2020.js";
import pino from "pino";
import { expect, it, onTestFinished } from "vitest";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { registerFirmwareCommands } from "../../../src/cli/firmwareCommands.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { parseEvidence } from "../../../src/domain/evidence.js";

const selected = {
  kind: "container",
  command: "/usr/bin/podman",
  image: `sha256:${"a".repeat(64)}`,
  existing_store_profile: "/tmp/operator-store.json",
};

const invoke = async (
  args: string[],
  environment: Readonly<Record<string, string | undefined>> = {},
) => {
  const exitCode = process.exitCode;
  onTestFinished(() => {
    process.exitCode = exitCode;
  });
  const cli = Cli.create("firmware-test", { version: "1" });
  registerFirmwareCommands(cli, pino({ level: "silent" }), environment);
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
      message: expect.stringContaining(
        "caller-container runtime is unavailable",
      ),
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
    const runtimeSchema = Reflect.get(properties, "runtime") as object;
    const validate = new Ajv2020({ strict: false }).compile(runtimeSchema);
    expect(validate(JSON.stringify(selected))).toBe(true);
    expect(validate(selected)).toBe(false);
    expect(Reflect.get(runtimeSchema, "description")).toContain(
      "caller-container runtime is currently unavailable",
    );
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
    message: expect.stringContaining("absolute REA_UNBLOB_COMMAND"),
  });
  expect(
    await invoke(["inspect-firmware-provider", "--provider-id", "unblob"]),
  ).toMatchObject({
    message: expect.stringContaining("absolute REA_UNBLOB_COMMAND"),
  });
});

it.skipIf(
  process.env.REA_UNBLOB_ACCEPTANCE_ROOT === undefined ||
    process.env.REA_UNBLOB_ACCEPTANCE_COMMAND === undefined,
)("extracts with pinned Unblob through the public REA CLI", async () => {
  const workspace = await createTestTempDirectory("rea-unblob-cli-");
  const output = join(workspace, "published");
  const evidence = parseEvidence(
    await invoke(
      [
        "extract-firmware",
        process.env.REA_UNBLOB_ACCEPTANCE_INPUT ?? "/tmp/rea-unblob-input.gz",
        output,
        "--workers",
        "3",
      ],
      {
        ...process.env,
        REA_UNBLOB_RUNTIME_ROOT: process.env.REA_UNBLOB_ACCEPTANCE_ROOT,
        REA_UNBLOB_COMMAND: process.env.REA_UNBLOB_ACCEPTANCE_COMMAND,
      },
    ),
  );
  expect(evidence.provider).toMatchObject({ id: "unblob", version: "26.6.4" });
  expect(evidence.operation).toBe("extract_firmware");
  expect(evidence.normalized_result).toMatchObject({
    engine: { worker_count: 3 },
    coverage: "partial",
  });
  const result = evidence.normalized_result as unknown as {
    files: readonly { relative_path: string; sha256: string }[];
    published_bytes: number;
  };
  expect(result.files.length).toBeGreaterThan(0);
  expect(result.published_bytes).toBeGreaterThan(0);
  for (const file of result.files) {
    const bytes = await readFile(join(output, file.relative_path));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(file.sha256);
  }
});
