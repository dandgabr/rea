import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { z } from "zod";
import { Ajv2020 } from "ajv/dist/2020.js";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { readFile, writeFile, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { expect } from "vitest";
import type { TestProcesses } from "../../support/process/processFixture.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createFirmwareAnalysisProvider } from "../../../src/composition/firmware.js";
import { FirmwareAnalysisService } from "../../../src/application/firmware/FirmwareAnalysisService.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
const configured =
  process.platform === "linux" &&
  [
    process.env.REA_BINWALK_NG_COMMAND,
    process.env.REA_FIRMWARE_BWRAP_COMMAND,
    process.env.REA_BINWALK_NG_RUNTIME_MANIFEST,
  ].every((value) => value !== undefined);
const test = cliTest.skipIf(!configured);
const selected = (name: string) => {
  const value = process.env[name];
  if (value === undefined)
    throw new Error(`Missing selected native prerequisite ${name}`);
  return value;
};
const runtime = () => ({
  TMPDIR: process.env.TMPDIR ?? "/tmp",
  REA_BINWALK_NG_COMMAND: selected("REA_BINWALK_NG_COMMAND"),
  REA_FIRMWARE_BWRAP_COMMAND: selected("REA_FIRMWARE_BWRAP_COMMAND"),
  REA_BINWALK_NG_RUNTIME_MANIFEST: selected("REA_BINWALK_NG_RUNTIME_MANIFEST"),
  REA_FIRMWARE_PRLIMIT_COMMAND:
    process.env.REA_FIRMWARE_PRLIMIT_COMMAND ?? "/usr/bin/prlimit",
});
const fixture = async () => {
  const root = await createTestTempDirectory("rea-ng-public-native-");
  const path = join(root, "operator-name.bin"),
    payload = Buffer.from("real native public REA boundary\n".repeat(128)),
    compressed = gzipSync(payload),
    bytes = Buffer.concat([
      Buffer.alloc(64, 0xff),
      compressed,
      Buffer.alloc(32),
    ]);
  await writeFile(path, bytes, { mode: 0o400 });
  return { root, path, payload, compressed, bytes };
};
const wireSchema = (
  schema: Readonly<Record<string, unknown>>,
): Record<string, unknown> => ({ ...schema });
const digest = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");

const nativeCli = (processes: TestProcesses, root: string) => {
  const entrypoint =
    process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
  return async (args: string[]) => {
    const outcome = await processes.run(
      process.execPath,
      [entrypoint, ...args, "--format", "json"],
      {
        env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: root },
        timeoutMs: 125000,
      },
    );
    expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(0);
    return parseEvidence(JSON.parse(outcome.stdout));
  };
};

test("real source or installed public CLI retains exact selection, current carvings, extraction, native entropy and provider inventory", async ({
  processes,
}) => {
  const { root, path, payload, compressed, bytes } = await fixture();
  const run = nativeCli(processes, root);
  const inventory = await run([
    "inspect-firmware-provider",
    "--provider",
    "binwalk-ng",
  ]);
  expect(inventory.subject).toBeNull();
  const formats = toolContract("inspect_firmware_provider").outputSchema.parse(
    inventory,
  ).normalized_result;
  expect(formats.reported_signature_count).toBeGreaterThan(0);
  expect(
    formats.formats.some(
      (format) => format.name === "gzip" && format.extractor === "Built-in",
    ),
  ).toBe(true);
  expect(formats.dependency_readiness).toBe("unknown");
  const scan = toolContract("inspect_firmware_regions").outputSchema.parse(
    await run([
      "inspect-firmware-regions",
      path,
      "--provider",
      "binwalk-ng",
      "--offset",
      "64",
      "--length",
      String(compressed.length),
      "--include",
      "gzip",
      "--workers",
      "2",
      "--no-mmap",
    ]),
  );
  expect(scan.subject?.digest.sha256).toBe(digest(bytes));
  expect(scan.parameters).toMatchObject({
    provider_id: "binwalk-ng",
    options: { include: ["gzip"], workers: 2, no_mmap: true },
    range: { offset: 64, length: compressed.length },
  });
  const scanned = scan.normalized_result;
  if (!("provider_id" in scanned)) throw Error("Expected ng result");
  expect(scanned.engine.worker_count).toBe(2);
  expect(scanned.analyses[0]?.regions[0]?.root_file_range).toEqual({
    offset: 64,
    length: compressed.length,
  });
  expect(scanned.analyses[0]?.regions[0]?.local_range.offset).toBe(0);
  const carve = toolContract("carve_firmware").outputSchema.parse(
    await run([
      "carve-firmware",
      path,
      join(root, "carved"),
      "--provider",
      "binwalk-ng",
      "--include",
      "gzip",
    ]),
  ).normalized_result;
  const carved = carve.files.find(
    (file) =>
      file.byte_correspondence === "verified" &&
      file.original_file_range?.offset === 64,
  );
  expect(carved).toBeDefined();
  if (carved === undefined) throw Error("Missing verified actual carving");
  expect(await readFile(carved.path)).toEqual(compressed);
  expect(carved.sha256).toBe(digest(compressed));
  const extracted = toolContract("extract_firmware").outputSchema.parse(
    await run([
      "extract-firmware",
      path,
      join(root, "extracted"),
      "--provider",
      "binwalk-ng",
      "--include",
      "gzip",
      "--carve",
      "--recursive",
      "--max-depth",
      "3",
    ]),
  ).normalized_result;
  if (!("provider_id" in extracted)) throw Error("Expected ng extraction");
  const actual = [];
  for (const file of extracted.files)
    actual.push({ file, bytes: await readFile(file.path) });
  const child = actual.find((item) => item.bytes.equals(payload));
  expect(child).toBeDefined();
  expect(child?.file.original_file_range).toBeNull();
  expect(child?.file.runtime_address).toBeNull();
  expect(child?.file.sha256).toBe(digest(payload));
  expect(extracted.attempted_files.some((file) => file.depth === 1)).toBe(true);
  const entropy = toolContract("inspect_firmware_entropy").outputSchema.parse(
    await run([
      "inspect-firmware-entropy",
      path,
      "--offset",
      "64",
      "--length",
      String(compressed.length),
    ]),
  ).normalized_result;
  expect(entropy.entropy).toMatchObject({
    unit: "bits_per_byte",
    examined_bytes: compressed.length,
    interpretation: null,
  });
  expect(entropy.entropy.blocks[0]?.root_file_range).toEqual({
    offset: 64,
    length: compressed.length,
  });
  expect(entropy.png).toMatchObject({
    path: null,
    publication_state: "unpublished",
    width: 2048,
    height: 1024,
  });
  const published = toolContract("inspect_firmware_entropy").outputSchema.parse(
    await run([
      "inspect-firmware-entropy",
      path,
      "--output-directory",
      join(root, "plot"),
    ]),
  ).normalized_result;
  expect(published.png.publication_state).toBe("published");
  expect(published.png.path).not.toBeNull();
  const png = await readFile(published.png.path ?? "");
  expect(digest(png)).toBe(published.png.sha256);
  expect(png.readUInt32BE(16)).toBe(2048);
  expect(png.readUInt32BE(20)).toBe(1024);
  expect(await readFile(path)).toEqual(bytes);
  expect((await stat(path)).mode & 0o777).toBe(0o400);
}, 125000);

test("real public MCP client validates converted advertised schemas and selected native Evidence", async () => {
  const { root, path, bytes, compressed, payload } = await fixture();
  const entrypoint =
    process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
  const client = new Client({ name: "rea-ng-real-native", version: "1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: root },
    stderr: "pipe",
  });
  try {
    await client.connect(transport);
    const advertised = await client.listTools();
    const ajv = new Ajv2020({ strict: false });
    for (const name of [
      "inspect_firmware_provider",
      "inspect_firmware_regions",
      "carve_firmware",
      "extract_firmware",
      "inspect_firmware_entropy",
    ] as const) {
      const tool = advertised.tools.find(
        (candidate) => candidate.name === name,
      );
      expect(tool).toBeDefined();
      if (tool === undefined) throw Error("Missing advertised tool");
      expect(ajv.validateSchema(tool.inputSchema)).toBe(true);
      if (tool.outputSchema !== undefined)
        expect(ajv.validateSchema(wireSchema(tool.outputSchema))).toBe(true);
    }
    const input = {
      path,
      provider_id: "binwalk-ng",
      range: { offset: 64, length: compressed.length },
      options: { include: ["gzip"] },
    };
    const tool = advertised.tools.find(
      (candidate) => candidate.name === "inspect_firmware_regions",
    );
    if (tool === undefined) throw Error("Missing named scan");
    expect(ajv.compile(tool.inputSchema)(input)).toBe(true);
    const called = await client.callTool({
      name: "inspect_firmware_regions",
      arguments: input,
    });
    expect(called.isError, JSON.stringify(called)).not.toBe(true);
    const evidence = toolContract(
      "inspect_firmware_regions",
    ).outputSchema.parse(called.structuredContent);
    expect(evidence.subject?.digest.sha256).toBe(digest(bytes));
    const result = evidence.normalized_result;
    if (!("provider_id" in result)) throw Error("Expected ng Evidence");
    expect(result.analyses[0]?.regions[0]?.root_file_range).toEqual({
      offset: 64,
      length: compressed.length,
    });
    if (tool.outputSchema !== undefined)
      expect(
        ajv.compile(wireSchema(tool.outputSchema))(called.structuredContent),
      ).toBe(true);
    const inventory = await client.callTool({
      name: "inspect_firmware_provider",
      arguments: { provider_id: "binwalk-ng" },
    });
    expect(inventory.isError).not.toBe(true);
    expect(
      toolContract("inspect_firmware_provider").outputSchema.parse(
        inventory.structuredContent,
      ).subject,
    ).toBeNull();
    const carved = await client.callTool({
      name: "carve_firmware",
      arguments: {
        path,
        provider_id: "binwalk-ng",
        output_directory: join(root, "mcp-carved"),
        range: { offset: 64, length: compressed.length },
        options: { include: ["gzip"] },
      },
    });
    expect(carved.isError, JSON.stringify(carved)).not.toBe(true);
    const carvings = toolContract("carve_firmware").outputSchema.parse(
      carved.structuredContent,
    ).normalized_result;
    const carving = carvings.files.find(
      (file) => file.original_file_range?.offset === 64,
    );
    if (carving === undefined) throw Error("Missing MCP carving");
    expect(await readFile(carving.path)).toEqual(compressed);
    expect(carving.sha256).toBe(digest(compressed));
    const extracted = await client.callTool({
      name: "extract_firmware",
      arguments: {
        path,
        provider_id: "binwalk-ng",
        output_directory: join(root, "mcp-extracted"),
        options: { include: ["gzip"], recursive: true, carve: true },
      },
    });
    expect(extracted.isError, JSON.stringify(extracted)).not.toBe(true);
    const extraction = toolContract("extract_firmware").outputSchema.parse(
      extracted.structuredContent,
    ).normalized_result;
    if (!("provider_id" in extraction)) throw Error("Expected ng extraction");
    const extractedChild = extraction.files.find(
      (file) => file.sha256 === digest(payload),
    );
    if (extractedChild === undefined) throw Error("Missing MCP payload");
    expect(await readFile(extractedChild.path)).toEqual(payload);
    expect(extractedChild.original_file_range).toBeNull();
    const entropy = await client.callTool({
      name: "inspect_firmware_entropy",
      arguments: {
        path,
        provider_id: "binwalk-ng",
        range: { offset: 64, length: compressed.length },
        output_directory: join(root, "mcp-plot"),
      },
    });
    expect(entropy.isError, JSON.stringify(entropy)).not.toBe(true);
    const measured = toolContract(
      "inspect_firmware_entropy",
    ).outputSchema.parse(entropy.structuredContent).normalized_result;
    expect(measured.entropy.blocks[0]?.root_file_range).toEqual({
      offset: 64,
      length: compressed.length,
    });
    expect(measured.entropy.interpretation).toBeNull();
    expect(digest(await readFile(measured.png.path ?? ""))).toBe(
      measured.png.sha256,
    );
    const invalid = await client.callTool({
      name: "inspect_firmware_regions",
      arguments: { ...input, options: { include: ["gzip"], exclude: ["tar"] } },
    });
    expect(invalid.isError).toBe(true);
    expect(await readFile(path)).toEqual(bytes);
  } finally {
    await client.close();
    await transport.close();
  }
}, 125000);

cliTest.skipIf(
  !configured || process.env.REA_NG_BOUNDARY_FIXTURE_ROOT === undefined,
)(
  "actual 128MiB public native input is admitted and plus-one refuses before any native launch",
  async ({ processes }) => {
    const root = process.env.REA_NG_BOUNDARY_FIXTURE_ROOT;
    if (root === undefined)
      throw Error("Missing selected boundary fixture root");
    const manifest = z
      .object({
        fixtures: z.array(
          z.object({ path: z.string(), size: z.number(), sha256: z.string() }),
        ),
      })
      .parse(JSON.parse(await readFile(join(root, "manifest.json"), "utf8")));
    const path = join(root, "input-limit.bin"),
      oversized = join(root, "input-limit-plus-one.bin");
    expect((await stat(path)).size).toBe(134217728);
    expect((await stat(oversized)).size).toBe(134217729);
    const home = await createTestTempDirectory("rea-ng-public-limit-home-");
    const entrypoint =
      process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
    const accepted = await processes.run(
      process.execPath,
      [
        entrypoint,
        "inspect-firmware-regions",
        path,
        "--provider",
        "binwalk-ng",
        "--include",
        "gzip",
        "--format",
        "json",
      ],
      {
        env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: home },
        timeoutMs: 125000,
      },
    );
    expect(accepted.exitCode, accepted.stderr).toBe(0);
    const evidence = parseEvidence(JSON.parse(accepted.stdout));
    expect(evidence.normalized_result).toMatchObject({
      input_size: 134217728,
      selection: { length: 134217728 },
    });
    expect(evidence.subject?.digest.sha256).toBe(
      manifest.fixtures.find((item) => item.path === path)?.sha256,
    );
    let launches = 0;
    const provider = createFirmwareAnalysisProvider(
      runtime(),
      async (options) => {
        launches++;
        return spawnOwnedProviderProcess(options);
      },
    );
    const service = new FirmwareAnalysisService(provider);
    try {
      const rejected = await service.execute("inspect_firmware_regions", {
        path: oversized,
        provider_id: "binwalk-ng",
      });
      expect(rejected).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError" },
      });
      expect(launches).toBe(0);
    } finally {
      await service.close();
    }
    const rejected = await processes.run(
      process.execPath,
      [
        entrypoint,
        "inspect-firmware-regions",
        oversized,
        "--provider",
        "binwalk-ng",
        "--format",
        "json",
      ],
      {
        env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: home },
        timeoutMs: 125000,
      },
    );
    expect(rejected.exitCode).not.toBe(0);
    expect(JSON.parse(rejected.stdout)).toMatchObject({
      code: "invalid_request",
    });
  },
  125000,
);

test("actual public native entropy preserves the 2047/2048/2049 window transition without interpolation", async ({
  processes,
}) => {
  const root = await createTestTempDirectory("rea-ng-public-windows-");
  const entrypoint =
    process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
  for (const length of [2047, 2048, 2049]) {
    const path = join(root, `window-${length}.bin`),
      bytes = Buffer.from(Array.from({ length }, (_, index) => index % 17));
    await writeFile(path, bytes, { mode: 0o400 });
    const called = await processes.run(
      process.execPath,
      [entrypoint, "inspect-firmware-entropy", path, "--format", "json"],
      {
        env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: root },
        timeoutMs: 125000,
      },
    );
    expect(called.exitCode, called.stdout + called.stderr).toBe(0);
    const entropy = toolContract("inspect_firmware_entropy").outputSchema.parse(
      JSON.parse(called.stdout),
    ).normalized_result.entropy;
    expect(entropy.nominal_window_bytes).toBe(length === 2047 ? 2047 : 1);
    expect(entropy.examined_bytes).toBe(length);
    expect(entropy.blocks).toHaveLength(length === 2047 ? 1 : length);
    expect(entropy.interpretation).toBeNull();
    if (length === 2047) {
      const counts = new Map<number, number>();
      for (const byte of bytes) counts.set(byte, (counts.get(byte) ?? 0) + 1);
      const measured = [...counts.values()].reduce(
        (sum, count) => sum - (count / length) * Math.log2(count / length),
        0,
      );
      expect(entropy.blocks[0]?.entropy).toBeCloseTo(measured, 5);
    } else {
      for (const block of entropy.blocks) {
        expect(block.end - block.start).toBe(1);
        expect(block.entropy).toBe(0);
      }
    }
  }
}, 125000);

cliTest.skipIf(
  !configured ||
    process.env.REA_BINWALK_NG_TEST_NO_ENTROPY_COMMAND === undefined,
)(
  "actual feature-disabled native build returns named public CLI and MCP capability refusal with native stderr",
  async ({ processes }) => {
    const { root, path, bytes } = await fixture();
    const entrypoint =
      process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
    const disabled = selected("REA_BINWALK_NG_TEST_NO_ENTROPY_COMMAND"),
      environment = {
        PATH: process.env.PATH ?? "",
        ...runtime(),
        REA_BINWALK_NG_COMMAND: disabled,
        HOME: root,
      };
    const called = await processes.run(
      process.execPath,
      [entrypoint, "inspect-firmware-entropy", path, "--format", "json"],
      { env: environment, timeoutMs: 125000 },
    );
    expect(called.exitCode).not.toBe(0);
    const error = z
      .object({
        code: z.literal("capability_unavailable"),
        details: z.object({ diagnostics: z.object({ stderr: z.string() }) }),
      })
      .parse(JSON.parse(called.stdout));
    expect(error.details.diagnostics.stderr).toContain(
      'built without the "entropy-plot" feature',
    );
    const client = new Client({ name: "rea-ng-no-entropy", version: "1" }),
      transport = new StdioClientTransport({
        command: process.execPath,
        args: [entrypoint, "mcp"],
        env: environment,
        stderr: "pipe",
      });
    try {
      await client.connect(transport);
      const response = await client.callTool({
        name: "inspect_firmware_entropy",
        arguments: { path, provider_id: "binwalk-ng" },
      });
      expect(response.isError).toBe(true);
      const projected = z
        .object({
          error: z.object({
            code: z.literal("capability_unavailable"),
            details: z.object({
              diagnostics: z.object({ stderr: z.string() }),
            }),
          }),
        })
        .parse(
          JSON.parse(
            response.content.find((item) => item.type === "text")?.text ??
              "null",
          ),
        );
      expect(projected.error.details.diagnostics.stderr).toContain(
        'built without the "entropy-plot" feature',
      );
    } finally {
      await client.close();
      await transport.close();
    }
    expect(await readFile(path)).toEqual(bytes);
  },
  125000,
);

test("actual public CLI preserves search-all/exclusion/no-recursion choices and refuses reused output and legacy-ignored options", async ({
  processes,
}) => {
  const { root, path, bytes } = await fixture();
  const run = nativeCli(processes, root);
  const scan = await run([
    "inspect-firmware-regions",
    path,
    "--provider",
    "binwalk-ng",
    "--search-all",
    "--exclude",
    "tar",
    "--exclude",
    "zip",
  ]);
  expect(scan.parameters).toMatchObject({
    options: { search_all: true, exclude: ["tar", "zip"], include: [] },
  });
  const output = join(root, "one-pass"),
    extracted = await run([
      "extract-firmware",
      path,
      output,
      "--provider",
      "binwalk-ng",
      "--include",
      "gzip",
      "--no-recursive",
    ]);
  expect(extracted.parameters).toMatchObject({ options: { recursive: false } });
  const result =
    toolContract("extract_firmware").outputSchema.parse(
      extracted,
    ).normalized_result;
  if (!("provider_id" in result)) throw Error("Expected ng extraction");
  expect(result.attempted_files).toHaveLength(1);
  const saved = await Promise.all(
    result.files.map(async (file) => ({
      path: file.path,
      bytes: await readFile(file.path),
    })),
  );
  const entrypoint =
    process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
  for (const args of [
    [
      "extract-firmware",
      path,
      output,
      "--provider",
      "binwalk-ng",
      "--include",
      "gzip",
    ],
    ["inspect-firmware-regions", path, "--include", "gzip"],
  ]) {
    const outcome = await processes.run(
      process.execPath,
      [entrypoint, ...args, "--format", "json"],
      {
        env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: root },
        timeoutMs: 125000,
      },
    );
    expect(outcome.exitCode).not.toBe(0);
    expect(JSON.parse(outcome.stdout)).toHaveProperty("code");
  }
  for (const savedFile of saved)
    expect(await readFile(savedFile.path)).toEqual(savedFile.bytes);
  expect(await readFile(path)).toEqual(bytes);
}, 125000);

cliTest.skipIf(
  !configured || process.env.REA_NG_BOUNDARY_FIXTURE_ROOT === undefined,
)(
  "actual public MCP admits the exact 128MiB fixture and refuses plus-one with a named request error",
  async () => {
    const root = selected("REA_NG_BOUNDARY_FIXTURE_ROOT"),
      home = await createTestTempDirectory("rea-ng-mcp-limit-home-");
    const path = join(root, "input-limit.bin"),
      oversized = join(root, "input-limit-plus-one.bin");
    const entrypoint =
      process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
    const client = new Client({ name: "rea-ng-mcp-boundary", version: "1" }),
      transport = new StdioClientTransport({
        command: process.execPath,
        args: [entrypoint, "mcp"],
        env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: home },
        stderr: "pipe",
      });
    try {
      await client.connect(transport);
      const admitted = await client.callTool({
        name: "inspect_firmware_regions",
        arguments: {
          path,
          provider_id: "binwalk-ng",
          options: { include: ["gzip"] },
        },
      });
      expect(admitted.isError, JSON.stringify(admitted)).not.toBe(true);
      const evidence = toolContract(
        "inspect_firmware_regions",
      ).outputSchema.parse(admitted.structuredContent);
      expect(evidence.normalized_result).toMatchObject({
        input_size: 134217728,
        selection: { offset: 0, length: 134217728 },
      });
      const oracle = z
        .object({
          fixtures: z.array(
            z.object({
              path: z.string(),
              size: z.number(),
              sha256: z.string(),
            }),
          ),
        })
        .parse(JSON.parse(await readFile(join(root, "manifest.json"), "utf8")));
      expect(evidence.subject?.digest.sha256).toBe(
        oracle.fixtures.find((item) => item.path === path)?.sha256,
      );
      const rejected = await client.callTool({
        name: "inspect_firmware_regions",
        arguments: { path: oversized, provider_id: "binwalk-ng" },
      });
      expect(rejected.isError).toBe(true);
      expect(
        JSON.parse(
          rejected.content.find((item) => item.type === "text")?.text ?? "null",
        ),
      ).toMatchObject({ error: { code: "invalid_request" } });
    } finally {
      await client.close();
      await transport.close();
    }
  },
  125000,
);

test("public native UTF8 boundaries refuse unpaired UTF16 without launch and preserve exact valid fixed argv through CLI and MCP", async ({
  processes,
}) => {
  const { root, path, bytes } = await fixture();
  const names = ["😀", "\ufffd", "two words", "--help"];
  const launches: string[][] = [];
  const service = new FirmwareAnalysisService(
    createFirmwareAnalysisProvider(runtime(), async (options) => {
      launches.push([...options.arguments]);
      return spawnOwnedProviderProcess(options);
    }),
  );
  try {
    for (const operation of [
      "inspect_firmware_regions",
      "extract_firmware",
      "carve_firmware",
    ] as const) {
      for (const field of ["include", "exclude"]) {
        for (const name of ["\ud800", "\udfff"]) {
          const input = JSON.parse(
            JSON.stringify({
              path,
              provider_id: "binwalk-ng",
              ...(operation === "inspect_firmware_regions"
                ? {}
                : { output_directory: join(root, "never-published") }),
              options: { [field]: [name] },
            }),
          );
          expect(await service.execute(operation, input)).toMatchObject({
            ok: false,
            error: { _tag: "AnalysisInputError" },
          });
        }
      }
    }
    expect(launches).toHaveLength(0);
    const outcome = await service.execute("inspect_firmware_regions", {
      path,
      provider_id: "binwalk-ng",
      options: { exclude: names },
    });
    expect(outcome.ok).toBe(true);
    const argv = launches.at(-1);
    expect(argv).toContain(`--exclude=${names.join(",")}`);
    expect(argv?.filter((value) => value === "--help")).toEqual([]);
    const retained = argv?.find((value) => value.startsWith("--exclude="));
    expect(Buffer.from(retained ?? "", "utf8").toString("utf8")).toBe(retained);
  } finally {
    await service.close();
  }
  const cli = await nativeCli(
    processes,
    root,
  )([
    "inspect-firmware-regions",
    path,
    "--provider",
    "binwalk-ng",
    ...names.map((name) => `--exclude=${name}`),
  ]);
  expect(cli.parameters).toMatchObject({ options: { exclude: names } });
  const entrypoint =
    process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
  const client = new Client({ name: "rea-ng-utf8-boundary", version: "1" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: root },
    stderr: "pipe",
  });
  try {
    await client.connect(transport);
    const advertised = await client.listTools();
    const ajv = new Ajv2020({ strict: false });
    for (const operation of [
      "inspect_firmware_regions",
      "extract_firmware",
      "carve_firmware",
    ] as const) {
      const tool = advertised.tools.find(
        (candidate) => candidate.name === operation,
      );
      if (!tool) throw Error("Missing named contract");
      const validate = ajv.compile(tool.inputSchema);
      for (const field of ["include", "exclude"]) {
        for (const name of ["\ud800", "\udfff"]) {
          const input = {
            path,
            provider_id: "binwalk-ng",
            ...(operation === "inspect_firmware_regions"
              ? {}
              : { output_directory: join(root, "never-published") }),
            options: { [field]: [name] },
          };
          expect(validate(input)).toBe(false);
          const rejected = await client.callTool({
            name: operation,
            arguments: input,
          });
          expect(rejected.isError).toBe(true);
          const refusal = rejected.content.find(
            (item) => item.type === "text",
          )?.text;
          expect(refusal).toContain("Input validation error");
          expect(refusal).toContain(
            "Signature names must be representable as UTF-8",
          );
        }
      }
    }
    const valid = {
      path,
      provider_id: "binwalk-ng",
      options: { exclude: names },
    };
    const schema = advertised.tools.find(
      (candidate) => candidate.name === "inspect_firmware_regions",
    )?.inputSchema;
    if (!schema) throw Error("Missing scan schema");
    expect(ajv.compile(schema)(valid)).toBe(true);
    const called = await client.callTool({
      name: "inspect_firmware_regions",
      arguments: valid,
    });
    expect(called.isError, JSON.stringify(called)).not.toBe(true);
    const evidence = toolContract(
      "inspect_firmware_regions",
    ).outputSchema.parse(called.structuredContent);
    expect(evidence.parameters).toMatchObject({ options: { exclude: names } });
    expect(evidence.subject?.digest.sha256).toBe(digest(bytes));
  } finally {
    await client.close();
    await transport.close();
  }
  expect(await readFile(path)).toEqual(bytes);
}, 125000);
