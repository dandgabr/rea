import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { z } from "zod";
import { Ajv2020 } from "ajv/dist/2020.js";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { readFile, readdir, stat, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { expect, it } from "vitest";
import type { TestProcesses } from "../../support/process/processFixture.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { firmwareInputSchemas } from "../../../src/domain/firmware/firmwareAnalysis.js";
import {
  binwalkNgInputSchemas,
  binwalkNgProviderInputSchema,
} from "../../../src/domain/firmware/binwalkNgAnalysis.js";
import { createFirmwareAnalysisProvider } from "../../../src/composition/firmware.js";
import { FirmwareAnalysisService } from "../../../src/application/firmware/FirmwareAnalysisService.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
const nativeConfigured =
  process.platform === "linux" &&
  [
    "REA_BINWALK_NG_COMMAND",
    "REA_BINWALK_NG_RUNTIME_MANIFEST",
    "REA_FIRMWARE_BWRAP_COMMAND",
  ].every((name) => (process.env[name] ?? "").startsWith("/"));
const test = cliTest.skipIf(!nativeConfigured);
const runtimeHasSevenZip = (() => {
  const manifestPath = process.env.REA_BINWALK_NG_RUNTIME_MANIFEST;
  if (manifestPath === undefined) return false;
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      helpers?: { name?: string; supported_signatures?: string[] }[];
    };
    return (
      manifest.helpers?.some(
        (helper) =>
          helper.name === "7z" &&
          helper.supported_signatures?.includes("7zip") === true,
      ) === true
    );
  } catch {
    return false;
  }
})();
const isolatedFixtureImage =
  "ghcr.io/binwalk-ng/binwalk-ng@sha256:fb2f83d2700a5cd3c97ac19896bac375993a591e3a10916e7f55e096598c7c04";
const isolatedFixtureConfigured =
  process.env.REA_BINWALK_NG_FIXTURE_IMAGE === isolatedFixtureImage;
const testWithBoundaryFixtures = cliTest.skipIf(
  !nativeConfigured || process.env.REA_NG_BOUNDARY_FIXTURE_ROOT === undefined,
);
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
  REA_FIRMWARE_SYSTEMD_RUN_COMMAND:
    process.env.REA_FIRMWARE_SYSTEMD_RUN_COMMAND ?? "/usr/bin/systemd-run",
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

it("keeps Binwalk-NG's public firmware catalog to analysis and extraction contracts only", () => {
  const providerOperations = [
    ...Object.keys(binwalkNgInputSchemas),
    "inspect_firmware_provider",
  ].sort();
  expect(providerOperations).toEqual(
    [
      "carve_firmware",
      "extract_firmware",
      "inspect_firmware_entropy",
      "inspect_firmware_regions",
      "inspect_firmware_provider",
    ].sort(),
  );
  const forbiddenOperations = [
    "flash_firmware",
    "update_firmware",
    "boot_firmware",
    "emulate_firmware",
    "jtag",
    "uart",
    "glitch_firmware",
    "control_hardware",
  ];
  for (const operation of forbiddenOperations) {
    expect(providerOperations).not.toContain(operation);
    expect(Object.keys(firmwareInputSchemas)).not.toContain(operation);
  }
  const samples = {
    inspect_firmware_regions: {
      path: "/tmp/firmware.bin",
      provider_id: "binwalk-ng",
    },
    carve_firmware: {
      path: "/tmp/firmware.bin",
      provider_id: "binwalk-ng",
      output_directory: "/tmp/carved",
    },
    extract_firmware: {
      path: "/tmp/firmware.bin",
      provider_id: "binwalk-ng",
      output_directory: "/tmp/extracted",
    },
    inspect_firmware_entropy: {
      path: "/tmp/firmware.bin",
      provider_id: "binwalk-ng",
    },
    inspect_firmware_provider: { provider_id: "binwalk-ng" },
  } as const;
  for (const [operation, sample] of Object.entries(samples))
    for (const field of [
      "flash",
      "update",
      "boot",
      "emulate",
      "jtag",
      "uart",
      "glitch",
      "device",
    ])
      expect(
        (operation === "inspect_firmware_provider"
          ? binwalkNgProviderInputSchema
          : binwalkNgInputSchemas[
              operation as keyof typeof binwalkNgInputSchemas
            ]
        ).safeParse({ ...sample, [field]: true }).success,
      ).toBe(false);
});

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

test("real native CLI retains selected scan and entropy Evidence plus provider inventory", async ({
  processes,
}) => {
  const { root, path, compressed, bytes } = await fixture();
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
  const extraction = toolContract("extract_firmware").outputSchema.parse(
    await run([
      "extract-firmware",
      path,
      join(root, "extracted"),
      "--provider",
      "binwalk-ng",
      "--include",
      "gzip",
      "--recursive",
      "--max-depth",
      "3",
    ]),
  );
  expect(extraction.subject?.digest.sha256).toBe(digest(bytes));
  expect(extraction.normalized_result.coverage).toBeDefined();
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

cliTest.skipIf(!nativeConfigured)(
  "real public MCP client validates converted schemas, extraction and recursive Evidence",
  async () => {
    const { root, path, bytes, compressed } = await fixture();
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
      const carvedOutput = join(root, "mcp-carve");
      const carved = await client.callTool({
        name: "carve_firmware",
        arguments: {
          path,
          provider_id: "binwalk-ng",
          output_directory: carvedOutput,
        },
      });
      expect(carved.isError, JSON.stringify(carved)).not.toBe(true);
      const carvedEvidence = toolContract("carve_firmware").outputSchema.parse(
        carved.structuredContent,
      );
      expect(carvedEvidence.subject?.digest.sha256).toBe(digest(bytes));
      expect(carvedEvidence.normalized_result.files).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            size: compressed.length,
            byte_correspondence: "verified",
          }),
        ]),
      );
      const extracted = await client.callTool({
        name: "extract_firmware",
        arguments: {
          path,
          provider_id: "binwalk-ng",
          output_directory: join(root, "mcp-extract"),
          max_depth: 3,
          options: { include: ["gzip"], recursive: true },
        },
      });
      expect(extracted.isError, JSON.stringify(extracted)).not.toBe(true);
      const extractionEvidence = toolContract(
        "extract_firmware",
      ).outputSchema.parse(extracted.structuredContent);
      expect(extractionEvidence.subject?.digest.sha256).toBe(digest(bytes));
      expect(extractionEvidence.parameters).toMatchObject({
        options: { include: ["gzip"], recursive: true },
        max_depth: 3,
      });
      expect(extractionEvidence.normalized_result.coverage).toBeDefined();
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
        arguments: {
          ...input,
          options: { include: ["gzip"], exclude: ["tar"] },
        },
      });
      expect(invalid.isError).toBe(true);
      expect(await readFile(path)).toEqual(bytes);
    } finally {
      await client.close();
      await transport.close();
    }
  },
  125000,
);

testWithBoundaryFixtures(
  "public native CLI enforces its selected input byte limit and preserves digest evidence at the boundary",
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
  !nativeConfigured ||
    !(process.env.REA_BINWALK_NG_TEST_NO_ENTROPY_COMMAND ?? "").startsWith("/"),
)(
  "public CLI and MCP report entropy capability unavailable for a feature-disabled native build",
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

test("actual public CLI preserves scan options and admits explicitly scoped extraction", async ({
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
  const output = join(root, "one-pass");
  const extraction = toolContract("extract_firmware").outputSchema.parse(
    await run([
      "extract-firmware",
      path,
      output,
      "--provider",
      "binwalk-ng",
      "--include",
      "gzip",
      "--recursive",
      "--max-depth",
      "3",
    ]),
  );
  expect(extraction.subject?.digest.sha256).toBe(digest(bytes));
  expect(extraction.parameters).toMatchObject({
    options: { include: ["gzip"], recursive: true },
    max_depth: 3,
  });
  expect((await stat(output)).isDirectory()).toBe(true);
  expect(await readFile(path)).toEqual(bytes);
}, 125000);

test("actual public REA carve path transfers quota-bounded internal Binwalk-NG artifacts", async ({
  processes,
}) => {
  const { root, path, bytes, compressed } = await fixture();
  const output = join(root, "carved-output");
  const entrypoint =
    process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
  const outcome = await processes.run(
    process.execPath,
    [
      entrypoint,
      "carve-firmware",
      path,
      output,
      "--provider",
      "binwalk-ng",
      "--format",
      "json",
    ],
    {
      env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: root },
      timeoutMs: 125000,
    },
  );
  expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(0);
  expect(await readFile(path)).toEqual(bytes);
  const evidence = toolContract("carve_firmware").outputSchema.parse(
    parseEvidence(JSON.parse(outcome.stdout)),
  );
  expect(evidence.normalized_result).toMatchObject({
    provider_id: "binwalk-ng",
    coverage: "signature_scan",
  });
  expect(evidence.normalized_result.files).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        size: compressed.length,
        byte_correspondence: "verified",
      }),
    ]),
  );
  expect((await stat(output)).isDirectory()).toBe(true);
}, 125000);

const assertMcpReportsMissingSevenZip = async (input: {
  readonly root: string;
  readonly entrypoint: string;
  readonly archivePath: string;
  readonly inputDigest: string;
  readonly archive: Buffer;
  readonly absentHelperManifest: string;
}) => {
  const outputDirectory = join(input.root, "mcp-no-helper-output");
  const client = new Client({
    name: "rea-ng-7z-native-no-helper",
    version: "1",
  });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [input.entrypoint, "mcp"],
    env: {
      PATH: process.env.PATH ?? "",
      ...runtime(),
      REA_BINWALK_NG_RUNTIME_MANIFEST: input.absentHelperManifest,
      HOME: input.root,
    },
    stderr: "pipe",
  });
  try {
    await client.connect(transport);
    const result = await client.callTool({
      name: "extract_firmware",
      arguments: {
        path: input.archivePath,
        provider_id: "binwalk-ng",
        output_directory: outputDirectory,
        options: { include: ["7zip"] },
      },
    });
    expect(result.isError, JSON.stringify(result)).not.toBe(true);
    const evidence = toolContract("extract_firmware").outputSchema.parse(
      result.structuredContent,
    );
    expect(evidence.subject?.digest.sha256).toBe(input.inputDigest);
    expect(evidence.normalized_result.coverage).toBe("partial");
    const normalized = evidence.normalized_result;
    if (!("analyses" in normalized))
      throw new Error("MCP extraction Evidence has no analysis observations");
    expect(normalized.analyses).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          extractions: expect.arrayContaining([
            expect.objectContaining({ success: false }),
          ]),
        }),
      ]),
    );
    expect(JSON.stringify(evidence.raw_result)).toContain(
      "No such file or directory",
    );
    expect(await readdir(outputDirectory)).toEqual([]);
    expect(await readFile(input.archivePath)).toEqual(input.archive);
  } finally {
    await client.close();
    await transport.close();
  }
};

const createIsolatedSevenZipFixture = async (input: {
  processes: TestProcesses;
  root: string;
  payloadPath: string;
  archivePath: string;
}): Promise<Buffer> => {
  const payload = Buffer.from("external helper extraction fixture\n");
  await writeFile(input.payloadPath, payload, { mode: 0o400 });
  const created = await input.processes.run(
    "/usr/bin/podman",
    [
      "run",
      "--rm",
      "--pull=never",
      "--network=none",
      "--read-only",
      "--cap-drop=all",
      "--security-opt=no-new-privileges",
      "--pids-limit=32",
      "--memory=256m",
      "--memory-swap=256m",
      "--cpus=1",
      "--userns=keep-id",
      "--user",
      `${String(process.getuid?.() ?? 1000)}:${String(process.getgid?.() ?? 1000)}`,
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,nodev,size=16m",
      "--tmpfs",
      "/out:rw,noexec,nosuid,nodev,size=16m",
      "--volume",
      `${input.payloadPath}:/fixture/payload.bin:ro,Z`,
      "--entrypoint",
      "/bin/sh",
      isolatedFixtureImage,
      "-c",
      "/usr/bin/7z a -t7z /out/external.7z /fixture/payload.bin >/dev/null && base64 -w0 /out/external.7z",
    ],
    {
      env: {
        PATH: "/usr/bin:/bin",
        HOME: process.env.HOME ?? input.root,
        ...(process.env.XDG_RUNTIME_DIR === undefined
          ? {}
          : { XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR }),
      },
      timeoutMs: 30_000,
    },
  );
  expect(created.exitCode, created.stderr).toBe(0);
  const archive = Buffer.from(created.stdout.trim(), "base64");
  expect(archive.length).toBeGreaterThan(0);
  await writeFile(input.archivePath, archive, { mode: 0o400 });
  return archive;
};

const assertCompleteSevenZipCapability = (helper: {
  supported_signatures: string[];
}) =>
  expect(helper.supported_signatures).toEqual([
    "7zip",
    "apfs",
    "arj",
    "compressd",
    "cpio",
    "cramfs",
    "efigpt",
    "iso9660",
    "zip",
    "xz",
  ]);

cliTest.skipIf(
  !nativeConfigured || !runtimeHasSevenZip || !isolatedFixtureConfigured,
)(
  "real CLI and MCP extract a 7z fixture through the explicitly admitted external helper",
  async ({ processes }) => {
    const root = await createTestTempDirectory("rea-ng-public-7z-");
    const manifest = JSON.parse(
      await readFile(selected("REA_BINWALK_NG_RUNTIME_MANIFEST"), "utf8"),
    ) as {
      helpers: {
        name: string;
        source: string;
        supported_signatures: string[];
      }[];
    };
    const helper = manifest.helpers.find((item) => item.name === "7z");
    if (helper === undefined)
      throw Error("7z helper disappeared from manifest");
    assertCompleteSevenZipCapability(helper);
    const payloadPath = join(root, "external-payload.bin");
    const archivePath = join(root, "external.7z");
    const outputPath = join(root, "cli-output");
    const archive = await createIsolatedSevenZipFixture({
      processes,
      root,
      payloadPath,
      archivePath,
    });
    const inputDigest = digest(archive);
    const entrypoint =
      process.env.REA_FIRMWARE_TEST_ENTRYPOINT ?? resolve("scripts/rea.mjs");
    const cli = await processes.run(
      process.execPath,
      [
        entrypoint,
        "extract-firmware",
        archivePath,
        outputPath,
        "--provider",
        "binwalk-ng",
        "--include",
        "7zip",
        "--format",
        "json",
      ],
      {
        env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: root },
        timeoutMs: 125_000,
      },
    );
    expect(cli.exitCode, cli.stdout + cli.stderr).toBe(0);
    const cliEvidence = toolContract("extract_firmware").outputSchema.parse(
      parseEvidence(JSON.parse(cli.stdout)),
    );
    expect(cliEvidence.subject?.digest.sha256).toBe(inputDigest);
    expect(cliEvidence.normalized_result.coverage).toBeDefined();
    expect(await readFile(archivePath)).toEqual(archive);

    const absentHelperManifest = join(root, "runtime-no-7z.json");
    await writeFile(
      absentHelperManifest,
      JSON.stringify({
        ...JSON.parse(
          await readFile(selected("REA_BINWALK_NG_RUNTIME_MANIFEST"), "utf8"),
        ),
        helpers: manifest.helpers.filter((item) => item.name !== "7z"),
      }),
    );
    const absentHelper = await processes.run(
      process.execPath,
      [
        entrypoint,
        "extract-firmware",
        archivePath,
        join(root, "no-helper-output"),
        "--provider",
        "binwalk-ng",
        "--include",
        "7zip",
        "--format",
        "json",
      ],
      {
        env: {
          PATH: process.env.PATH ?? "",
          ...runtime(),
          REA_BINWALK_NG_RUNTIME_MANIFEST: absentHelperManifest,
          HOME: root,
        },
        timeoutMs: 125_000,
      },
    );
    expect(
      absentHelper.exitCode,
      absentHelper.stdout + absentHelper.stderr,
    ).toBe(0);
    const absentHelperEvidence = toolContract(
      "extract_firmware",
    ).outputSchema.parse(parseEvidence(JSON.parse(absentHelper.stdout)));
    expect(absentHelperEvidence.normalized_result.coverage).toBe("partial");
    const absentHelperResult = absentHelperEvidence.normalized_result;
    if (!("analyses" in absentHelperResult))
      throw new Error("Extraction Evidence has no analysis observations");
    expect(absentHelperResult.analyses).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          extractions: expect.arrayContaining([
            expect.objectContaining({ success: false }),
          ]),
        }),
      ]),
    );
    expect(JSON.stringify(absentHelperEvidence.raw_result)).toContain(
      "No such file or directory",
    );
    expect(await readdir(join(root, "no-helper-output"))).toEqual([]);
    expect(await readFile(archivePath)).toEqual(archive);

    await assertMcpReportsMissingSevenZip({
      root,
      entrypoint,
      archivePath,
      inputDigest,
      archive,
      absentHelperManifest,
    });

    const client = new Client({ name: "rea-ng-7z-native", version: "1" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [entrypoint, "mcp"],
      env: { PATH: process.env.PATH ?? "", ...runtime(), HOME: root },
      stderr: "pipe",
    });
    try {
      await client.connect(transport);
      const result = await client.callTool({
        name: "extract_firmware",
        arguments: {
          path: archivePath,
          provider_id: "binwalk-ng",
          output_directory: join(root, "mcp-output"),
          options: { include: ["7zip"] },
        },
      });
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      const evidence = toolContract("extract_firmware").outputSchema.parse(
        result.structuredContent,
      );
      expect(evidence.subject?.digest.sha256).toBe(inputDigest);
      expect(evidence.normalized_result.coverage).toBeDefined();
      expect(await readFile(archivePath)).toEqual(archive);
    } finally {
      await client.close();
      await transport.close();
    }
  },
  125_000,
);

testWithBoundaryFixtures(
  "public MCP enforces the native input byte limit and preserves digest evidence at the boundary",
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
