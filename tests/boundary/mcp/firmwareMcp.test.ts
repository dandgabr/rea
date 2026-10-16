import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it as test, onTestFinished } from "vitest";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { FIRMWARE_TOOL_CONTRACTS } from "../../../src/contracts/firmware/firmwareToolContracts.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { firmwareInputSchemas } from "../../../src/domain/firmware/firmwareAnalysis.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import {
  firmwareFixture,
  assertFirmwareCleanup,
} from "../../fixtures/firmware/provider.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const it = test.skipIf(process.platform !== "linux");

test.skipIf(
  process.platform !== "linux" ||
    process.env.REA_UNBLOB_ACCEPTANCE_ROOT === undefined ||
    process.env.REA_UNBLOB_ACCEPTANCE_COMMAND === undefined,
)(
  "executes real Unblob inspection through the public MCP contract",
  async () => {
    const root = process.env.REA_UNBLOB_ACCEPTANCE_ROOT!;
    const command = process.env.REA_UNBLOB_ACCEPTANCE_COMMAND!;
    const session = createTestBinarySession(() => {
      throw new Error("Firmware inspection must not acquire a native provider");
    });
    const server = createServer(
      { kind: "session", session },
      {
        environment: {
          ...process.env,
          REA_UNBLOB_RUNTIME_ROOT: root,
          REA_UNBLOB_COMMAND: command,
        },
      },
    );
    const client = new Client({ name: "real-unblob-acceptance", version: "1" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    onTestFinished(async () => {
      await client.close();
      await server.close();
      await session.close();
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const path =
      process.env.REA_UNBLOB_ACCEPTANCE_INPUT ?? "/tmp/rea-unblob-input.gz";
    const response = await client.callTool({
      name: "inspect_firmware_regions",
      arguments: { provider_id: "unblob", path, options: { workers: 3 } },
    });
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    const result = FIRMWARE_TOOL_CONTRACTS.find(
      ({ name }) => name === "inspect_firmware_regions",
    )!.outputSchema.parse(response.structuredContent);
    const evidence = parseEvidence(result);
    expect(evidence.provider).toMatchObject({
      id: "unblob",
      version: "26.6.4",
    });
    expect(evidence.operation).toBe("inspect_firmware_regions");
    expect(evidence.subject?.digest.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(evidence.normalized_result).toMatchObject({
      engine: { worker_count: 3 },
      coverage: "partial",
    });
    const inventoryResponse = await client.callTool({
      name: "inspect_firmware_provider",
      arguments: { provider_id: "unblob" },
    });
    expect(
      inventoryResponse.isError,
      JSON.stringify(inventoryResponse),
    ).not.toBe(true);
    const inventory = FIRMWARE_TOOL_CONTRACTS.find(
      ({ name }) => name === "inspect_firmware_provider",
    )!.outputSchema.parse(inventoryResponse.structuredContent);
    expect(parseEvidence(inventory).provider).toMatchObject({
      id: "unblob",
      version: "26.6.4",
    });
  },
);

test.skipIf(
  process.platform !== "linux" ||
    process.env.REA_UNBLOB_ACCEPTANCE_ROOT === undefined ||
    process.env.REA_UNBLOB_ACCEPTANCE_COMMAND === undefined,
)(
  "publishes real Unblob extraction through the public MCP contract",
  async () => {
    const workspace = await createTestTempDirectory("rea-unblob-mcp-");
    const output = join(workspace, "published");
    const session = createTestBinarySession(() => {
      throw new Error("Firmware extraction must not acquire a native provider");
    });
    const server = createServer(
      { kind: "session", session },
      {
        environment: {
          ...process.env,
          REA_UNBLOB_RUNTIME_ROOT: process.env.REA_UNBLOB_ACCEPTANCE_ROOT,
          REA_UNBLOB_COMMAND: process.env.REA_UNBLOB_ACCEPTANCE_COMMAND,
        },
      },
    );
    const client = new Client({
      name: "real-unblob-extraction-acceptance",
      version: "1",
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    onTestFinished(async () => {
      await client.close();
      await server.close();
      await session.close();
    });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const response = await client.callTool({
      name: "extract_firmware",
      arguments: {
        provider_id: "unblob",
        path:
          process.env.REA_UNBLOB_ACCEPTANCE_INPUT ?? "/tmp/rea-unblob-input.gz",
        output_directory: output,
        options: { workers: 3 },
      },
    });
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    const contract = FIRMWARE_TOOL_CONTRACTS.find(
      ({ name }) => name === "extract_firmware",
    )!;
    const evidence = parseEvidence(
      contract.outputSchema.parse(response.structuredContent),
    );
    expect(evidence.provider).toMatchObject({
      id: "unblob",
      version: "26.6.4",
    });
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
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(
        file.sha256,
      );
    }
  },
);

it("executes named firmware contracts with inline Evidence and no native binary admission", async () => {
  const fixture = await firmwareFixture("dependency");
  const session = createTestBinarySession(() => {
    throw new Error("Firmware inspection must not acquire a native provider");
  });
  const server = createServer(
    { kind: "session", session },
    {
      firmwareAnalysis: fixture.provider,
    },
  );
  const client = new Client({ name: "firmware-regression", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const advertised = await client.listTools();
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  for (const contract of FIRMWARE_TOOL_CONTRACTS) {
    const tool = advertised.tools.find((tool) => tool.name === contract.name);
    if (tool === undefined)
      throw new Error(`Missing named tool: ${contract.name}`);
    expect(ajv.validateSchema(tool.inputSchema)).toBe(true);
    const validate = ajv.compile(tool.inputSchema);
    if (contract.name === "inspect_firmware_provider") {
      expect(validate({ provider_id: "unblob" })).toBe(true);
      expect(validate({ provider_id: "unblob", path: fixture.path })).toBe(
        false,
      );
    } else if (contract.name === "inspect_firmware_regions") {
      expect(
        validate({
          provider_id: "unblob",
          path: fixture.path,
          options: { workers: 2, randomness_depth: 1 },
        }),
        JSON.stringify(validate.errors),
      ).toBe(true);
      expect(
        validate({
          provider_id: "binwalk",
          path: fixture.path,
          options: { workers: 2 },
        }),
      ).toBe(false);
      // xorshift32 seed0x53444b31,64 provider/options correlation pairs.
      let seed = 0x53444b31;
      for (let index = 0; index < 64; index++) {
        seed ^= seed << 13;
        seed ^= seed >>> 17;
        seed ^= seed << 5;
        const workers = 1 + ((seed >>> 0) % 128);
        const valid = {
          provider_id: "unblob",
          path: fixture.path,
          options: {
            workers,
            skip_magic: { mode: "append", values: [`prefix-${seed >>> 0}`] },
          },
        };
        const invalid = { ...valid, provider_id: "binwalk" };
        expect(
          firmwareInputSchemas.inspect_firmware_regions.safeParse(valid)
            .success,
        ).toBe(true);
        expect(validate(valid), JSON.stringify(validate.errors)).toBe(true);
        expect(
          firmwareInputSchemas.inspect_firmware_regions.safeParse(invalid)
            .success,
        ).toBe(false);
        expect(validate(invalid)).toBe(false);
      }
    }
    expect(
      advertised.tools.find((tool) => tool.name === contract.name)?.annotations,
    ).toMatchObject(contract.annotations);
    const response = await client.callTool({
      name: contract.name,
      arguments:
        contract.name === "inspect_firmware_provider"
          ? { provider_id: "unblob" }
          : {
              path: fixture.path,
              provider_id:
                contract.name === "inspect_firmware_regions"
                  ? "binwalk"
                  : "unblob",
              ...(contract.name === "extract_firmware"
                ? { output_directory: fixture.output }
                : {}),
            },
    });
    expect(response.isError, JSON.stringify(response)).not.toBe(true);
    const result = contract.outputSchema.parse(response.structuredContent);
    const evidence = parseEvidence(result);
    expect(evidence.operation).toBe(contract.name);
    expect(evidence.raw_result).not.toBeNull();
    if (
      contract.name === "inspect_firmware_provider" ||
      contract.name === "extract_firmware"
    ) {
      const limitations = evidence.limitations.join("\n");
      expect(limitations).toMatch(/exposed when .*configured/iu);
      expect(limitations).toMatch(
        /current-head live CLI\/MCP\/systemd acceptance remains unverified/iu,
      );
      expect(limitations).toMatch(/each request performs runtime admission/iu);
      expect(limitations).toMatch(
        /caller-container execution is unavailable/iu,
      );
    }
    if (contract.name === "extract_firmware")
      expect(evidence.normalized_result).toMatchObject({
        extraction_gaps: [
          { kind: "missing-extractor-dependency", dependencies: ["sasquatch"] },
        ],
        extraction_continuations: [
          { id: expect.any(String), instruction: expect.any(String) },
        ],
      });
    if (contract.name === "inspect_firmware_provider")
      expect(evidence.subject).toBeNull();
  }
  await assertFirmwareCleanup(fixture.launches);
});

it("advertises and executes provider inventory by its exact MCP contract", async () => {
  const fixture = await firmwareFixture("inventory-missing");
  const session = createTestBinarySession(() => {
    throw new Error("Inventory has no binary subject");
  });
  const server = createServer(
    { kind: "session", session },
    { firmwareAnalysis: fixture.provider },
  );
  const client = new Client({ name: "firmware-inventory", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const advertised = (await client.listTools()).tools.find(
    (tool) => tool.name === "inspect_firmware_provider",
  );
  expect(advertised).toBeDefined();
  const response = await client.callTool({
    name: "inspect_firmware_provider",
    arguments: { provider_id: "unblob" },
  });
  expect(response.isError, JSON.stringify(response)).not.toBe(true);
  const result = FIRMWARE_TOOL_CONTRACTS.find(
    ({ name }) => name === "inspect_firmware_provider",
  )!.outputSchema.parse(response.structuredContent);
  expect(parseEvidence(result).normalized_result).toMatchObject({
    dependency_readiness: "reported_missing",
  });
  expect(fixture.launches.length).toBeGreaterThan(0);
  await assertFirmwareCleanup(fixture.launches);
});
