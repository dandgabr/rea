import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it as test, onTestFinished } from "vitest";
import { FIRMWARE_TOOL_CONTRACTS } from "../../../src/contracts/firmware/firmwareToolContracts.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { firmwareInputSchemas } from "../../../src/domain/firmware/firmwareAnalysis.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import {
  firmwareFixture,
  assertFirmwareCleanup,
} from "../../fixtures/firmware/provider.js";

const it = test.skipIf(process.platform !== "linux");

it("executes named firmware contracts with inline Evidence and no native binary admission", async () => {
  const fixture = await firmwareFixture();
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
  expect(parseEvidence(response.structuredContent)).toMatchObject({
    subject: null,
    operation: "inspect_firmware_provider",
    normalized_result: { dependency_readiness: "reported_missing" },
  });
  await assertFirmwareCleanup(fixture.launches);
});
