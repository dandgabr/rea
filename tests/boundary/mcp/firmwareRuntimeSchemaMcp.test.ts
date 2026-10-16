import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it, onTestFinished } from "vitest";
import { createServer } from "../../../src/server/createServer.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import {
  expandToolAvailability,
  sessionProvider,
} from "../../../src/contracts/toolOutputSchemaPrimitives.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { firmwareFixture } from "../../fixtures/firmware/provider.js";
import { z } from "zod";

it("advertises correlated Unblob container selections through the actual SDK without native fallback", async () => {
  const fixture = await firmwareFixture();
  const session = createTestBinarySession(() => {
    throw new Error("Binary provider must not start");
  });
  const server = createServer(
    { kind: "session", session },
    { firmwareAnalysis: fixture.provider },
  );
  const client = new Client({
    name: "firmware-container-contract",
    version: "1",
  });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const tools = (await client.listTools()).tools;
  for (const name of [
    "inspect_firmware_provider",
    "inspect_firmware_regions",
    "extract_firmware",
  ]) {
    const description = tools.find((tool) => tool.name === name)?.description;
    expect(description).toContain("exposed when");
    expect(description).toContain("configured");
    expect(description).toContain(
      "current-head live CLI/MCP/systemd acceptance remains unverified.",
    );
    expect(description).toContain("Each request performs runtime admission");
  }
  const runtime = {
    kind: "container",
    command: "/usr/bin/podman",
    image: `sha256:${"a".repeat(64)}`,
    existing_store_profile: `${fixture.root}/absent-profile.json`,
  };
  for (const name of [
    "inspect_firmware_regions",
    "extract_firmware",
    "inspect_firmware_provider",
  ] as const) {
    const advertised = tools.find((tool) => tool.name === name);
    if (advertised === undefined)
      throw new Error(`Missing firmware schema: ${name}`);
    const ajv = new Ajv2020({ strict: false, validateFormats: false });
    expect(ajv.validateSchema(advertised.inputSchema)).toBe(true);
    const validate = ajv.compile(advertised.inputSchema);
    const input = {
      provider_id: "unblob",
      ...(name === "inspect_firmware_provider" ? {} : { path: fixture.path }),
      ...(name === "extract_firmware"
        ? { output_directory: fixture.output }
        : {}),
      runtime,
    };
    for (const arguments_ of [
      input,
      { ...input, provider_id: "binwalk" },
      { ...input, runtime: { ...runtime, image: "latest" } },
      { ...input, runtime: { ...runtime, args: ["--privileged"] } },
      {
        ...input,
        runtime: { ...runtime, existing_store_profile: "profile.json" },
      },
    ])
      expect(validate(arguments_), JSON.stringify(validate.errors)).toBe(
        toolContract(name).inputSchema.safeParse(arguments_).success,
      );
    const response = await client.callTool(
      { name, arguments: input },
      { toolDefinition: advertised },
    );
    expect(response.isError).toBe(true);
  }
  expect(fixture.launches).toEqual([]);
  await client.ping();
});

it("reports configured native firmware commands as available without verifying a runtime", async () => {
  const session = createTestBinarySession(() => {
    throw new Error("Availability inspection must not start a provider");
  });
  const server = createServer(
    { kind: "session", session },
    {
      environment: {
        ...process.env,
        REA_BINWALK_COMMAND: "/usr/bin/true",
        REA_UNBLOB_COMMAND: "/usr/bin/true",
        REA_UNBLOB_RUNTIME_ROOT: "/usr",
      },
    },
  );
  const client = new Client({ name: "firmware-availability", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const response = await client.callTool({
    name: "binary_session",
    arguments: {},
  });
  const status = z
    .object({ result: sessionProvider })
    .parse(response.structuredContent).result;
  const availability = expandToolAvailability(status.tool_availability);
  expect(availability).toContainEqual(
    expect.objectContaining({
      name: "inspect_firmware_regions",
      available: true,
    }),
  );
  expect(availability).toContainEqual(
    expect.objectContaining({ name: "extract_firmware", available: true }),
  );
});
