import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it, onTestFinished } from "vitest";
import { createServer } from "../../../src/server/createServer.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { firmwareFixture } from "../../fixtures/firmware/provider.js";

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
