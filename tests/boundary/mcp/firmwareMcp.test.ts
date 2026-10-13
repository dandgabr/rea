import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it as test, onTestFinished } from "vitest";
import { FIRMWARE_TOOL_CONTRACTS } from "../../../src/contracts/firmware/firmwareToolContracts.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
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
  for (const contract of FIRMWARE_TOOL_CONTRACTS.filter(
    (contract) =>
      contract.name === "inspect_firmware_regions" ||
      contract.name === "extract_firmware",
  )) {
    expect(
      advertised.tools.find((tool) => tool.name === contract.name)?.annotations,
    ).toMatchObject(contract.annotations);
    const response = await client.callTool({
      name: contract.name,
      arguments: {
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

it("refuses unpaired UTF16 in all ng signature contracts before provider admission and preserves valid Unicode controls", async () => {
  const { vi } = await import("vitest");
  const { createFirmwareAnalysisProvider } =
    await import("../../../src/composition/firmware.js");
  let launches = 0;
  const provider = createFirmwareAnalysisProvider({}, async () => {
    launches++;
    throw Error("Unexpected native launch during boundary refusal");
  });
  const admitted = vi.spyOn(provider, "execute");
  const session = createTestBinarySession(() => {
    throw Error("Unexpected native binary session");
  });
  const server = createServer(
    { kind: "session", session },
    { firmwareAnalysis: provider },
  );
  const client = new Client({ name: "firmware-utf8-refusal", version: "1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(b);
    await client.connect(a);
    for (const operation of [
      "inspect_firmware_regions",
      "extract_firmware",
      "carve_firmware",
    ] as const) {
      for (const field of ["include", "exclude"]) {
        for (const name of ["\ud800", "\udfff"]) {
          const response = await client.callTool({
            name: operation,
            arguments: {
              path: "/tmp/fw",
              provider_id: "binwalk-ng",
              ...(operation === "inspect_firmware_regions"
                ? {}
                : { output_directory: "/tmp/new" }),
              options: { [field]: [name] },
            },
          });
          expect(response.isError).toBe(true);
          const refusal = response.content.find(
            (item) => item.type === "text",
          )?.text;
          expect(refusal).toContain("Input validation error");
          expect(refusal).toContain(
            "Signature names must be representable as UTF-8",
          );
        }
      }
    }
    expect(admitted).not.toHaveBeenCalled();
    expect(launches).toBe(0);
    const names = ["😀", "\ufffd", "two words", "--help"];
    const control = await client.callTool({
      name: "inspect_firmware_regions",
      arguments: {
        path: "/tmp/fw",
        provider_id: "binwalk-ng",
        options: { exclude: names },
      },
    });
    expect(control.isError).toBe(true);
    expect(admitted).toHaveBeenCalledOnce();
    expect(admitted.mock.calls[0]?.[0]).toMatchObject({
      input: { options: { exclude: names } },
    });
    expect(launches).toBe(0);
  } finally {
    admitted.mockRestore();
    await client.close();
    await server.close();
    await session.close();
  }
});
