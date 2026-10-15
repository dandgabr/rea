import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, onTestFinished } from "vitest";
import { FIRMWARE_TOOL_CONTRACTS } from "../../src/contracts/firmware/firmwareToolContracts.js";
import { createFirmwareAnalysisProvider } from "../../src/composition/firmware.js";
import { createServer } from "../../src/server/createServer.js";
import { createTestBinarySession } from "../fixtures/binarySession.js";
import { parseMcpToolError } from "../fixtures/mcpToolError.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const ngRuntime = async (root: string) => {
  const marker = join(root, "upstream-started");
  const bubblewrap = join(root, "bubblewrap-sentinel");
  await writeFile(
    bubblewrap,
    `#!/bin/sh\nprintf started > '${marker}'\nexit 97\n`,
  );
  await chmod(bubblewrap, 0o700);
  const manifest = join(root, "ng-runtime.json");
  await writeFile(
    manifest,
    JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts: [] }),
  );
  return {
    marker,
    environment: {
      REA_LOG_LEVEL: "silent",
      REA_BINWALK_NG_COMMAND: "/bin/true",
      REA_FIRMWARE_BWRAP_COMMAND: bubblewrap,
      REA_BINWALK_NG_RUNTIME_MANIFEST: manifest,
    },
  };
};

it("describes the supported native Binwalk-NG subset and deferred extraction without weakening defaults", () => {
  const contracts = new Map(
    FIRMWARE_TOOL_CONTRACTS.map((contract) => [contract.name, contract]),
  );
  expect(contracts.get("inspect_firmware_regions")?.description).toContain(
    "Binwalk-NG 4.0.0",
  );
  expect(contracts.get("inspect_firmware_regions")?.description).toContain(
    "systemd-run",
  );
  expect(contracts.get("inspect_firmware_regions")?.description).toContain(
    "default Binwalk 3.1.x",
  );
  expect(contracts.get("extract_firmware")?.description).toContain(
    "Binwalk-NG extraction is unavailable",
  );
  expect(contracts.get("extract_firmware")?.description).toContain(
    "default Unblob 26.6.x",
  );
  for (const name of [
    "carve_firmware",
    "inspect_firmware_entropy",
    "inspect_firmware_provider",
  ] as const) {
    const contract = contracts.get(name);
    expect(contract?.description).toContain("Binwalk-NG 4.0.0");
  }
  expect(contracts.get("carve_firmware")?.description).toContain(
    "internal carving",
  );
});

cliTest(
  "CLI refuses unsupported NG extraction before target reads or upstream launch",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-ng-cli-unavailable-");
    const { marker, environment } = await ngRuntime(root);
    const target = join(root, "missing-firmware.bin");
    for (const args of [
      [
        "extract-firmware",
        target,
        join(root, "extracted"),
        "--provider",
        "binwalk-ng",
        "--json",
      ],
    ]) {
      const result = await cli.run({ arguments: args, environment });
      expect(result.exitCode).toBe(1);
      expect(result.json).toMatchObject({
        code: "capability_unavailable",
        message: expect.stringContaining("external helpers"),
      });
    }
    await expect(
      import("node:fs/promises").then(({ access }) => access(marker)),
    ).rejects.toMatchObject({ code: "ENOENT" });
  },
);

cliTest(
  "extract-firmware help only advertises options supported by the available extraction provider",
  async ({ cli }) => {
    const help = await cli.run({ arguments: ["extract-firmware", "--help"] });
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain("--provider");
    expect(help.stdout).toContain("--max-depth");
    expect(help.stdout).toContain("Unblob only");
    for (const unsupported of [
      "--include",
      "--exclude",
      "--search-all",
      "--carve",
      "--recursive",
      "--workers",
    ])
      expect(help.stdout).not.toContain(unsupported);
  },
);

it("MCP refuses unsupported NG extraction before target reads or upstream launch", async () => {
  const root = await createTestTempDirectory("rea-ng-mcp-unavailable-");
  const { marker, environment } = await ngRuntime(root);
  const session = createTestBinarySession(() => {
    throw new Error("Binwalk-NG refusal must not acquire a binary session");
  });
  let launches = 0;
  const provider = createFirmwareAnalysisProvider(environment, async () => {
    launches++;
    throw new Error("Binwalk-NG refusal must not launch an upstream process");
  });
  const server = createServer(
    { kind: "session", session },
    { firmwareAnalysis: provider },
  );
  const client = new Client({ name: "binwalk-ng-unavailable", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  for (const request of [
    {
      name: "extract_firmware",
      arguments: {
        path: join(root, "missing-firmware.bin"),
        provider_id: "binwalk-ng",
        output_directory: join(root, "extracted"),
      },
    },
  ]) {
    const response = await client.callTool(request);
    expect(parseMcpToolError(response).error).toMatchObject({
      code: "capability_unavailable",
      message: expect.stringContaining("external helpers"),
    });
  }
  expect(launches).toBe(0);
  await expect(
    import("node:fs/promises").then(({ access }) => access(marker)),
  ).rejects.toMatchObject({ code: "ENOENT" });
});
