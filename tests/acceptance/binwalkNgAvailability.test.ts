import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, onTestFinished, vi } from "vitest";
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

it("describes the supported Binwalk-NG analysis and extraction contracts without weakening defaults", () => {
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
    "helper manifest",
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

it("does not advertise or admit a caller-provisioned Binwalk-NG container mode", async () => {
  const contracts = new Map(
    FIRMWARE_TOOL_CONTRACTS.map((contract) => [contract.name, contract]),
  );
  const names = [
    "inspect_firmware_regions",
    "extract_firmware",
    "carve_firmware",
    "inspect_firmware_entropy",
    "inspect_firmware_provider",
  ] as const;
  const client = new Client({
    name: "binwalk-ng-no-container-mode",
    version: "1",
  });
  const session = createTestBinarySession(() => {
    throw new Error(
      "Firmware contract validation must not acquire a binary session",
    );
  });
  const provider = createFirmwareAnalysisProvider({}, async () => {
    throw new Error("Unsupported container input must not launch a provider");
  });
  const execute = vi.spyOn(provider, "execute");
  const server = createServer(
    { kind: "session", session },
    { firmwareAnalysis: provider },
  );
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const advertised = await client.listTools();
    for (const name of names) {
      const contract = contracts.get(name);
      expect(contract).toBeDefined();
      if (!contract) throw new Error(`Missing firmware contract: ${name}`);
      const tool = advertised.tools.find(
        (candidate) => candidate.name === name,
      );
      expect(tool).toBeDefined();
      expect(Object.keys(tool?.inputSchema.properties ?? {})).not.toContain(
        "container",
      );
      const properties = contract?.inputSchema.safeParse({
        ...(name === "inspect_firmware_provider"
          ? { provider_id: "binwalk-ng" }
          : {
              provider_id: "binwalk-ng",
              path: "/tmp/firmware.bin",
              ...(name === "extract_firmware" || name === "carve_firmware"
                ? { output_directory: "/tmp/firmware-output" }
                : {}),
            }),
        container: {
          kind: "podman-existing",
          container_id: "sha256:caller-selected",
        },
      });
      expect(properties.success, name).toBe(false);
    }

    const response = await client.callTool({
      name: "inspect_firmware_provider",
      arguments: {
        provider_id: "binwalk-ng",
        container: {
          kind: "podman-existing",
          container_id: "sha256:caller-selected",
        },
      },
    });
    expect(response.isError).toBe(true);
    expect(
      response.content
        .map((item) => (item.type === "text" ? item.text : ""))
        .join("\n"),
    ).toContain("Input validation error");
    expect(execute).not.toHaveBeenCalled();
  } finally {
    execute.mockRestore();
    await client.close();
    await server.close();
    await session.close();
  }
});

cliTest(
  "CLI fails closed when the selected extraction runtime cannot launch",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-ng-cli-runtime-failure-");
    const { marker, environment } = await ngRuntime(root);
    const target = join(root, "firmware.bin");
    await writeFile(target, "static firmware fixture");
    const result = await cli.run({
      arguments: [
        "extract-firmware",
        target,
        join(root, "extracted"),
        "--provider",
        "binwalk-ng",
        "--json",
      ],
      environment,
    });
    expect(result.exitCode).toBe(1);
    expect(result.json).toMatchObject({ code: "capability_unavailable" });
    await import("node:fs/promises").then(({ access }) => access(marker));
  },
);

cliTest(
  "extract-firmware help advertises the scoped extraction and recursion controls",
  async ({ cli }) => {
    const help = await cli.run({ arguments: ["extract-firmware", "--help"] });
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain("--provider");
    expect(help.stdout).toContain("--max-depth");
    expect(help.stdout).toContain("Unblob");
    expect(help.stdout).toContain("--include");
    expect(help.stdout).toContain("--recursive");
  },
);

cliTest(
  "rejects Binwalk-NG-only extraction options instead of ignoring them for Unblob",
  async ({ cli }) => {
    const root = await createTestTempDirectory("rea-ng-cli-option-owner-");
    const target = join(root, "firmware.bin");
    await writeFile(target, "static firmware fixture");
    const result = await cli.run({
      arguments: [
        "extract-firmware",
        target,
        join(root, "extracted"),
        "--include",
        "gzip",
        "--json",
      ],
    });
    expect(result.exitCode).toBe(1);
    expect(result.stdout + result.stderr).toContain(
      "require --provider binwalk-ng",
    );
  },
);

it("MCP fails closed when the selected extraction runtime cannot launch", async () => {
  const root = await createTestTempDirectory("rea-ng-mcp-runtime-failure-");
  const { environment } = await ngRuntime(root);
  const session = createTestBinarySession(() => {
    throw new Error(
      "Firmware extraction must not acquire a binary-analysis session",
    );
  });
  let launches = 0;
  const provider = createFirmwareAnalysisProvider(environment, async () => {
    launches++;
    throw new Error("Synthetic runtime launch marker expected");
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
  const target = join(root, "firmware.bin");
  await writeFile(target, "static firmware fixture");
  const response = await client.callTool({
    name: "extract_firmware",
    arguments: {
      path: target,
      provider_id: "binwalk-ng",
      output_directory: join(root, "extracted"),
    },
  });
  expect(parseMcpToolError(response).error).toMatchObject({
    code: "capability_unavailable",
  });
  expect(launches).toBe(1);
});
