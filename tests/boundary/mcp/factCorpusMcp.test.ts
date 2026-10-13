import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { AnySchema } from "ajv";
import { Ajv2020 } from "ajv/dist/2020.js";
import { createServer as httpServer } from "node:http";
import { once } from "node:events";
import { expect, it } from "vitest";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/toolContracts.js";
import { firmwareCorpusInputs } from "../../../src/domain/corpus/firmwareCorpus.js";
import { createCli } from "../../../src/cli.js";
import { createCliInventory } from "../../../scripts/lib/catalog-cli.mjs";
import { parseEvidence } from "../../../src/domain/evidence.js";

it("advertises all named corpus workflows with SDK-valid schemas and dedicated CLI commands", async () => {
  const session = createTestBinarySession(() => {
    throw Error("Corpus tools must not acquire a binary engine");
  });
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "fact-public-contract", version: "1" });
  try {
    const [c, s] = InMemoryTransport.createLinkedPair();
    await server.connect(s);
    await client.connect(c);
    const advertised = await client.listTools(),
      cli = createCliInventory(createCli({}));
    const ajv = new Ajv2020({
      strict: false,
      validateFormats: false,
      addUsedSchema: false,
    });
    for (const name of Object.keys(firmwareCorpusInputs)) {
      const contract = TOOL_CONTRACTS.find(
          (contract) => contract.name === name,
        ),
        tool = advertised.tools.find((tool) => tool.name === name);
      expect(contract, name).toBeDefined();
      expect(tool, name).toBeDefined();
      if (!contract || !tool) throw Error(`Missing ${name}`);
      expect(cli.primary).toContain(name.replaceAll("_", "-"));
      expect(tool.annotations).toMatchObject(contract.annotations);
      for (const schema of [tool.inputSchema, tool.outputSchema]) {
        expect(ajv.validateSchema(schema as AnySchema)).toBe(true);
        ajv.compile(schema as AnySchema);
        ajv.removeSchema();
      }
      for (const example of contract.examples) {
        expect(
          contract.inputSchema.safeParse(example.input).success,
          example.title,
        ).toBe(true);
        expect(ajv.compile(tool.inputSchema)(example.input), name).toBe(true);
        ajv.removeSchema();
        expect(
          ajv.compile(tool.inputSchema)({
            ...example.input,
            __unexpected__: true,
          }),
          name,
        ).toBe(false);
        ajv.removeSchema();
      }
    }
    expect(Object.keys(firmwareCorpusInputs)).toHaveLength(18);
    expect(
      advertised.tools.find((tool) => tool.name === "delete_corpus_firmware")
        ?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
    });
    expect(
      advertised.tools.find((tool) => tool.name === "collect_corpus_yara")
        ?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
    });
    expect(
      advertised.tools.find((tool) => tool.name === "inspect_corpus_gaps")
        ?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: true,
    });
    expect(
      advertised.tools.find((tool) => tool.name === "export_corpus_firmware")
        ?.annotations,
    ).toMatchObject({ readOnlyHint: false, idempotentHint: false });
  } finally {
    await client.close();
    await server.close();
    await session.close();
  }
});

it("delivers null-subject corpus Evidence and retains consuming observations in one MCP session", async () => {
  let statusCalls = 0,
    yaraCalls = 0;
  const authorization = "private-FACT-key",
    uid = "a".repeat(64) + "_3";
  const api = httpServer((req, res) => {
    expect(req.headers.authorization).toBe(authorization);
    res.setHeader("content-type", "application/json");
    if (req.url?.startsWith("/rest/status")) {
      statusCalls++;
      res.end(
        JSON.stringify({
          status: 0,
          timestamp: 42,
          request_resource: "/rest/status",
          system_status: { frontend: {}, database: {}, backend: {} },
          plugins: {
            "custom-plugin": {
              description: "firmware-password-like-finding",
              version: "1",
            },
          },
        }),
      );
    } else {
      yaraCalls++;
      res.end(
        JSON.stringify({
          status: 0,
          timestamp: 42,
          request_resource: "/rest/binary_search",
          binary_search_results: { rule: [uid] },
        }),
      );
    }
  });
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  const address = api.address();
  if (!address || typeof address === "string") throw Error("No address");
  const connection = {
    endpoint: `http://127.0.0.1:${address.port}`,
    profile: "source-54aed90b",
    authorization,
  };
  const session = createTestBinarySession(() => {
    throw Error("Unexpected binary admission");
  });
  const server = createServer({ kind: "session", session }),
    client = new Client({ name: "fact-public-evidence", version: "1" });
  try {
    const [c, s] = InMemoryTransport.createLinkedPair();
    await server.connect(s);
    await client.connect(c);
    const status = await client.callTool({
      name: "inspect_firmware_corpus",
      arguments: { connection },
    });
    expect(status.isError, JSON.stringify(status)).not.toBe(true);
    const evidence = parseEvidence(status.structuredContent);
    expect(evidence).toMatchObject({
      subject: null,
      authority: "external-service",
      provider: { id: "fact-core", version: null },
      normalized_result: { state: "completed" },
    });
    expect(JSON.stringify(status)).not.toContain(authorization);
    expect(JSON.stringify(status)).toContain("firmware-password-like-finding");
    const first = await client.callTool({
      name: "collect_corpus_yara",
      arguments: { connection, search_id: "one-result" },
    });
    const again = await client.callTool({
      name: "collect_corpus_yara",
      arguments: {
        connection: { ...connection, endpoint: connection.endpoint + "/" },
        search_id: "one-result",
      },
    });
    expect(parseEvidence(first.structuredContent).evidence_id).toBe(
      parseEvidence(again.structuredContent).evidence_id,
    );
    expect({ statusCalls, yaraCalls }).toEqual({
      statusCalls: 1,
      yaraCalls: 1,
    });
  } finally {
    await client.close();
    await server.close();
    await session.close();
    api.closeAllConnections();
    await new Promise<void>((resolve) => api.close(() => resolve()));
  }
});

it("binds every MCP handler to its named workflow and preserves selected inputs", async () => {
  const seen: { operation: string; input: unknown }[] = [];
  const session = createTestBinarySession(() => {
    throw Error("binary admission");
  });
  const server = createServer(
    { kind: "session", session },
    {
      firmwareCorpus: {
        async execute(operation, input) {
          seen.push({ operation, input });
          return {
            ok: true,
            value: {
              provider: {
                id: "fixture-corpus",
                name: "Boundary fixture",
                version: null,
              },
              result: {
                state: "completed",
                endpoint: null,
                profile:
                  "connection" in input
                    ? input.connection.profile
                    : input.profile,
                http_status: null,
                observed_at: "fixture",
                raw_sha256: null,
                coverage: "producer-response",
                data: { operation },
                diagnostics: [],
              },
              rawResult: null,
              subject: null,
              limitations: [],
              locations: [],
            },
          };
        },
      },
    },
  );
  const client = new Client({ name: "fact-named-bindings", version: "1" });
  try {
    const [c, s] = InMemoryTransport.createLinkedPair();
    await server.connect(s);
    await client.connect(c);
    for (const name of Object.keys(firmwareCorpusInputs).reverse()) {
      const contract = TOOL_CONTRACTS.find((item) => item.name === name);
      if (!contract) throw Error(name);
      const input = contract.examples[0]!.input;
      const result = await client.callTool({ name, arguments: input });
      expect(result.isError, JSON.stringify(result)).not.toBe(true);
      const evidence = parseEvidence(result.structuredContent);
      expect(evidence.operation).toBe(name);
      expect(seen.at(-1)).toEqual({
        operation: name,
        input: contract.inputSchema.parse(input),
      });
      expect(evidence.normalized_result).toMatchObject({
        data: { operation: name },
      });
    }
    const before = seen.length;
    // Deterministic malformed-origin corpus; semantic admission must precede provider delivery.
    const origins = [
      "http://localhost:5000",
      "http://127.0.0.2",
      "http://127.0.0.1/path",
      "http://user:pass@127.0.0.1",
      "file:///tmp/fact",
      "http://127.0.0.1?token=x",
      "http://127.0.0.1#x",
      "http://[::2]",
    ];
    let seed = 0xfac70006;
    for (let index = 0; index < 64; index++) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      const suffix = seed.toString(16);
      const endpoint =
        origins[index % origins.length] +
        (index % 2 ? `/${suffix}` : `?case=${suffix}`);
      const result = await client.callTool({
        name: "inspect_firmware_corpus",
        arguments: {
          connection: {
            endpoint,
            profile: "source-54aed90b",
          },
        },
      });
      expect(result.isError).toBe(true);
      expect(seen).toHaveLength(before);
    }
  } finally {
    await client.close();
    await server.close();
    await session.close();
  }
});
