import { FIRMWARE_CORPUS_TOOL_CONTRACTS } from "../../../src/contracts/corpus/firmwareCorpusToolContracts.js";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { once } from "node:events";
import { createServer as httpServer, validateHeaderValue } from "node:http";
import { expect, it } from "vitest";
import { FirmwareCorpusService } from "../../../src/application/corpus/FirmwareCorpusService.js";
import { corpusConnectionSchema } from "../../../src/domain/corpus/firmwareCorpus.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { cliTest } from "../../support/cli/cliFixture.js";

const invalid = [
  "\ud800",
  "\udfff",
  "a\ud800b",
  "\udfff\ud800",
  "😀",
  "漢",
  "Ā",
  "\0",
  "a\x01b",
  "a\x1fb",
  "a\x7fb",
  " token",
  "token ",
  "\ttoken",
  "token\t",
  " \t ",
  "Token\n",
  "Token\r",
  "Token\r\n",
];
const valid = [
  "Bearer abc+/=",
  "Token é",
  "Token \x80",
  "Token \xff",
  "Token a\tb",
  'Token "quoted"\\key',
];
const input = (authorization: string, endpoint = "http://127.0.0.1:1") => ({
  connection: { endpoint, profile: "source-54aed90b", authorization },
});

it("returns tagged invalid input before any provider call and matches measured HTTP byte/normalization admission", async () => {
  let calls = 0;
  const service = new FirmwareCorpusService({
    async execute() {
      calls++;
      throw Error("Invalid input reached provider");
    },
  });
  const generated = [...invalid];
  let seed = 0xfac70302;
  for (let index = 0; index < 128; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const code =
      index % 2 === 0 ? 0xd800 + (seed % 0x800) : 0x100 + (seed % 0xd700);
    generated.push(`Token ${String.fromCharCode(code)}`);
  }
  for (const authorization of generated) {
    const result = await service.execute(
      "inspect_firmware_corpus",
      input(authorization),
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
    expect(
      corpusConnectionSchema.safeParse(input(authorization).connection).success,
    ).toBe(false);
  }
  for (const authorization of valid) {
    expect(() =>
      validateHeaderValue("Authorization", authorization),
    ).not.toThrow();
    expect(
      new Headers({ Authorization: authorization }).get("Authorization"),
    ).toBe(authorization);
    expect(
      corpusConnectionSchema.safeParse(input(authorization).connection).success,
    ).toBe(true);
  }
  expect(calls).toBe(0);
});

cliTest(
  "advertises and enforces HTTP-representable authorization while preserving ordinary Unicode findings",
  async ({ cli }) => {
    let calls = 0;
    const unicode = "ordinary漢字😀\ud800 /firmware/漢字😀.bin";
    let selected = "";
    const api = httpServer((req, res) => {
      calls++;
      expect(req.headers.authorization).toBe(selected);
      res.end(
        JSON.stringify({
          status: 0,
          timestamp: 42,
          request_resource: "/rest/status",
          system_status: { frontend: {}, database: {}, backend: {} },
          plugins: { unicode: { description: unicode, version: "1" } },
        }),
      );
    });
    api.listen(0, "127.0.0.1");
    await once(api, "listening");
    const address = api.address();
    if (!address || typeof address === "string") throw Error("No address");
    const endpoint = `http://127.0.0.1:${address.port}`;
    const session = createTestBinarySession(() => {
      throw Error("Unexpected binary engine");
    });
    const server = createServer({ kind: "session", session });
    const client = new Client({ name: "fact-authorization", version: "1" });
    try {
      const [c, s] = InMemoryTransport.createLinkedPair();
      await server.connect(s);
      await client.connect(c);
      const advertised = await client.listTools();
      const ajv = new Ajv2020({
        strict: false,
        validateFormats: false,
        addUsedSchema: false,
      });
      let schemas = 0;
      for (const tool of advertised.tools.filter(
        (t) => t.inputSchema.properties?.connection,
      )) {
        if (
          !tool.name.includes("corpus") &&
          tool.name !== "inspect_firmware_corpus"
        )
          continue;
        const example = FIRMWARE_CORPUS_TOOL_CONTRACTS.find(
          (contract) => contract.name === tool.name,
        )!.examples[0]!.input;
        const validate = ajv.compile(tool.inputSchema);
        for (const authorization of invalid)
          expect(
            validate({
              ...example,
              connection: input(authorization, endpoint).connection,
            }),
            tool.name,
          ).toBe(false);
        for (const authorization of valid)
          expect(
            validate({
              ...example,
              connection: input(authorization, endpoint).connection,
            }),
            tool.name,
          ).toBe(true);
        schemas++;
        ajv.removeSchema();
      }
      expect(schemas).toBe(10);
      for (const authorization of invalid) {
        const result = await cli.run({
          arguments: [
            "inspect-firmware-corpus",
            JSON.stringify(input(authorization, endpoint)),
            "--json",
          ],
        });
        expect(result.exitCode, result.stdout + result.stderr).toBe(1);
        expect(result.json).toMatchObject({
          code: "invalid_request",
          category: "invalid_input",
        });
        expect(result.stdout + result.stderr).not.toContain("URI malformed");
        expect(result.json).not.toHaveProperty("connection");
        const mcp = await client.callTool({
          name: "inspect_firmware_corpus",
          arguments: input(authorization, endpoint),
        });
        expect(mcp.isError).toBe(true);
      }
      expect(calls).toBe(0);
      for (const authorization of valid) {
        selected = authorization;
        const result = await cli.run({
          arguments: [
            "inspect-firmware-corpus",
            JSON.stringify(input(authorization, endpoint)),
            "--json",
          ],
        });
        expect(result.exitCode, result.stdout + result.stderr).toBe(0);
        const evidence = parseEvidence(result.json);
        expect(evidence.normalized_result).toMatchObject({
          state: "completed",
          data: { plugins: { unicode: { description: unicode } } },
        });
        expect(JSON.stringify(result.json)).not.toContain(
          JSON.stringify(authorization).slice(1, -1),
        );
        const mcp = await client.callTool({
          name: "inspect_firmware_corpus",
          arguments: input(authorization, endpoint),
        });
        expect(mcp.isError).not.toBe(true);
        expect(
          parseEvidence(mcp.structuredContent).normalized_result,
        ).toMatchObject({
          state: "completed",
          data: { plugins: { unicode: { description: unicode } } },
        });
      }
      expect(calls).toBe(valid.length * 2);
    } finally {
      await client.close();
      await server.close();
      await session.close();
      api.closeAllConnections();
      await new Promise<void>((resolve) => api.close(() => resolve()));
    }
  },
  60_000,
);
