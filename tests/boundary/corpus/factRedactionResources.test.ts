import { FirmwareCorpusService } from "../../../src/application/corpus/FirmwareCorpusService.js";
import { once } from "node:events";
import { createServer } from "node:http";
import { expect, it } from "vitest";
import { cliTest } from "../../support/cli/cliFixture.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer as createMcpServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

cliTest(
  "completes small percent near-matches through the public CLI under an external watchdog",
  async ({ cli }) => {
    const authorization = "a".repeat(30) + "b";
    const near = "%61".repeat(30) + "x";
    const query = { near, overlapping: "b" + near, ordinary: "漢字😀" };
    let calls = 0;
    const server = createServer((req, res) => {
      calls++;
      expect(req.headers.authorization).toBe(authorization);
      expect(
        JSON.parse(
          new URL(req.url!, "http://local").searchParams.get("query")!,
        ),
      ).toEqual(query);
      res.end(
        JSON.stringify({
          status: 0,
          timestamp: 42,
          request_resource: "/rest/firmware",
          uids: [],
          request: {
            query,
            offset: 0,
            limit: 0,
            recursive: false,
            inverted: false,
          },
          finding: query,
        }),
      );
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") throw Error("No address");
    const session = createTestBinarySession(() => {
      throw Error("Unexpected binary admission");
    });
    const mcpServer = createMcpServer({ kind: "session", session });
    const client = new Client({ name: "fact-bounded-redaction", version: "1" });
    const input = {
      connection: {
        endpoint: `http://127.0.0.1:${address.port}`,
        profile: "source-54aed90b",
        authorization,
      },
      kind: "firmware",
      query,
    };
    try {
      const result = await cli.run({
        arguments: ["search-corpus-objects", JSON.stringify(input), "--json"],
        timeoutMs: 2500,
      });
      expect(result.exitCode, result.stdout + result.stderr).toBe(0);
      expect(parseEvidence(result.json).normalized_result).toMatchObject({
        state: "completed",
        data: { finding: query },
      });
      expect(calls).toBe(1);
      const [c, s] = InMemoryTransport.createLinkedPair();
      await mcpServer.connect(s);
      await client.connect(c);
      const mcp = await client.callTool({
        name: "search_corpus_objects",
        arguments: input,
      });
      expect(mcp.isError).not.toBe(true);
      expect(
        parseEvidence(mcp.structuredContent).normalized_result,
      ).toMatchObject({ state: "completed", data: { finding: query } });
      expect(calls).toBe(2);
      const refused = await client.callTool({
        name: "search_corpus_objects",
        arguments: {
          ...input,
          connection: {
            ...input.connection,
            authorization: "a".repeat(300) + "b",
          },
          query: { near: "%61".repeat(9999) + "b" },
        },
      });
      expect(refused.isError).toBe(true);
      expect(calls).toBe(2);
    } finally {
      await client.close();
      await mcpServer.close();
      await session.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);

it("refuses public parameter work with a tagged secret-safe result before provider admission", async () => {
  const authorization = "a".repeat(300) + "b";
  const near = "%61".repeat(9999) + "b";
  let calls = 0;
  const service = new FirmwareCorpusService({
    async execute() {
      calls++;
      throw Error("Privacy admission was bypassed");
    },
  });
  const input = {
    connection: {
      endpoint: "http://127.0.0.1:1",
      profile: "source-54aed90b",
      authorization,
    },
    kind: "firmware",
    query: { near },
  };
  const result = await service.execute("search_corpus_objects", input);
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisResourceConstraintError", resource: "cpu" },
  });
  expect(calls).toBe(0);
  expect(input.query.near).toBe(near);
  expect(input.connection.authorization).toBe(authorization);
  expect(JSON.stringify(result)).not.toContain(authorization);
  expect(JSON.stringify(result)).not.toContain(near);
});
