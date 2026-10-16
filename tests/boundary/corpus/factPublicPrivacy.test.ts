import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { once } from "node:events";
import { createServer as httpServer } from "node:http";
import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { cliTest } from "../../support/cli/cliFixture.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createServer } from "../../../src/server/createServer.js";
import { parseEvidence } from "../../../src/domain/evidence.js";

cliTest(
  "classifies malformed JSON documents before filename diagnostics, retaining explicit file failures",
  async ({ cli }) => {
    const secret = "synthetic-review-key+a/b";
    let seed = 0xfac70301;
    for (let index = 0; index < 16; index++) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      const input = `${index % 2 ? " [" : "{"}"connection":{"authorization":"${secret}","endpoint":"http://127.0.0.1/${seed.toString(16)}.json`;
      const result = await cli.run({
        arguments: ["inspect-firmware-corpus", input, "--json"],
      });
      expect(result.exitCode).toBe(1);
      expect(result.json).toMatchObject({
        code: "invalid_request",
        details: { issues: [{ reason: "invalid_format", expected: "JSON" }] },
      });
      expect(result.json).not.toHaveProperty("input_path");
      expect(result.stdout + result.stderr).not.toContain(secret);
    }
    const root = await createTestTempDirectory("rea-fact-privacy-path-");
    const filename = '{"connection".json';
    const selected = join(root, filename);
    await writeFile(selected, "{}");
    const ambiguous = await cli.run({
      arguments: ["inspect-firmware-corpus", filename, "--json"],
      cwd: root,
    });
    expect(ambiguous.json).toMatchObject({
      details: { issues: [{ reason: "invalid_format", expected: "JSON" }] },
    });
    expect(ambiguous.json).not.toHaveProperty("input_path");
    const explicit = await cli.run({
      arguments: ["inspect-firmware-corpus", `./${filename}`, "--json"],
      cwd: root,
    });
    expect(explicit.json).toMatchObject({ code: "invalid_request" });
    expect(explicit.json).not.toHaveProperty("input_path");
    const invalid = await cli.run({
      arguments: ["inspect-firmware-corpus", selected, "--json"],
    });
    expect(invalid.exitCode).toBe(1);
    expect(invalid.json).not.toHaveProperty("input_path"); // File read succeeded; contract rejected its contents.
    const missing = join(root, "[missing].json");
    const missingResult = await cli.run({
      arguments: ["inspect-firmware-corpus", missing, "--json"],
    });
    expect(missingResult.json).toMatchObject({
      input_path: missing,
      input_reason: "read-failed",
    });
    expect(missingResult.stdout).toContain("ENOENT");
    if (process.platform !== "win32" && process.getuid?.() !== 0) {
      await chmod(selected, 0o000);
      try {
        const denied = await cli.run({
          arguments: ["inspect-firmware-corpus", selected, "--json"],
        });
        expect(denied.json).toMatchObject({
          code: "access_denied",
          input_path: selected,
        });
      } finally {
        await chmod(selected, 0o600);
      }
    }
  },
);

cliTest(
  "redacts repeated actual authentication in CLI and retained MCP Evidence while delivering original queries",
  async ({ cli }) => {
    const secret = 'synthetic-review-key+a/bé"';
    const variants = [
      secret,
      encodeURIComponent(secret),
      Buffer.from(secret).toString("base64"),
      Buffer.from(secret).toString("hex"),
      Buffer.from(secret).toString("hex").toUpperCase(),
      JSON.stringify(secret).slice(1, -1),
      Buffer.from(secret, "latin1").toString("base64"),
      Buffer.from(secret, "latin1").toString("hex"),
      Buffer.from(secret, "latin1").toString("hex").toUpperCase(),
      [...Buffer.from(secret, "latin1")]
        .map((byte) => `%${byte.toString(16).padStart(2, "0")}`)
        .join(""),
      secret.replace("é", "%e9"),
      [...Buffer.from(secret)]
        .map((byte) => `%${byte.toString(16).padStart(2, "0")}`)
        .join(""),
    ];
    const query = {
      nested: {
        values: variants,
        keys: Object.fromEntries(
          variants.map((value, index) => [value, index]),
        ),
        password: "firmware-password-like-finding",
        path: "/firmware/passwords/config.json",
        "[REDACTED]": "collision preserved",
      },
    };
    let calls = 0;
    const api = httpServer((req, res) => {
      res.setHeader("content-type", "application/json");
      calls++;
      expect(req.headers.authorization).toBe(secret);
      const url = new URL(req.url!, "http://127.0.0.1");
      expect(JSON.parse(url.searchParams.get("query")!)).toEqual(query);
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
          echoed: query,
        }),
      );
    });
    api.listen(0, "127.0.0.1");
    await once(api, "listening");
    const address = api.address();
    if (!address || typeof address === "string") throw Error("No address");
    const input = {
      connection: {
        endpoint: `http://127.0.0.1:${address.port}`,
        profile: "source-54aed90b",
        authorization: secret,
      },
      kind: "firmware",
      query,
    };
    const session = createTestBinarySession(() => {
      throw Error("Unexpected binary admission");
    });
    const server = createServer({ kind: "session", session });
    const client = new Client({ name: "fact-public-privacy", version: "1" });
    const assertPrivate = (value: unknown) => {
      const serialized = JSON.stringify(value);
      for (const variant of variants)
        expect(serialized).not.toContain(JSON.stringify(variant).slice(1, -1));
      for (const control of [
        "firmware-password-like-finding",
        "/firmware/passwords/config.json",
        "collision preserved",
      ])
        expect(serialized).toContain(control);
    };
    try {
      const result = await cli.run({
        arguments: ["search-corpus-objects", JSON.stringify(input), "--json"],
      });
      expect(result.exitCode, result.stdout + result.stderr).toBe(0);
      expect(parseEvidence(result.json).normalized_result).toMatchObject({
        state: "completed",
      });
      assertPrivate(result.json);
      const parameters = parseEvidence(result.json).parameters;
      expect(parameters).toMatchObject({
        query: { nested: { values: variants.map(() => "[REDACTED]") } },
      });
      const [c, s] = InMemoryTransport.createLinkedPair();
      await server.connect(s);
      await client.connect(c);
      const response = await client.callTool({
        name: "search_corpus_objects",
        arguments: input,
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      const evidence = parseEvidence(response.structuredContent);
      assertPrivate(response);
      const retained = session.evidenceById(evidence.evidence_id);
      expect(retained).toBeDefined();
      assertPrivate(retained);
      expect(calls).toBe(2);
      expect(input.query).toEqual(query);
      expect(input.connection.authorization).toBe(secret);
    } finally {
      await client.close();
      await server.close();
      await session.close();
      api.closeAllConnections();
      await new Promise<void>((resolve) => api.close(() => resolve()));
    }
  },
);
