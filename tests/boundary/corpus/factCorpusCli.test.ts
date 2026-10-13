import { createServer } from "node:http";
import { once } from "node:events";
import { expect } from "vitest";
import { cliTest } from "../../support/cli/cliFixture.js";
import { parseEvidence } from "../../../src/domain/evidence.js";

cliTest(
  "executes the public named corpus CLI against literal loopback without admitting a binary engine",
  async ({ cli }) => {
    let calls = 0;
    const server = createServer((_req, res) => {
      calls++;
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          status: 0,
          timestamp: 42,
          request_resource: "/rest/status",
          system_status: { frontend: {}, database: {}, backend: {} },
          plugins: {},
        }),
      );
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const addr = server.address();
    if (!addr || typeof addr === "string") throw Error("address");
    try {
      const result = await cli.run({
        arguments: [
          "inspect-firmware-corpus",
          JSON.stringify({
            connection: {
              endpoint: `http://127.0.0.1:${addr.port}`,
              profile: "source-54aed90b",
            },
          }),
          "--json",
        ],
      });
      expect(result.exitCode, result.stdout + result.stderr).toBe(0);
      expect(calls).toBe(1);
      expect(parseEvidence(result.json)).toMatchObject({
        subject: null,
        authority: "external-service",
        operation: "inspect_firmware_corpus",
        normalized_result: { state: "completed" },
      });
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);

cliTest(
  "rejects malformed public workflow input with a failing exit status",
  async ({ cli }) => {
    for (const input of [
      "{",
      JSON.stringify({
        connection: {
          endpoint: "https://remote.example",
          profile: "source-54aed90b",
        },
      }),
    ]) {
      const result = await cli.run({
        arguments: ["inspect-firmware-corpus", input, "--json"],
      });
      expect(result.exitCode, result.stdout + result.stderr).toBe(1);
      expect(result.json).toMatchObject({
        code: "invalid_request",
        category: "invalid_input",
      });
    }
  },
);

cliTest(
  "preserves native accepted/failed/unknown facts and corresponding public exit status",
  async ({ cli }) => {
    const uid = "a".repeat(64) + "_3";
    let response: unknown = null,
      calls = 0;
    const server = createServer(async (req, res) => {
      calls++;
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const body = Buffer.concat(chunks).toString();
      expect(req.method).toBe("PUT");
      expect(req.url).toBe(`/rest/analysis/${uid}/file_type?force=true`);
      expect(body).toBe("");
      res.end(JSON.stringify(response));
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const addr = server.address();
    if (!addr || typeof addr === "string") throw Error("address");
    const connection = {
      endpoint: `http://127.0.0.1:${addr.port}`,
      profile: "source-54aed90b",
    };
    try {
      for (const [body, state, exit] of [
        [
          {
            status: 0,
            request_resource: "/rest/analysis",
            timestamp: 42,
            success: true,
          },
          "accepted",
          0,
        ],
        [
          {
            status: 1,
            request_resource: "/rest/analysis",
            timestamp: 42,
            error_message: "preserved postgres finding",
          },
          "failed",
          1,
        ],
        [
          {
            status: 0,
            request_resource: "/rest/analysis",
            timestamp: 42,
            arbitrary: true,
          },
          "unknown",
          1,
        ],
      ] as const) {
        response = body;
        const result = await cli.run({
          arguments: [
            "enqueue-corpus-analysis",
            JSON.stringify({
              connection,
              uid,
              plugin: "file_type",
              force: true,
            }),
            "--json",
          ],
        });
        expect(result.exitCode, result.stdout + result.stderr).toBe(exit);
        expect(parseEvidence(result.json)).toMatchObject({
          operation: "enqueue_corpus_analysis",
          parameters: { uid, plugin: "file_type", force: true },
          normalized_result: { state, data: body },
        });
      }
      expect(calls).toBe(3);
      const unsupported = await cli.run({
        arguments: [
          "enqueue-corpus-analysis",
          JSON.stringify({
            connection: { ...connection, profile: "release-4.4.1" },
            uid,
            plugin: "file_type",
            force: true,
          }),
          "--json",
        ],
      });
      expect(unsupported.exitCode).toBe(1);
      expect(calls).toBe(3);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);
