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
  "keeps excluded mutation and plugin-triggering workflows out of the public CLI",
  async ({ cli }) => {
    let calls = 0;
    const server = createServer((_req, res) => {
      calls++;
      res.end("{}");
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const addr = server.address();
    if (!addr || typeof addr === "string") throw Error("address");
    try {
      for (const command of [
        "upload-corpus-firmware",
        "reanalyze-corpus-firmware",
        "enqueue-corpus-analysis",
        "start-corpus-comparison",
        "start-corpus-yara",
        "delete-corpus-firmware",
        "import-corpus-firmware",
      ]) {
        const result = await cli.run({
          arguments: [command, "{}", "--json"],
        });
        expect(result.exitCode, result.stdout + result.stderr).toBe(1);
        expect(result.json).toMatchObject({ code: "COMMAND_NOT_FOUND" });
      }
      expect(calls).toBe(0);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);

cliTest(
  "preserves unknown media-type evidence and admits JSON through compiled CLI",
  async ({ cli }) => {
    let selected = "text/plain";
    const uid = `${"a".repeat(64)}_3`;
    const api = createServer((_request, response) => {
      response.setHeader("content-type", selected);
      response.end(
        JSON.stringify({
          status: 0,
          timestamp: 42,
          request_resource: "/rest/analysis",
          request: { uid, plugin: "dummy" },
          analysis: {
            analysis_date: 0,
            plugin_version: "0",
            system_version: null,
            summary: [],
            tags: {},
            result: { content: "ordinary漢字😀" },
          },
        }),
      );
    });
    api.listen(0, "127.0.0.1");
    await once(api, "listening");
    const address = api.address();
    if (!address || typeof address === "string") throw Error("Missing address");
    try {
      for (const mediaType of [
        "text/plain",
        'Application/JSON; charset="UTF-8"',
      ]) {
        selected = mediaType;
        const admitted = mediaType !== "text/plain";
        const result = await cli.run({
          arguments: [
            "inspect-corpus-analysis",
            JSON.stringify({
              connection: {
                endpoint: `http://127.0.0.1:${address.port}`,
                profile: "source-54aed90b",
              },
              uid,
              plugin: "dummy",
            }),
            "--json",
          ],
        });
        expect(result.exitCode).toBe(admitted ? 0 : 1);
        const evidence = parseEvidence(result.json);
        expect(evidence.normalized_result).toMatchObject({
          state: admitted ? "completed" : "unknown",
          http_status: 200,
          raw_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
          ...(admitted
            ? { data: { analysis: { result: { content: "ordinary漢字😀" } } } }
            : {
                data: null,
                diagnostics: [expect.stringContaining("Content-Type")],
              }),
        });
      }
    } finally {
      api.closeAllConnections();
      await new Promise<void>((resolve) => api.close(() => resolve()));
    }
  },
);
