import { once } from "node:events";
import { createServer } from "node:http";
import { expect, it } from "vitest";
import { FirmwareCorpusService } from "../../../src/application/corpus/FirmwareCorpusService.js";
import { FactRestProvider } from "../../../src/firmware/fact/FactRestProvider.js";
import { FACT_LIMITS } from "../../../src/firmware/fact/FactProtocol.js";

it("keeps 256 deterministic bounded response cases fail-closed and private (seed 0x46414354)", async () => {
  const uid = `${"a".repeat(64)}_3`,
    secret = "fact-live.synthetic+'é";
  const encoded = [
    secret,
    Buffer.from(secret).toString("base64"),
    Buffer.from(secret, "latin1").toString("hex"),
    encodeURIComponent(secret),
  ];
  let kind = 0,
    state = 0x46414354,
    calls = 0;
  const methods: string[] = [];
  const analysis = {
    analysis_date: 0,
    plugin_version: "0",
    system_version: null,
    summary: [],
    tags: {},
    result: { content: "ordinary finding" },
  };
  const api = createServer((request, response) => {
    methods.push(request.method!);
    calls++;
    expect(request.headers.authorization).toBe(secret);
    response.setHeader("content-type", "application/json");
    const valid = {
      status: 0,
      timestamp: state,
      request_resource: "/rest/analysis",
      request: { uid, plugin: "dummy" },
      analysis,
    };
    switch (kind) {
      case 0:
        response.end(`{${state.toString(16)}`);
        break;
      case 1: {
        const mediaTypes = [
          "text/plain",
          "text/html",
          "application/octet-stream",
          "application/json-invalid",
          "not a media type",
          "",
        ];
        const mediaType = mediaTypes[(calls >>> 3) % mediaTypes.length]!;
        if (mediaType === "") response.removeHeader("content-type");
        else response.setHeader("content-type", mediaType);
        response.end(JSON.stringify(valid));
        break;
      }
      case 2:
        response.setHeader("content-length", FACT_LIMITS.jsonBytes + 1);
        response.end("{");
        break;
      case 3:
        response.end(JSON.stringify({ ...valid, analysis: {} }));
        break;
      case 4:
        response.statusCode = 500;
        response.end(
          JSON.stringify({
            ...valid,
            note: encoded,
            finding: "ordinary finding",
          }),
        );
        break;
      case 5:
        response.end(
          JSON.stringify({
            ...valid,
            request: { uid: `${"b".repeat(64)}_3`, plugin: "dummy" },
          }),
        );
        break;
      case 6:
        response.setHeader(
          "content-type",
          calls % 16 === 7
            ? 'Application/JSON; charset="UTF-8"'
            : "application/json; charset=ignored-by-json-format",
        );
        response.end(JSON.stringify(valid));
        break;
      case 7:
        response.end(JSON.stringify({ ...valid, request: {} }));
        break;
    }
  });
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  const address = api.address();
  if (!address || typeof address === "string") throw Error("Missing address");
  const provider = new FactRestProvider(),
    service = new FirmwareCorpusService(provider);
  try {
    for (let index = 0; index < 256; index++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      kind = index % 8;
      const observed = await service.execute("inspect_corpus_analysis", {
        connection: {
          endpoint: `http://127.0.0.1:${address.port}`,
          profile: "source-54aed90b",
          authorization: secret,
        },
        uid,
        plugin: "dummy",
      });
      expect(observed.ok, `case ${index}/${kind}`).toBe(true);
      if (!observed.ok) throw Error(`Unexpected case failure ${index}`);
      const result = observed.value.normalized_result as {
        state: string;
        data: unknown;
        diagnostics: string[];
      };
      expect(result.state === "completed", `case ${index}/${kind}`).toBe(
        kind === 6,
      );
      const serialized = JSON.stringify(observed);
      for (const value of encoded)
        expect(
          serialized.includes(value),
          `private representation case ${index}`,
        ).toBe(false);
      if (kind === 4 || kind === 6)
        expect(serialized).toContain("ordinary finding");
      if (kind !== 4 && kind !== 6)
        expect(result.diagnostics.length, `case ${index}`).toBeGreaterThan(0);
      if (kind === 1) {
        expect(result.data).toBe(null);
        expect(observed.value.normalized_result).toMatchObject({
          raw_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
        });
        expect(result.diagnostics.join(" ")).toContain("Content-Type");
      }
      expect(provider.responses.pendingResources).toEqual([]);
    }
    expect(calls).toBe(256);
    expect(methods.every((method) => method === "GET")).toBe(true);
  } finally {
    await service.close();
    api.closeAllConnections();
    await new Promise<void>((resolve) => api.close(() => resolve()));
  }
}, 60000);
