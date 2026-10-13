import { createServer } from "node:http";
import { once } from "node:events";
import { afterEach, describe, expect, it } from "vitest";
import { FirmwareCorpusService } from "../../application/corpus/FirmwareCorpusService.js";
import { FactRestProvider } from "./FactRestProvider.js";

const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
async function fixture(
  reply: (
    url: URL,
    method: string,
    body: string,
    auth: string | undefined,
  ) => { code?: number; body: unknown; headers?: Record<string, string> },
) {
  const server = createServer(async (req, res) => {
    let data = "";
    for await (const chunk of req) data += chunk;
    const answer = reply(
      new URL(req.url!, "http://127.0.0.1"),
      req.method!,
      data,
      req.headers.authorization,
    );
    res.writeHead(answer.code ?? 200, {
      "content-type": "application/json",
      ...answer.headers,
    });
    res.end(JSON.stringify(answer.body));
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw Error("address");
  return {
    endpoint: `http://127.0.0.1:${address.port}`,
    profile: "source-54aed90b" as const,
    authorization: "secret-Key",
  };
}
const uid = "a".repeat(64) + "_3";
describe("FACT production REST boundary", () => {
  it("preserves exact query, unbounded limit and literal raw Authorization without persisting credentials", async () => {
    const connection = await fixture((url, method, body, auth) => {
      expect(url.pathname).toBe("/rest/firmware");
      expect(url.searchParams.get("limit")).toBe("0");
      expect(JSON.parse(url.searchParams.get("query")!)).toEqual({
        password: { $exists: true },
      });
      expect(url.searchParams.get("recursive")).toBe("true");
      expect(auth).toBe("secret-Key");
      expect(method).toBe("GET");
      expect(body).toBe("");
      return { body: { status: 0, uids: [uid], timestamp: 42 } };
    });
    const result = await new FirmwareCorpusService(
      new FactRestProvider(),
    ).execute("search_corpus_objects", {
      connection,
      kind: "firmware",
      query: { password: { $exists: true } },
      offset: 7,
      limit: 0,
      recursive: true,
      inverted: false,
    });
    if (!result.ok) throw result.error;
    expect(result.value.subject).toBeNull();
    expect(result.value.authority).toBe("external-service");
    expect(JSON.stringify(result.value)).not.toContain("secret-Key");
    expect(JSON.stringify(result.value)).toContain("password");
    expect(result.value.normalized_result).toMatchObject({
      state: "completed",
      coverage: "requested-page",
      data: { uids: [uid] },
    });
  });
  it("treats HTTP 200 producer status 1 as failed and comparison GET 202 as completed", async () => {
    const connection = await fixture((_url, method) =>
      method === "PUT"
        ? { body: { status: 1, error_message: "Compare already exists" } }
        : { code: 202, body: { status: 0, comparison: { same: true } } },
    );
    const service = new FirmwareCorpusService(new FactRestProvider());
    const start = await service.execute("start_corpus_comparison", {
      connection,
      uids: [uid, "b".repeat(64) + "_2"],
      redo: false,
    });
    if (!start.ok) throw start.error;
    expect(start.value.normalized_result).toMatchObject({
      state: "failed",
      http_status: 200,
    });
    const get = await service.execute("inspect_corpus_comparison", {
      connection,
      uids: [uid, "b".repeat(64) + "_2"],
    });
    if (!get.ok) throw get.error;
    expect(get.value.normalized_result).toMatchObject({
      state: "completed",
      http_status: 202,
    });
  });
  it("caches first consumed YARA Evidence before delivery, including concurrent reads", async () => {
    let reads = 0;
    const connection = await fixture(() => {
      reads++;
      return { body: { status: 0, binary_search_results: { rule: [uid] } } };
    });
    const service = new FirmwareCorpusService(new FactRestProvider());
    const results = await Promise.all([
      service.execute("collect_corpus_yara", {
        connection,
        search_id: "request-1",
      }),
      service.execute("collect_corpus_yara", {
        connection,
        search_id: "request-1",
      }),
    ]);
    for (const result of results) if (!result.ok) throw result.error;
    expect(reads).toBe(1);
    expect(results[0]).toEqual(results[1]);
    await service.execute("collect_corpus_yara", {
      connection,
      search_id: "request-1",
    });
    expect(reads).toBe(1);
  });
  it("refuses remote hosts, URL credentials and redirects without following them", async () => {
    const service = new FirmwareCorpusService(new FactRestProvider());
    for (const endpoint of [
      "http://localhost:5000",
      "http://example.org",
      "http://user:key@127.0.0.1:5000",
    ]) {
      const result = await service.execute("inspect_firmware_corpus", {
        connection: { endpoint, profile: "release-4.4.1" },
      });
      expect(result.ok).toBe(false);
    }
    let calls = 0;
    const connection = await fixture(() => {
      calls++;
      return {
        code: 302,
        headers: { location: "http://example.org" },
        body: { status: 0 },
      };
    });
    const result = await service.execute("inspect_firmware_corpus", {
      connection,
    });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      state: "failed",
      http_status: 302,
    });
    expect(calls).toBe(1);
  });
  it("does not retry a lost consuming response and redacts encoded transport credentials", async () => {
    let reads = 0;
    const connection = await fixture(() => {
      reads++;
      return {
        body: {
          status: 1,
          error_message: "secret-Key %73ecret-Key c2VjcmV0LUtleQ==",
        },
      };
    });
    const service = new FirmwareCorpusService(new FactRestProvider());
    const first = await service.execute("collect_corpus_yara", {
      connection,
      search_id: "request-2",
    });
    if (!first.ok) throw first.error;
    expect(JSON.stringify(first.value)).not.toContain("secret-Key");
    await service.execute("collect_corpus_yara", {
      connection,
      search_id: "request-2",
    });
    expect(reads).toBe(1);
  });
});
