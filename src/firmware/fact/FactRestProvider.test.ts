import { writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import {
  FACT_LIMITS,
  FactResponseResources,
  factHash,
  factUid,
} from "./FactProtocol.js";
import { FactFileResources } from "./FactFiles.js";
import { createServer } from "node:http";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, expect, it } from "vitest";
import { firmwareCorpusResultSchema } from "../../domain/corpus/firmwareCorpus.js";
import { FirmwareCorpusService } from "../../application/corpus/FirmwareCorpusService.js";
import { FactRestProvider } from "./FactRestProvider.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";

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
  ) => {
    code?: number;
    body?: unknown;
    bytes?: Buffer;
    disconnect?: boolean;
    headers?: Record<string, string>;
  },
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
    if (answer.disconnect) {
      req.socket.destroy();
      return;
    }
    res.writeHead(answer.code ?? 200, {
      "content-type": "application/json",
      ...answer.headers,
    });
    const requestUrl = new URL(req.url!, "http://127.0.0.1");
    const requestEcho = (): Record<string, unknown> | undefined => {
      const path = requestUrl.pathname;
      const segments = path.split("/").filter(Boolean);
      if (path === "/rest/firmware" || path === "/rest/file_object") {
        const query = requestUrl.searchParams.get("query");
        const echo: Record<string, unknown> = {
          offset: Number(requestUrl.searchParams.get("offset")),
          limit: Number(requestUrl.searchParams.get("limit")),
          query: query === null ? {} : JSON.parse(query),
        };
        if (path === "/rest/firmware") {
          echo.recursive = requestUrl.searchParams.get("recursive") === "true";
          echo.inverted = requestUrl.searchParams.get("inverted") === "true";
        }
        return echo;
      }
      if (segments[0] === "rest" && segments[1] === "analysis")
        return { uid: segments[2], plugin: segments[3] };
      if (segments[0] === "plugins" && segments[2] === "rest")
        return { uid: segments[3] };
      if (segments[0] === "rest" && segments[1] === "compare")
        return { compare_id: segments[2] };
      if (segments[0] === "rest" && segments[1] === "binary")
        return {
          uid: segments[2],
          tar: requestUrl.searchParams.get("tar") === "true",
        };
      if (segments[0] === "rest" && segments[1] === "firmware" && segments[2])
        return { uid: segments[2] };
      if (
        segments[0] === "rest" &&
        segments[1] === "file_object" &&
        segments[2]
      )
        return { uid: segments[2] };
      return undefined;
    };
    const body =
      answer.body !== null &&
      typeof answer.body === "object" &&
      !Array.isArray(answer.body) &&
      "status" in answer.body
        ? {
            timestamp: 42,
            request_resource: new URL(
              req.url!,
              "http://127.0.0.1",
            ).pathname.startsWith("/plugins/")
              ? new URL(req.url!, "http://127.0.0.1").pathname.replace(
                  /\/[^/]+$/u,
                  "/<uid>",
                )
              : new URL(req.url!, "http://127.0.0.1").pathname
                  .split("/")
                  .slice(0, 3)
                  .join("/"),
            ...(requestEcho() === undefined ? {} : { request: requestEcho() }),
            ...answer.body,
          }
        : answer.body;
    res.end(answer.bytes ?? JSON.stringify(body));
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
const producerAnalysis = (result: Record<string, unknown>) => ({
  analysis_date: 42,
  plugin_version: "1",
  system_version: null,
  summary: [],
  tags: {},
  result,
});

it("denies FACT mutation and plugin-triggering REST operations before HTTP", async () => {
  let requests = 0;
  const connection = await fixture(() => {
    requests++;
    return { body: { status: 0 } };
  });
  const provider = new FactRestProvider();
  try {
    for (const operation of [
      "upload_corpus_firmware",
      "reanalyze_corpus_firmware",
      "enqueue_corpus_analysis",
      "start_corpus_comparison",
      "start_corpus_yara",
      "delete_corpus_firmware",
    ]) {
      const result = await provider.execute(
        operation as never,
        { connection } as never,
      );
      expect(result.ok, operation).toBe(false);
      if (!result.ok)
        expect(result.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    }
    expect(requests).toBe(0);
  } finally {
    await provider.close();
  }
});
it("cancels unfinished oversized response bodies without accumulating transports", async () => {
  const unfinished = new Set<import("node:net").Socket>();
  let calls = 0;
  const server = createServer((req, res) => {
    calls++;
    if (calls <= 3) {
      unfinished.add(req.socket);
      req.socket.once("close", () => unfinished.delete(req.socket));
      res.writeHead(200, {
        "content-length": String(FACT_LIMITS.jsonBytes + 1),
      });
      res.write("{"); // Deliberately never finish the rejected body.
    } else {
      res.end(
        JSON.stringify({
          status: 0,
          timestamp: 42,
          request_resource: "/rest/status",
          system_status: { frontend: {}, database: {}, backend: {} },
          plugins: {},
        }),
      );
    }
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw Error("address");
  const connection = {
    endpoint: `http://127.0.0.1:${address.port}`,
    profile: "source-54aed90b" as const,
  };
  const service = new FirmwareCorpusService(new FactRestProvider());
  try {
    for (let at = 0; at < 3; at++) {
      const result = await service.execute("inspect_firmware_corpus", {
        connection,
      });
      if (!result.ok) throw result.error;
      const resultObservation = firmwareCorpusResultSchema.parse(
        result.value.normalized_result,
      );
      expect(resultObservation.state).toBe("unknown");
      expect(resultObservation.diagnostics.join(" ")).toContain(
        "wire byte budget",
      );
      for (let waited = 0; unfinished.size && waited < 100; waited++)
        await delay(10);
      expect(unfinished.size).toBe(0);
    }
    const admitted = await service.execute("inspect_firmware_corpus", {
      connection,
    });
    if (!admitted.ok) throw admitted.error;
    const admittedObservation = firmwareCorpusResultSchema.parse(
      admitted.value.normalized_result,
    );
    expect(admittedObservation.state).toBe("completed");
    await service.close();
    for (let at = 0; unfinished.size && at < 100; at++) await delay(10);
    expect(unfinished.size).toBe(0);
    expect(calls).toBe(4);
  } finally {
    await service.close();
  }
});

it("binds other native selection echoes and preserves ambiguous consuming errors without retry", async () => {
  let body: Record<string, unknown> = {};
  let calls = 0;
  const connection = await fixture(() => {
    calls++;
    return { body };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  const uids = [uid, "b".repeat(64) + "_3"];
  try {
    for (const echoed of [uids.join(";"), "wrong-id"]) {
      body = {
        status: 0,
        _id: uids.join(";"),
        general: { hid: { [uid]: "first", [uids[1]!]: "second" } },
        submission_date: 42,
        request: { compare_id: echoed },
      };
      const result = await service.execute("inspect_corpus_comparison", {
        connection,
        uids,
      });
      if (!result.ok) throw result.error;
      const resultObservation = firmwareCorpusResultSchema.parse(
        result.value.normalized_result,
      );
      expect(resultObservation.state).toBe(
        echoed === "wrong-id" ? "unknown" : "completed",
      );
    }
    body = {
      status: 1,
      error_message:
        "The result is not ready yet or it has already been fetched",
      request: { search_id: "different-search" },
    };
    const first = await service.execute("collect_corpus_yara", {
      connection,
      search_id: "selected-search",
    });
    if (!first.ok) throw first.error;
    const firstObservation = firmwareCorpusResultSchema.parse(
      first.value.normalized_result,
    );
    expect(firstObservation.state).toBe("unknown");
    const repeated = await service.execute("collect_corpus_yara", {
      connection,
      search_id: "selected-search",
    });
    if (!repeated.ok) throw repeated.error;
    expect(repeated.value).toBe(first.value);
    expect(calls).toBe(3);
  } finally {
    await service.close();
  }
});

it("does not publish a verified download whose available UID or tar echo contradicts selection", async () => {
  const root = await createTestTempDirectory("rea-fact-download-correlation-");
  const bytes = Buffer.from("abc");
  let request: Record<string, unknown> = {};
  let calls = 0;
  const connection = await fixture(() => {
    calls++;
    return {
      body: {
        status: 0,
        binary: bytes.toString("base64"),
        SHA256: factHash(bytes),
        file_name: "firmware.bin",
        request,
      },
    };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  try {
    for (const [echo, state] of [
      [{ uid: "b".repeat(64) + "_3", tar: false }, "unknown"],
      [{ uid: factUid(bytes), tar: true }, "unknown"],
      [{ uid: factUid(bytes), tar: false }, "completed"],
    ] as const) {
      request = echo;
      const output_path = join(root, `${calls}.bin`);
      const result = await service.execute("download_corpus_binary", {
        connection,
        uid: factUid(bytes),
        output_path,
      });
      if (!result.ok) throw result.error;
      const resultObservation = firmwareCorpusResultSchema.parse(
        result.value.normalized_result,
      );
      expect(resultObservation.state).toBe(state);
      if (state === "unknown")
        await expect(readFile(output_path)).rejects.toMatchObject({
          code: "ENOENT",
        });
      else expect(await readFile(output_path)).toEqual(bytes);
      expect(resultObservation.data).toMatchObject({ request });
    }
    expect(calls).toBe(3);
  } finally {
    await service.close();
    await rm(root, { recursive: true });
  }
});

it("preserves exact query, unbounded limit and literal raw Authorization without persisting credentials", async () => {
  const connection = await fixture((url, method, body, auth) => {
    expect(url.pathname).toBe("/rest/firmware");
    expect(url.searchParams.get("limit")).toBe("0");
    expect(url.searchParams.get("offset")).toBe("7");
    expect(url.searchParams.get("inverted")).toBe("false");
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
it("accepts comparison GET observations without starting comparison work", async () => {
  const connection = await fixture(() => ({
    code: 202,
    body: {
      status: 0,
      general: { hid: { [uid]: "first", ["b".repeat(64) + "_2"]: "second" } },
      _id: [uid, "b".repeat(64) + "_2"].sort().join(";"),
      submission_date: 1,
    },
  }));
  const service = new FirmwareCorpusService(new FactRestProvider());
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
it("retains ambiguous producer failures and redacts every encoded key while preserving firmware findings", async () => {
  let reads = 0;
  const connection = await fixture(() => {
    reads++;
    return {
      body: {
        status: 1,
        error_message:
          "secret-Key %73ecret-Key c2VjcmV0LUtleQ== 7365637265742d4b6579 firmware password=test",
      },
    };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  const first = await service.execute("collect_corpus_yara", {
    connection,
    search_id: "request-2",
  });
  if (!first.ok) throw first.error;
  for (const encoded of [
    "secret-Key",
    "%73ecret-Key",
    "c2VjcmV0LUtleQ==",
    "7365637265742d4b6579",
  ])
    expect(JSON.stringify(first.value)).not.toContain(encoded);
  expect(JSON.stringify(first.value)).toContain("firmware password=test");
  await service.execute("collect_corpus_yara", {
    connection,
    search_id: "request-2",
  });
  expect(reads).toBe(1);
});

it("isolates consuming caches by private authorization and canonical origin", async () => {
  const keys: (string | undefined)[] = [];
  const connection = await fixture((_url, _method, _body, auth) => {
    keys.push(auth);
    return auth === "secret-Key"
      ? { body: { status: 0, binary_search_results: { privileged: [uid] } } }
      : {
          code: 403,
          body: {
            status: 1,
            error_message:
              "Caller does not have permission to collect this result",
          },
        };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  const first = await service.execute("collect_corpus_yara", {
    connection,
    search_id: "private-id",
  });
  if (!first.ok) throw first.error;
  const alias = await service.execute("collect_corpus_yara", {
    connection: { ...connection, endpoint: connection.endpoint + "/" },
    search_id: "private-id",
  });
  expect(alias).toEqual(first);
  const other = await service.execute("collect_corpus_yara", {
    connection: { ...connection, authorization: "second-key" },
    search_id: "private-id",
  });
  if (!other.ok) throw other.error;
  expect(other.value.evidence_id).not.toBe(first.value.evidence_id);
  expect(other.value.normalized_result).toMatchObject({ state: "failed" });
  expect(JSON.stringify(other.value.normalized_result)).not.toContain(
    "privileged",
  );
  const { authorization: _authorization, ...publicConnection } = connection;
  await service.execute("collect_corpus_yara", {
    connection: publicConnection,
    search_id: "private-id",
  });
  expect(keys).toEqual(["secret-Key", "second-key", undefined]);
  for (const result of [first, other])
    if (result.ok)
      expect(JSON.stringify(result.value.parameters)).not.toMatch(
        /secret-Key|second-key/u,
      );
});
it("releases only provably undelivered reservations for a later explicit call", async () => {
  let reads = 0;
  const connection = await fixture(() => {
    reads++;
    return { body: { status: 0, binary_search_results: { rule: [uid] } } };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  const controller = new AbortController();
  controller.abort();
  const first = await service.execute(
    "collect_corpus_yara",
    { connection, search_id: "cancel-id" },
    { signal: controller.signal },
  );
  if (!first.ok) throw first.error;
  expect(first.value.normalized_result).toMatchObject({
    state: "not-delivered",
  });
  expect(reads).toBe(0);
  const next = await service.execute("collect_corpus_yara", {
    connection,
    search_id: "cancel-id",
  });
  if (!next.ok) throw next.error;
  expect(next.value.normalized_result).toMatchObject({ state: "completed" });
  expect(reads).toBe(1);
});
it("retains real disconnect uncertainty and never consumes again automatically or explicitly", async () => {
  let reads = 0;
  const connection = await fixture(() => {
    reads++;
    return { disconnect: true };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  const input = { connection, search_id: "lost-id" };
  const first = await service.execute("collect_corpus_yara", input);
  if (!first.ok) throw first.error;
  expect(first.value.normalized_result).toMatchObject({
    state: "unknown",
    http_status: null,
  });
  expect(reads).toBe(1);
  expect(await service.execute("collect_corpus_yara", input)).toEqual(first);
  expect(reads).toBe(1);
});

it("keeps malformed successful producer envelopes unknown with their source facts and digest", async () => {
  const responses: unknown[] = [
    null,
    [],
    {},
    { status: 0, success: true },
    { status: "0", analysis: { found: true } },
    { status: 0, analysis: [] },
  ];
  const connection = await fixture(() => ({ body: responses.shift() }));
  const service = new FirmwareCorpusService(new FactRestProvider());
  for (let i = 0; i < 6; i++) {
    const result = await service.execute(
      i === 3 ? "inspect_corpus_object" : "inspect_corpus_analysis",
      {
        connection,
        uid,
        ...(i === 3 ? { kind: "firmware" } : { plugin: "file_type" }),
      },
    );
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      state: "unknown",
      raw_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
      diagnostics: [expect.stringContaining("producer response")],
    });
    if (i === 3)
      expect(result.value.normalized_result).toMatchObject({
        data: { success: true },
      });
  }
});
it("accepts producer-shaped analysis and raw category statistics without inventing status", async () => {
  const connection = await fixture((url) => ({
    body: url.pathname.startsWith("/rest/statistics")
      ? { general: { files: 3 } }
      : {
          status: 0,
          analysis: producerAnalysis({ password: "firmware-finding" }),
        },
  }));
  const service = new FirmwareCorpusService(new FactRestProvider());
  for (const [operation, input] of [
    ["inspect_corpus_analysis", { uid, plugin: "file_type" }],
    ["inspect_corpus_statistics", { category: "general" }],
  ] as const) {
    const result = await service.execute(operation, { connection, ...input });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      state: "completed",
    });
  }
});

it("keeps successful responses unknown when pinned upstream echoes are missing or contradictory", async () => {
  const cases = [
    {
      operation: "search_corpus_objects",
      input: { kind: "firmware", query: {}, offset: 0, limit: 10 },
      body: { status: 0, uids: [uid], request: {} },
    },
    {
      operation: "search_corpus_objects",
      input: {
        kind: "firmware",
        query: { vendor: "acme" },
        offset: 2,
        limit: 10,
      },
      body: {
        status: 0,
        uids: [uid],
        request: { query: {}, offset: 2, limit: 10 },
      },
    },
    {
      operation: "inspect_corpus_analysis",
      input: { uid, plugin: "file_type" },
      body: { status: 0, analysis: producerAnalysis({}), request: { uid } },
    },
    {
      operation: "inspect_corpus_analysis",
      input: { uid, plugin: "file_type" },
      body: {
        status: 0,
        analysis: producerAnalysis({}),
        request: { uid, plugin: "other_plugin" },
      },
    },
    {
      operation: "inspect_corpus_object",
      input: { uid, kind: "file" },
      body: {
        status: 0,
        file_object: {
          meta_data: {
            hid: "x",
            size: 3,
            number_of_included_files: 0,
            included_files: [],
            total_files_in_firmware: "unknown",
            firmwares_including_this_file: [],
            virtual_file_path: {},
          },
          analysis: {},
        },
        request: { uid: "b".repeat(64) + "_3" },
      },
    },
    {
      operation: "inspect_corpus_object",
      input: { uid, kind: "firmware", summary: true },
      body: {
        status: 0,
        firmware: {
          meta_data: {
            hid: "x",
            size: 3,
            number_of_included_files: 0,
            included_files: [],
            total_files_in_firmware: "unknown",
            device_name: null,
            device_class: null,
            device_part: "",
            vendor: null,
            version: null,
            release_date: null,
          },
          analysis: {},
        },
        request: { uid, summary: false },
      },
    },
    {
      operation: "inspect_corpus_parent_analysis",
      input: { uid, plugin: "qemu_exec" },
      body: {
        status: 0,
        qemu_exec: {},
        request: { uid: "b".repeat(64) + "_3" },
      },
    },
  ] as const;
  for (const testCase of cases) {
    const connection = await fixture(() => ({ body: testCase.body }));
    const service = new FirmwareCorpusService(new FactRestProvider());
    const result = await service.execute(testCase.operation, {
      connection,
      ...testCase.input,
    } as never);
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result, testCase.operation).toMatchObject({
      state: "unknown",
    });
    await service.close();
  }
});
it("binds a consumed YARA result to the exact requested route without inventing an upstream echo", async () => {
  for (const [selected, request, payload, expectedState] of [
    [
      "selected-search",
      undefined,
      { binary_search_results: { rule: [uid] } },
      "completed",
    ],
    [
      "other-selected-search",
      { search_id: "different-search" },
      { binary_search_results: { rule: [uid] } },
      "unknown",
    ],
    [
      "malformed-search",
      undefined,
      { binary_search_results: { rule: "not-an-array" } },
      "unknown",
    ],
  ] as const) {
    const connection = await fixture((url, method, body) => {
      expect(url.pathname).toBe(`/rest/binary_search/${selected}`);
      expect(method).toBe("GET");
      expect(body).toBe("");
      return {
        body: {
          status: 0,
          ...payload,
          ...(request === undefined ? {} : { request }),
        },
      };
    });
    const service = new FirmwareCorpusService(new FactRestProvider());
    const result = await service.execute("collect_corpus_yara", {
      connection,
      search_id: selected,
    });
    if (!result.ok) throw result.error;
    expect(result.value.parameters).toMatchObject({ search_id: selected });
    expect(result.value.normalized_result).toMatchObject({
      state: expectedState,
      data: { binary_search_results: payload.binary_search_results },
    });
    const observed = result.value.normalized_result;
    if (request === undefined)
      expect(observed).not.toHaveProperty("data.request");
    else
      expect(observed).toHaveProperty(
        "data.request.search_id",
        "different-search",
      );
    await service.close();
  }
});
it("binds firmware summary selection to the exact query without inventing an upstream echo", async () => {
  const connection = await fixture((url) => {
    expect(url.pathname).toBe(`/rest/firmware/${uid}`);
    expect(url.searchParams.get("summary")).toBe("true");
    return {
      body: {
        status: 0,
        firmware: {
          meta_data: {
            hid: "x",
            size: 3,
            number_of_included_files: 0,
            included_files: [],
            total_files_in_firmware: "unknown",
            device_name: null,
            device_class: null,
            device_part: "",
            vendor: null,
            version: null,
            release_date: null,
          },
          analysis: {},
        },
        request: { uid },
      },
    };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  const result = await service.execute("inspect_corpus_object", {
    connection,
    uid,
    kind: "firmware",
    summary: true,
  });
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toMatchObject({
    state: "completed",
    data: { request: { uid } },
  });
  expect(result.value.parameters).toMatchObject({ summary: true });
  expect(result.value.normalized_result).not.toHaveProperty(
    "data.request.summary",
  );
  await service.close();
});
it("rejects malformed UTF-8 without repairing bytes into observed values", async () => {
  const bytes = Buffer.from([
    0x7b, 0x22, 0x78, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d,
  ]);
  const connection = await fixture(() => ({ bytes }));
  const result = await new FirmwareCorpusService(
    new FactRestProvider(),
  ).execute("inspect_corpus_analysis", {
    connection,
    uid,
    plugin: "file_type",
  });
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toMatchObject({
    state: "unknown",
    diagnostics: [expect.stringContaining("UTF-8")],
  });
  expect(JSON.stringify(result.value)).not.toContain("�");
});

it("serializes heavy response ownership with tagged capacity and permits explicit work after cancellation", async () => {
  let begun!: () => void;
  const started = new Promise<void>((resolve) => {
    begun = resolve;
  });
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let calls = 0;
  const server = createServer(async (req, res) => {
    calls++;
    begun();
    await held;
    res.end(
      JSON.stringify({
        status: 0,
        timestamp: 42,
        request_resource: req.url?.startsWith("/rest/binary_search")
          ? "/rest/binary_search"
          : "/rest/analysis",
        ...(req.url?.startsWith("/rest/binary_search")
          ? { binary_search_results: { ready: [uid] } }
          : { analysis: producerAnalysis({ ready: true }) }),
      }),
    );
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw Error("address");
  const connection = {
    endpoint: `http://127.0.0.1:${address.port}`,
    profile: "source-54aed90b",
  };
  const service = new FirmwareCorpusService(new FactRestProvider());
  const controller = new AbortController();
  const active = service.execute(
    "inspect_corpus_analysis",
    { connection, uid, plugin: "file_type" },
    { signal: controller.signal },
  );
  await started;
  const refused = await Promise.race([
    service.execute("collect_corpus_yara", {
      connection,
      search_id: "capacity",
    }),
    new Promise<undefined>((resolve) =>
      setTimeout(() => resolve(undefined), 1000),
    ),
  ]);
  controller.abort();
  release();
  const canceled = await active;
  expect(refused?.ok).toBe(false);
  if (refused && !refused.ok)
    expect(refused.error).toMatchObject({
      _tag: "AnalysisResourceConstraintError",
      resource: "capacity",
    });
  expect(calls).toBe(1);
  if (!canceled.ok) throw canceled.error;
  expect(canceled.value.normalized_result).toMatchObject({ state: "unknown" });
  release();
  const next = await service.execute("collect_corpus_yara", {
    connection,
    search_id: "capacity",
  });
  if (!next.ok) throw next.error;
  expect(next.value.normalized_result).toMatchObject({ state: "completed" });
  expect(calls).toBe(2);
  await service.close();
});
it("retains verified download facts when partial publication and rollback fail", async () => {
  const root = await createTestTempDirectory("rea-fact-download-publication-");
  const path = join(root, "firmware.bin");
  const bytes = Buffer.from("abc");
  let cleanup = 0;
  const files = new FactFileResources({
    writeBytes: async (handle, data) => {
      await handle.write(data.subarray(0, 2));
      throw Error("synthetic partial write");
    },
    removeFile: async (path) => {
      if (cleanup++ === 0) throw Error("synthetic unlink failure");
      await rm(path);
    },
  });
  const connection = await fixture(() => ({
    body: {
      status: 0,
      binary: bytes.toString("base64"),
      SHA256: factHash(bytes),
      file_name: "firmware.bin",
    },
  }));
  const service = new FirmwareCorpusService(new FactRestProvider(files));
  const result = await service.execute("download_corpus_binary", {
    connection,
    uid: factUid(bytes),
    output_path: path,
  });
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toMatchObject({
    state: "unknown",
    data: {
      producer: {
        artifact: {
          size: 3,
          sha256: factHash(bytes),
          root_uid: factUid(bytes),
          verified: true,
        },
      },
      publication: { path, written_bytes: 2, cleanup: "retained" },
    },
    diagnostics: expect.arrayContaining([
      expect.stringContaining("Cleanup remains uncertain"),
    ]),
  });
  expect(JSON.stringify(result.value)).not.toContain("YWJj");
  expect(await readFile(path, "utf8")).toBe("ab");
  await service.close();
  await expect(readFile(path)).rejects.toMatchObject({ code: "ENOENT" });
  await rm(root, { recursive: true });
});
it("retains completed Evidence across response cleanup failure and retries close without refetch", async () => {
  let cleanupAttempts = 0;
  class RetryCleanup extends FactResponseResources {
    override async release(
      reader: Parameters<FactResponseResources["release"]>[0],
    ) {
      cleanupAttempts++;
      if (cleanupAttempts <= 2)
        throw new Error("injected reader cleanup failure");
      await super.release(reader);
    }
  }
  let calls = 0;
  const connection = await fixture(() => {
    calls++;
    return { body: { status: 0, analysis: producerAnalysis({ answer: 42 }) } };
  });
  const service = new FirmwareCorpusService(
    new FactRestProvider(undefined, undefined, new RetryCleanup()),
  );
  const result = await service.execute("inspect_corpus_analysis", {
    connection,
    uid,
    plugin: "file_type",
  });
  if (!result.ok) throw result.error;
  const evidence = result.value;
  expect(evidence.normalized_result).toMatchObject({
    state: "completed",
    data: { analysis: { result: { answer: 42 } } },
    diagnostics: [expect.stringContaining("FACT HTTP response body")],
  });
  await expect(service.close()).rejects.toThrow("cleanup remains unresolved");
  expect(evidence.normalized_result).toMatchObject({
    state: "completed",
    data: { analysis: { result: { answer: 42 } } },
  });
  await service.close();
  expect(cleanupAttempts).toBe(3);
  expect(calls).toBe(1);
});
it("retains malformed scalar and array producer values as partial observations", async () => {
  for (const body of [null, 42, "source-value", [{ fact: "retained" }]]) {
    const connection = await fixture(() => ({ body }));
    const service = new FirmwareCorpusService(new FactRestProvider());
    const result = await service.execute("inspect_corpus_analysis", {
      connection,
      uid,
      plugin: "file_type",
    });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      state: "unknown",
      data: body,
    });
    await service.close();
  }
});
it("accepts native download request metadata and enforces separately measured escaped response overhead", async () => {
  const root = await createTestTempDirectory("rea-fact-download-budget-");
  const bytes = Buffer.from("abc");
  const prefix =
    '{"status":0,"timestamp":42,"request_resource":"/rest/binary","request":{"uid":"' +
    factUid(bytes) +
    '","tar":false},"binary":"YWJj","SHA256":"' +
    factHash(bytes) +
    '","file_name":"';
  const suffix = '"}';
  const escaped = "\\u00e9\\ud83d\\ude80";
  const fixed = Buffer.byteLength(prefix + suffix + escaped) - 4;
  for (const extra of [0, 1]) {
    const wire = Buffer.from(
      prefix +
        escaped +
        "x".repeat(FACT_LIMITS.jsonBytes - fixed + extra) +
        suffix,
    );
    const connection = await fixture(() => ({ bytes: wire }));
    const service = new FirmwareCorpusService(new FactRestProvider());
    const output_path = join(root, `output-${extra}`);
    const result = await service.execute("download_corpus_binary", {
      connection,
      uid: factUid(bytes),
      output_path,
    });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      state: extra ? "unknown" : "completed",
    });
    if (extra) {
      await expect(readFile(output_path)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } else expect(await readFile(output_path)).toEqual(bytes);
    await service.close();
  }
  await rm(root, { recursive: true });
});

it("keeps first-caller fetch ownership when a concurrent YARA waiter cancels delivery", async () => {
  let begun!: () => void;
  const started = new Promise<void>((resolve) => {
    begun = resolve;
  });
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let calls = 0;
  const server = createServer(async (_req, res) => {
    calls++;
    begun();
    await held;
    res.end(
      JSON.stringify({
        status: 0,
        timestamp: 42,
        request_resource: "/rest/binary_search",
        binary_search_results: { ready: [uid] },
      }),
    );
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw Error("address");
  const connection = {
    endpoint: `http://127.0.0.1:${address.port}`,
    profile: "source-54aed90b",
  };
  const service = new FirmwareCorpusService(new FactRestProvider());
  const first = service.execute("collect_corpus_yara", {
    connection,
    search_id: "joined",
  });
  await started;
  const waiter = new AbortController();
  const joined = service.execute(
    "collect_corpus_yara",
    {
      connection: { ...connection, endpoint: connection.endpoint + "/" },
      search_id: "joined",
    },
    { signal: waiter.signal },
  );
  waiter.abort();
  release();
  const [a, b] = await Promise.all([first, joined]);
  if (!a.ok) throw a.error;
  if (!b.ok) throw b.error;
  expect(a.value.normalized_result).toMatchObject({ state: "completed" });
  expect(b.value).toBe(a.value);
  expect(calls).toBe(1);
  await service.close();
});
it("requires native analysis metadata and object facts before claiming requested reads completed", async () => {
  for (const [operation, input, body] of [
    [
      "inspect_corpus_analysis",
      { uid, plugin: "file_type" },
      { status: 0, analysis: {} },
    ],
    [
      "inspect_corpus_analysis",
      { uid, plugin: "file_type" },
      { status: 0, analysis: { result: {} } },
    ],
    [
      "inspect_corpus_object",
      { uid, kind: "firmware" },
      { status: 0, firmware: { meta_data: {}, analysis: {} } },
    ],
    [
      "inspect_corpus_object",
      { uid, kind: "file" },
      { status: 0, file_object: { meta_data: { size: 3 }, analysis: {} } },
    ],
  ] as const) {
    const connection = await fixture(() => ({ body }));
    const service = new FirmwareCorpusService(new FactRestProvider());
    const result = await service.execute(operation, { connection, ...input });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({
      state: "unknown",
      data: body,
    });
    await service.close();
  }
});
it("accepts both pinned profiles native file metadata and binds reported object size to selected UID", async () => {
  const meta_data = {
    hid: "firmware.bin",
    size: 3,
    number_of_included_files: 0,
    included_files: [],
    total_files_in_firmware: "unknown",
    firmwares_including_this_file: [],
    virtual_file_path: {},
  };
  for (const profile of ["release-4.4.1", "source-54aed90b"] as const) {
    for (const size of [3, 4]) {
      const connection = await fixture(() => ({
        body: {
          status: 0,
          file_object: { meta_data: { ...meta_data, size }, analysis: {} },
        },
      }));
      const service = new FirmwareCorpusService(new FactRestProvider());
      const result = await service.execute("inspect_corpus_object", {
        connection: { ...connection, profile },
        uid,
        kind: "file",
      });
      if (!result.ok) throw result.error;
      expect(result.value.normalized_result).toMatchObject({
        state: size === 3 ? "completed" : "unknown",
        data: { file_object: { meta_data: { size } } },
      });
      await service.close();
    }
  }
});
it("redacts exact Unicode authentication encodings while preserving different-case firmware findings", async () => {
  const secret = 'é-"Key';
  const encodings = [
    secret,
    encodeURIComponent(secret),
    "é%2d%22Key",
    Buffer.from(secret).toString("base64"),
    Buffer.from(secret).toString("hex").toUpperCase(),
    JSON.stringify(secret).slice(1, -1),
  ];
  const connection = await fixture(() => ({
    body: {
      status: 1,
      error_message: encodings.join(" / "),
      firmware_password: 'É-"KEY',
    },
  }));
  const service = new FirmwareCorpusService(new FactRestProvider());
  const result = await service.execute("inspect_corpus_analysis", {
    connection: { ...connection, authorization: secret },
    uid,
    plugin: "file_type",
  });
  if (!result.ok) throw result.error;
  const observation = result.value.normalized_result;
  if (
    observation === null ||
    typeof observation !== "object" ||
    Array.isArray(observation)
  )
    throw Error("observation");
  const data = observation.data;
  if (
    data === null ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    typeof data.error_message !== "string"
  )
    throw Error("data");
  for (const encoded of encodings)
    expect(data.error_message).not.toContain(encoded);
  expect(data.firmware_password).toBe('É-"KEY');
  await service.close();
});

it("retains a consumed response resource refusal and its exact digest without re-fetching", async () => {
  const secret = "a".repeat(300) + "b";
  const near = "%61".repeat(9999) + "b";
  const body = {
    status: 0,
    timestamp: 42,
    request_resource: "/rest/binary_search",
    binary_search_results: { [near]: ["a".repeat(64) + "_1"] },
  };
  const bytes = Buffer.from(JSON.stringify(body));
  let calls = 0;
  const connection = {
    ...(await fixture(() => {
      calls++;
      return { bytes };
    })),
    authorization: secret,
  };
  const provider = new FactRestProvider();
  const service = new FirmwareCorpusService(provider);
  try {
    const input = { connection, search_id: "privacy-once" };
    const first = await service.execute("collect_corpus_yara", input);
    expect(first).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisResourceConstraintError", resource: "cpu" },
    });
    expect(await service.execute("collect_corpus_yara", input)).toBe(first);
    expect(calls).toBe(1);
    if (!first.ok) {
      expect(first.error.partialObservation).toMatchObject({
        parameters: {},
        normalized_result: {
          state: "unknown",
          http_status: 200,
          raw_sha256: factHash(bytes),
          data: { producer_state: "completed", retained_cleanup_resources: 0 },
        },
      });
      expect(JSON.stringify(first.error)).not.toContain(secret);
      expect(JSON.stringify(first.error)).not.toContain(near);
    }
  } finally {
    await service.close();
  }
});
