import { writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { FACT_LIMITS, factHash, factUid } from "./FactProtocol.js";
import { FactFileResources } from "./FactFiles.js";
import { createServer } from "node:http";
import { once } from "node:events";
import { afterEach, expect, it } from "vitest";
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
it("treats HTTP 200 producer status 1 as failed and comparison GET 202 as completed", async () => {
  const connection = await fixture((_url, method) =>
    method === "PUT"
      ? { body: { status: 1, error_message: "Compare already exists" } }
      : {
          code: 202,
          body: {
            status: 0,
            general: {
              hid: { [uid]: "first", ["b".repeat(64) + "_2"]: "second" },
            },
            _id: [uid, "b".repeat(64) + "_2"].sort().join(";"),
            submission_date: 1,
          },
        },
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

it("rejects every release-profile enqueue before HTTP and preserves source force", async () => {
  const calls: string[] = [];
  const connection = await fixture((url, method) => {
    calls.push(`${method} ${url.pathname}?${url.searchParams}`);
    return { body: { status: 0, success: true } };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  for (const force of [undefined, false, true]) {
    const result = await service.execute("enqueue_corpus_analysis", {
      connection: { ...connection, profile: "release-4.4.1" },
      uid,
      plugin: "file_type",
      ...(force === undefined ? {} : { force }),
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCapabilityUnavailableError" },
    });
  }
  expect(calls).toEqual([]);
  for (const force of [false, true]) {
    const result = await service.execute("enqueue_corpus_analysis", {
      connection,
      uid,
      plugin: "file_type",
      force,
    });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({ state: "accepted" });
  }
  expect(calls).toEqual([
    `PUT /rest/analysis/${uid}/file_type?force=false`,
    `PUT /rest/analysis/${uid}/file_type?force=true`,
  ]);
});
it("isolates consuming caches by private authorization and canonical origin", async () => {
  const keys: (string | undefined)[] = [];
  const connection = await fixture((_url, _method, _body, auth) => {
    keys.push(auth);
    return (auth === "secret-Key"
        ? { body: { status: 0, binary_search_results: { privileged: [uid] } } }
        : {
            code: 403,
            body: {
              status: 1,
              error_message:
                "Caller does not have permission to collect this result",
            },
          });
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

it("allows a later explicit collection after the producer returns no ready result", async () => {
  let calls = 0;
  const connection = await fixture((_url, method) => {
    calls++;
    if (method === "POST")
      return {
        body: {
          status: 0,
          message:
            "Started binary search. Please use GET and the search_id to get the results",
          request: { search_id: "eventually-ready" },
        },
      };
    return calls === 2
      ? {
          code: 400,
          body: {
            status: 1,
            error_message:
              "The result is not ready yet or it has already been fetched",
          },
        }
      : { body: { status: 0, binary_search_results: { rule: [uid] } } };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  const start = await service.execute("start_corpus_yara", {
    connection,
    rule_file: "rule test { condition:true }",
  });
  if (!start.ok) throw start.error;
  expect(start.value.normalized_result).toMatchObject({ state: "accepted" });
  const first = await service.execute("collect_corpus_yara", {
    connection,
    search_id: "eventually-ready",
  });
  if (!first.ok) throw first.error;
  expect(first.value.normalized_result).toMatchObject({
    state: "failed",
    data: {
      error_message:
        "The result is not ready yet or it has already been fetched",
    },
  });
  expect(calls).toBe(2);
  const second = await service.execute("collect_corpus_yara", {
    connection,
    search_id: "eventually-ready",
  });
  if (!second.ok) throw second.error;
  expect(second.value.normalized_result).toMatchObject({ state: "completed" });
  expect(calls).toBe(3);
  expect(
    await service.execute("collect_corpus_yara", {
      connection,
      search_id: "eventually-ready",
    }),
  ).toEqual(second);
  expect(calls).toBe(3);
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
it("requires a real deletion count and enqueue acknowledgement without retrying mutations", async () => {
  let calls = 0;
  const connection = await fixture(() => {
    calls++;
    return { body: { status: 0 } };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  for (const operation of [
    "delete_corpus_firmware",
    "enqueue_corpus_analysis",
  ] as const) {
    const result = await service.execute(operation, {
      connection,
      uid,
      ...(operation === "enqueue_corpus_analysis"
        ? { plugin: "file_type" }
        : {}),
    });
    if (!result.ok) throw result.error;
    expect(result.value.normalized_result).toMatchObject({ state: "unknown" });
  }
  expect(calls).toBe(2);
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
it("rejects upload metadata overflow independently of a tiny binary before HTTP delivery", async () => {
  const root = await createTestTempDirectory("rea-fact-upload-budget-");
  const path = join(root, "firmware.bin");
  await writeFile(path, "abc");
  let calls = 0;
  const connection = await fixture(() => {
    calls++;
    return { body: { status: 0, uid: factUid(Buffer.from("abc")) } };
  });
  const service = new FirmwareCorpusService(new FactRestProvider());
  const result = await service.execute("upload_corpus_firmware", {
    connection,
    path,
    metadata: {
      device_name: "é🚀".repeat(FACT_LIMITS.jsonBytes / 6),
      device_part: "",
      device_class: "",
      file_name: "firmware.bin",
      version: "",
      vendor: "",
    },
    plugins: [],
  });
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toMatchObject({
    state: "not-delivered",
    diagnostics: [expect.stringContaining("metadata")],
  });
  expect(calls).toBe(0);
  await service.close();
  await rm(root, { recursive: true });
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
it("preserves an accepted upload observation separately from failed snapshot cleanup", async () => {
  const root = await createTestTempDirectory("rea-fact-post-cleanup-");
  const runtime = await createTestTempDirectory("rea-fact-private-cleanup-");
  const path = join(root, "é firmware.bin");
  await writeFile(path, "abc");
  let cleanup = 0;
  const files = new FactFileResources({
    createRuntime: async () => ({
      path: runtime,
      close: async () => {
        if (cleanup++ === 0) throw Error("synthetic private cleanup failure");
        await rm(runtime, { recursive: true });
      },
    }),
  });
  const connection = await fixture((url, method, body) => {
    const payload = JSON.parse(body);
    expect(url.pathname).toBe("/rest/firmware");
    expect(method).toBe("PUT");
    expect(payload.binary).toBe("YWJj");
    expect(payload.requested_analysis_systems).toEqual(["file_type"]);
    expect(payload.file_name).toBe("caller-selected-name");
    const { binary: _binary, ...request } = payload;
    return { body: { status: 0, uid: factUid(Buffer.from("abc")), request } };
  });
  const service = new FirmwareCorpusService(new FactRestProvider(files));
  const result = await service.execute("upload_corpus_firmware", {
    connection,
    path,
    metadata: {
      device_name: "device",
      device_part: "part",
      device_class: "class",
      file_name: "caller-selected-name",
      version: "1",
      vendor: "vendor",
    },
    plugins: ["file_type"],
  });
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toMatchObject({
    state: "accepted",
    data: { uid: factUid(Buffer.from("abc")) },
    diagnostics: expect.arrayContaining([
      expect.stringContaining("Snapshot cleanup failed"),
    ]),
  });
  expect(files.pendingResources).toContain(runtime);
  expect(await readFile(path, "utf8")).toBe("abc");
  await service.close();
  expect(cleanup).toBe(2);
  await rm(root, { recursive: true });
});
it("retains bounded upload error echo facts without storing a binary representation", async () => {
  const root = await createTestTempDirectory("rea-fact-upload-error-");
  const path = join(root, "firmware.bin");
  await writeFile(path, "abc");
  const connection = await fixture((_url, _method, body) => ({
    code: 400,
    body: {
      status: 1,
      error_message: "Storing file failed",
      request: JSON.parse(body),
    },
  }));
  const service = new FirmwareCorpusService(new FactRestProvider());
  const result = await service.execute("upload_corpus_firmware", {
    connection,
    path,
    metadata: {
      device_name: "",
      device_part: "",
      device_class: "",
      file_name: "firmware.bin",
      version: "",
      vendor: "",
    },
    plugins: [],
  });
  if (!result.ok) throw result.error;
  expect(result.value.normalized_result).toMatchObject({
    state: "failed",
    data: {
      request: {
        binary_observation: {
          encoded_chars: 4,
          decoded_bytes: 3,
          sha256: factHash(Buffer.from("abc")),
        },
      },
    },
  });
  expect(JSON.stringify(result.value)).not.toContain("YWJj");
  await service.close();
  await rm(root, { recursive: true });
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
