import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:http";
import {
  readFile,
  readdir,
  writeFile,
  rm,
  stat,
  copyFile,
} from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { processTest } from "../../support/process/processFixture.js";

const manifestPath = "tests/fixtures/fact-core/manifest.json";

async function createReadFixture(
  requests: { method: string; path: string }[],
  statusSuccess = false,
) {
  const fixture = JSON.parse(await readFile(manifestPath, "utf8"));
  const object = JSON.parse(
    await readFile("tests/fixtures/fact-core/object.json", "utf8"),
  );
  return createServer((request, response) => {
    const url = new URL(request.url!, "http://127.0.0.1");
    expect(request.headers.authorization).toBeUndefined();
    requests.push({ method: request.method!, path: url.pathname });
    response.setHeader("content-type", "application/json");
    const envelope = {
      status: 0,
      timestamp: 42,
      request_resource: url.pathname,
    };
    let body: unknown;
    if (url.pathname === "/rest/status") {
      response.statusCode = statusSuccess ? 200 : 500;
      body = statusSuccess
        ? {
            ...envelope,
            system_status: { frontend: {}, database: {}, backend: {} },
            plugins: {},
          }
        : {
            message: "Unrelated synthetic status failure",
            finding: "ordinary finding",
          };
    } else if (url.pathname === "/rest/statistics")
      body = Object.fromEntries(
        [
          "architecture",
          "crypto_material",
          "elf_executable",
          "exploit_mitigations",
          "file_type",
          "firmware_meta",
          "general",
          "ips_and_uris",
          "known_vulnerabilities",
          "release_date",
          "software_components",
          "unpacking",
        ].map((key) => [key, {}]),
      );
    else if (url.pathname === "/rest/missing")
      body = { ...envelope, missing_analyses: {}, failed_analyses: {} };
    else if (url.pathname === "/rest/firmware")
      body = {
        ...envelope,
        uids: [fixture.uid],
        request: {
          query: {},
          offset: 0,
          limit: 10,
          recursive: false,
          inverted: false,
        },
      };
    else if (url.pathname === `/rest/firmware/${fixture.uid}`) body = object;
    else if (url.pathname === `/rest/firmware/${fixture.absent_uid}`) {
      response.statusCode = 400;
      body = {
        ...envelope,
        request_resource: "/rest/firmware",
        status: 1,
        error_message: `No firmware with UID ${fixture.absent_uid} found`,
        request: { uid: fixture.absent_uid },
      };
    } else if (url.pathname === `/rest/analysis/${fixture.uid}/dummy`)
      body = {
        ...envelope,
        request_resource: "/rest/analysis",
        request: { uid: fixture.uid, plugin: "dummy" },
        analysis: object.firmware.analysis.dummy,
      };
    else {
      response.statusCode = 405;
      body = { error: "Forbidden test route" };
    }
    response.end(JSON.stringify(body));
  });
}
it("pins the fixture independently of the service response", async () => {
  const bytes = await readFile(manifestPath);
  const fixture = JSON.parse(bytes.toString("utf8"));
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(
    "044ed40a91a0f81d94061c00d959ada2076a3639077e290318725b79a6b80d1c",
  );
  expect(fixture.uid).toBe(
    "418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787",
  );
  expect(fixture.sha256).toBe(
    "418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962",
  );
  expect(fixture.size).toBe(787);
  expect(fixture.source_commit).toBe(
    "54aed90bacb13c484404018101527c72d0bff6c5",
  );
  expect(fixture.absent_uid).not.toBe(fixture.uid);
});
processTest(
  "compares CLI and production stdio MCP frontend readiness without submitting work",
  async ({ processes }) => {
    const privateRoot = await createTestTempDirectory("rea-fact-live-harness-");
    const secret = "fact-live.test+'é";
    const authorizationFile = `${privateRoot}/authorization.txt`;
    await writeFile(authorizationFile, secret, { mode: 0o600 });
    const selectedManifest = `${privateRoot}/canonical-copy.json`;
    await copyFile(manifestPath, selectedManifest);
    const argvLog = `${privateRoot}/argv.jsonl`;
    const entrypoint = `${privateRoot}/rea-wrapper.mjs`;
    await writeFile(
      entrypoint,
      `import { appendFile } from "node:fs/promises";
await appendFile(${JSON.stringify(argvLog)}, JSON.stringify(process.argv) + "\\n", {mode: 0o600});
await import(${JSON.stringify(pathToFileURL(resolve("scripts/rea.mjs")).href)});
`,
    );
    const requests: { method: string; path: string }[] = [];
    const api = await createReadFixture(requests);
    api.listen(0, "127.0.0.1");
    await once(api, "listening");
    const address = api.address();
    if (!address || typeof address === "string") throw Error("Missing address");
    try {
      const result = await processes.run(
        process.execPath,
        [
          "scripts/verify/fact-core/live-rest.mjs",
          "--endpoint",
          `http://127.0.0.1:${address.port}`,
          "--profile",
          "source-54aed90b",
          "--fixture",
          selectedManifest,
          "--entrypoint",
          entrypoint,
        ],
        {
          timeoutMs: 30000,
          env: { PATH: process.env.PATH ?? "", TMPDIR: privateRoot },
        },
      );
      expect(result.exitCode, result.stdout + result.stderr).toBe(0);
      const capturedArgv = (await readFile(argvLog, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as string[]);
      expect(capturedArgv).toHaveLength(8); // Seven CLI invocations plus the real MCP process.
      expect(
        capturedArgv.some((argv) => argv.some((arg) => arg.includes(secret))),
      ).toBe(false);
      expect(
        capturedArgv.some((argv) =>
          argv.some((arg) => arg.includes('"authorization"')),
        ),
      ).toBe(false);
      expect(result.stdout + result.stderr).not.toContain(secret);
      expect(result.stdout + result.stderr).not.toContain(
        Buffer.from(secret, "latin1").toString("hex"),
      );
      expect(result.stdout).toContain("ordinary finding");
      expect((await readdir(privateRoot)).sort()).toEqual([
        "argv.jsonl",
        "authorization.txt",
        "canonical-copy.json",
        "rea-wrapper.mjs",
      ]);
      const report = JSON.parse(result.stdout);
      expect(report).toMatchObject({
        verified: true,
        acceptance_lane: "frontend-only",
        readiness: "read-workflows-completed",
        status_diagnosis: { kind: "generic-http-500", cause: "unverified" },
        fixture_manifest_sha256:
          "044ed40a91a0f81d94061c00d959ada2076a3639077e290318725b79a6b80d1c",
        source_revision_attested: false,
        backend_started_by_harness: false,
        service_backend_state: "unverified",
      });
      expect(report.observations).toHaveLength(7);
      expect(
        report.observations.find(
          (row: { key: string }) => row.key === "status",
        ),
      ).toMatchObject({
        http_status: 500,
        cli: { state: "failed" },
        mcp: { state: "failed" },
      });
      expect(
        report.observations.find(
          (row: { key: string }) => row.key === "absent-object",
        ),
      ).toMatchObject({ cli: { state: "failed" }, mcp: { state: "failed" } });
      expect(report.unverified).toContain("download_corpus_binary");
      expect(report.unverified).toContain("collect_corpus_yara");
      expect(requests).toHaveLength(21);
      expect(requests.every(({ method }) => method === "GET")).toBe(true);
    } finally {
      api.closeAllConnections();
      await new Promise<void>((resolve) => api.close(() => resolve()));
      await rm(privateRoot, { recursive: true, force: true });
    }
  },
  35000,
);

processTest(
  "rejects the retired credential-file option before any child launch",
  async ({ processes }) => {
    const root = await createTestTempDirectory("rea-fact-live-private-error-");
    const secret = "fact-live.synthetic-secret+'é";
    const authorizationFile = `${root}/authorization.txt`;
    const marker = `${root}/spawned.json`;
    const entrypoint = `${root}/probe.mjs`;
    await writeFile(authorizationFile, secret, { mode: 0o600 });
    await writeFile(
      entrypoint,
      `import { writeFile } from "node:fs/promises";
await writeFile(${JSON.stringify(marker)}, JSON.stringify(process.argv));
process.exit(99);
`,
    );
    try {
      const result = await processes.run(
        process.execPath,
        [
          "scripts/verify/fact-core/live-rest.mjs",
          "--endpoint",
          "http://127.0.0.1:1",
          "--profile",
          "source-54aed90b",
          "--fixture",
          manifestPath,
          "--entrypoint",
          entrypoint,
          "--authorization-file",
          authorizationFile,
        ],
        { timeoutMs: 5000 },
      );
      expect(result.exitCode).toBe(1);
      expect(result.stdout + result.stderr).not.toContain(secret);
      await expect(stat(marker)).rejects.toMatchObject({ code: "ENOENT" });
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toEqual({
        verified: false,
        error: "FACT_LIVE_ACCEPTANCE_FAILED",
        phase: "admission",
      });
      expect(await readFile(authorizationFile, "utf8")).toBe(secret);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

processTest(
  "rejects substituted manifests before launching or querying a service",
  async ({ processes }) => {
    const root = await createTestTempDirectory("rea-fact-manifest-admission-");
    let calls = 0;
    const api = createServer((_request, response) => {
      calls++;
      response.end("{}");
    });
    api.listen(0, "127.0.0.1");
    await once(api, "listening");
    const address = api.address();
    if (!address || typeof address === "string") throw Error("Missing address");
    const canonical = JSON.parse(await readFile(manifestPath, "utf8"));
    const marker = `${root}/spawned.json`;
    const entrypoint = `${root}/probe.mjs`;
    await writeFile(
      entrypoint,
      `import { writeFile } from "node:fs/promises";
await writeFile(${JSON.stringify(marker)}, JSON.stringify(process.argv));
process.exit(99);
`,
    );
    const alternatives = [
      {
        ...canonical,
        uid: `${"b".repeat(64)}_4`,
        sha256: "b".repeat(64),
        size: 4,
      },
      { ...canonical, source_path: "src/test/data/container/other.zip" },
      { ...canonical, absent_uid: `${"c".repeat(64)}_5` },
    ];
    try {
      for (const [index, manifest] of alternatives.entries()) {
        const selected = `${root}/manifest-${index}.json`;
        await writeFile(selected, JSON.stringify(manifest));
        const result = await processes.run(
          process.execPath,
          [
            "scripts/verify/fact-core/live-rest.mjs",
            "--endpoint",
            `http://127.0.0.1:${address.port}`,
            "--profile",
            "source-54aed90b",
            "--fixture",
            selected,
            "--entrypoint",
            entrypoint,
          ],
          { timeoutMs: 5000 },
        );
        expect(result.exitCode).toBe(1);
        expect(JSON.parse(result.stdout)).toEqual({
          verified: false,
          error: "FACT_LIVE_ACCEPTANCE_FAILED",
          phase: "admission",
        });
        await expect(stat(marker)).rejects.toMatchObject({ code: "ENOENT" });
        expect(calls).toBe(0);
      }
    } finally {
      api.closeAllConnections();
      await new Promise<void>((resolve) => api.close(() => resolve()));
      await rm(root, { recursive: true, force: true });
    }
  },
);

processTest(
  "settles both failing MCP closes and private HOME after success or operation failure",
  async ({ processes }) => {
    for (const operationFails of [false, true]) {
      const root = await createTestTempDirectory("rea-fact-close-fault-");
      const log = `${root}/closes.log`;
      const preload = `${root}/close-fault.mjs`;
      const secret = "synthetic-private-close-diagnostic";
      await writeFile(
        preload,
        `
import { appendFile } from "node:fs/promises";
import { Client } from ${JSON.stringify(import.meta.resolve("@modelcontextprotocol/client"))};
import { StdioClientTransport } from ${JSON.stringify(import.meta.resolve("@modelcontextprotocol/client/stdio"))};
const transportClose = StdioClientTransport.prototype.close;
StdioClientTransport.prototype.close = async function () {
  await appendFile(${JSON.stringify(log)}, "transport\\n");
  await transportClose.call(this);
  throw new Error(${JSON.stringify(secret)} + "-transport");
};
const clientClose = Client.prototype.close;
Client.prototype.close = async function () {
  await appendFile(${JSON.stringify(log)}, "client\\n");
  try { await clientClose.call(this); } catch {}
  throw new Error(${JSON.stringify(secret)} + "-client");
};
`,
      );
      const requests: { method: string; path: string }[] = [];
      const api = await createReadFixture(requests, operationFails);
      api.listen(0, "127.0.0.1");
      await once(api, "listening");
      const address = api.address();
      if (!address || typeof address === "string")
        throw Error("Missing address");
      try {
        const result = await processes.run(
          process.execPath,
          [
            "--import",
            preload,
            "scripts/verify/fact-core/live-rest.mjs",
            "--endpoint",
            `http://127.0.0.1:${address.port}`,
            "--profile",
            "source-54aed90b",
            "--fixture",
            manifestPath,
          ],
          {
            timeoutMs: 30000,
            env: { PATH: process.env.PATH ?? "", TMPDIR: root },
          },
        );
        expect(result.exitCode).toBe(1);
        expect(result.stdout + result.stderr).not.toContain(secret);
        expect(result.stderr).toBe("");
        const report = JSON.parse(result.stdout);
        expect(report).toMatchObject({
          verified: false,
          phase: operationFails ? "status" : "cleanup",
          cleanup: {
            attempted: ["client", "transport", "process", "home"],
            failed: ["client", "transport"],
            operation_failed: operationFails,
          },
        });
        expect(report.observations).toHaveLength(operationFails ? 0 : 7);
        expect((await readdir(root)).sort()).toEqual([
          "close-fault.mjs",
          "closes.log",
        ]);
        expect((await readFile(log, "utf8")).trim().split("\n")).toEqual([
          "client",
          "transport",
          "transport",
        ]);
      } finally {
        await new Promise<void>((resolve) => api.close(() => resolve()));
        await rm(root, { recursive: true, force: true });
      }
    }
  },
  65000,
);

processTest(
  "retains exact primary and cleanup errors privately while removing HOME",
  async ({ processes }) => {
    const result = await processes.run(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `
import assert from "node:assert/strict";
import { mkdtemp, stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { settleLiveRestResources } from "./scripts/verify/fact-core/live-rest-resources.mjs";
const home = await mkdtemp(tmpdir() + "/rea-fact-owner-");
const primary = new Error("private operation body");
const clientError = new Error("private client body");
const transportError = new Error("private transport body");
const client = { close: async () => { throw clientError; } };
const transport = { close: async () => { throw transportError; } };
try {
const result = await settleLiveRestResources({ client, transport, temporary: home, primaryError: primary, operationFailed: true });
assert(result.error instanceof AggregateError);
assert.equal(result.error.cause, primary);
assert.deepEqual(result.error.errors, [primary, clientError, transportError]);
assert.equal(result.failures[0].owner, client);
assert.equal(result.failures[1].owner, transport);
assert.deepEqual(result.attempted, ["client", "transport", "home"]);
await assert.rejects(stat(home), { code: "ENOENT" });
const pendingOwner = {
  stop: async () => ({ status: "incomplete", reason: "private stop reason" }),
  observedExit: () => undefined,
};
const pending = await settleLiveRestResources({ processOwner: pendingOwner });
assert.equal(pending.failures.length, 1);
assert.equal(pending.failures[0].owner, pendingOwner);
assert.equal(pending.failures[0].resource, "process");
assert.deepEqual(pending.process, { status: "incomplete", exited: false });
assert(!JSON.stringify(pending.process).includes("private stop reason"));
console.log(JSON.stringify({ retained_errors: result.error.errors.length, home_removed: true }));
} finally { await rm(home, { recursive: true, force: true }); }
`,
      ],
      { timeoutMs: 10000 },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      retained_errors: 3,
      home_removed: true,
    });
  },
);

processTest(
  "recovers the exact spawned MCP child when transport close rejects before stopping it",
  async ({ processes }) => {
    const root = await createTestTempDirectory("rea-fact-preclose-");
    const preload = `${root}/preclose.mjs`;
    const childReceipt = `${root}/child.json`;
    const watchdogReceipt = `${root}/watchdog.json`;
    const secret = "synthetic-private-before-close";
    await writeFile(
      preload,
      `
import { writeFileSync } from "node:fs";
import { StdioClientTransport } from ${JSON.stringify(import.meta.resolve("@modelcontextprotocol/client/stdio"))};
const start = StdioClientTransport.prototype.start;
StdioClientTransport.prototype.start = async function () {
  await start.call(this);
  const child = this._process;
  if (!child) throw new Error("Test SDK child not captured");
  const receipt = { pid: child.pid, exited: false };
  writeFileSync(${JSON.stringify(childReceipt)}, JSON.stringify(receipt));
  const watchdog = setTimeout(() => {
    writeFileSync(${JSON.stringify(watchdogReceipt)}, JSON.stringify({ fired: true }));
    process.exitCode = 124;
    child.kill("SIGKILL");
  }, 10000);
  watchdog.unref();
  child.once("exit", (code, signal) => {
    clearTimeout(watchdog);
    writeFileSync(${JSON.stringify(childReceipt)}, JSON.stringify({ ...receipt, exited: true, code, signal }));
  });
};
StdioClientTransport.prototype.close = async function () {
  throw new Error(${JSON.stringify(secret)});
};
`,
    );
    const requests: { method: string; path: string }[] = [];
    const api = await createReadFixture(requests, true);
    api.listen(0, "127.0.0.1");
    await once(api, "listening");
    const address = api.address();
    if (!address || typeof address === "string") throw Error("Missing address");
    try {
      const result = await processes.run(
        process.execPath,
        [
          "--import",
          preload,
          "scripts/verify/fact-core/live-rest.mjs",
          "--endpoint",
          `http://127.0.0.1:${address.port}`,
          "--profile",
          "source-54aed90b",
          "--fixture",
          manifestPath,
        ],
        {
          timeoutMs: 15000,
          env: { PATH: process.env.PATH ?? "", TMPDIR: root },
        },
      );
      expect(result.stdout + result.stderr).not.toContain(secret);
      expect(result.stderr).toBe("");
      expect(result.exitCode).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report).toMatchObject({
        verified: false,
        phase: "status",
        cleanup: {
          failed: ["client", "transport"],
          operation_failed: true,
          process: { status: "terminated", exited: true },
        },
      });
      const child = JSON.parse(await readFile(childReceipt, "utf8"));
      expect(child.exited).toBe(true);
      expect(child.code !== null || child.signal !== null).toBe(true);
      await expect(stat(`/proc/${child.pid}`)).rejects.toMatchObject({
        code: "ENOENT",
      });
      await expect(stat(watchdogReceipt)).rejects.toMatchObject({
        code: "ENOENT",
      });
      expect((await readdir(root)).sort()).toEqual([
        "child.json",
        "preclose.mjs",
      ]);
    } finally {
      api.closeAllConnections();
      await new Promise<void>((resolve) => api.close(() => resolve()));
      await rm(root, { recursive: true, force: true });
    }
  },
  20000,
);

processTest(
  "binds SDK 2.3.1 direct-child ownership and escalates a TERM-resistant child within bounded recovery",
  async ({ processes }) => {
    const result = await processes.run(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `
import assert from "node:assert/strict";
import { once } from "node:events";
import { OwnedLiveRestTransport } from "./scripts/verify/fact-core/live-rest-process.mjs";
import { readFile } from "node:fs/promises";
const sdk = JSON.parse(await readFile(new URL("../package.json", import.meta.resolve("@modelcontextprotocol/client/stdio")), "utf8"));
assert.equal(sdk.version, "2.3.1");
const transport = new OwnedLiveRestTransport({
  command: process.execPath,
  args: ["-e", 'process.on("SIGTERM", () => {}); process.stderr.write("ready"); setInterval(() => {}, 1000);'],
  stderr: "pipe",
});
const ready = once(transport.stderr, "data");
try {
  await transport.start();
  await ready;
  const owner = transport.processOwner;
  assert(owner);
  assert.equal(owner.launch.process, transport._process);
  assert.equal(owner.launch.process.pid, transport.pid);
  assert.equal(owner.launch.ownsProcessLifetime, true);
  const stopped = await owner.stop({ terminationGraceMs: 50, killGraceMs: 1000 });
  assert.equal(stopped.status, "killed");
  assert.deepEqual(owner.observedExit(), { code: null, signal: "SIGKILL" });
  assert.equal((await owner.stop()).status, "killed");
  console.log(JSON.stringify({ ownership: "original-spawned-child", recovered: true }));
} finally { await transport.close(); }
`,
      ],
      { timeoutMs: 5000 },
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual({
      ownership: "original-spawned-child",
      recovered: true,
    });
  },
);
