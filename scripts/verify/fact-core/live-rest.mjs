#!/usr/bin/env node
// Unauthenticated frontend-only acceptance. No credential input or service provisioning.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { parseArgs, promisify, isDeepStrictEqual } from "node:util";
import { performance } from "node:perf_hooks";
import { Client } from "@modelcontextprotocol/client";
import { OwnedLiveRestTransport } from "./live-rest-process.mjs";
import { corpusConnectionSchema } from "../../../dist/domain/corpus/firmwareCorpus.js";
import { parseEvidence } from "../../../dist/domain/evidence.js";
import {
  FACT_LIMITS,
  FactResponseResources,
  readFactResponse,
  factHash,
} from "../../../dist/firmware/fact/FactProtocol.js";

import { settleLiveRestResources } from "./live-rest-resources.mjs";

const FIXTURE_MANIFEST_SHA256 =
  "044ed40a91a0f81d94061c00d959ada2076a3639077e290318725b79a6b80d1c";
const FIXTURE_UID =
  "418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787";
const FIXTURE_SHA256 =
  "418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962";
const execute = promisify(execFile);
const started = performance.now(),
  cpu = process.cpuUsage();
let client, transport, temporary, report, primaryError;
let operationFailed = false;
const observations = [];
let phase = "admission";
try {
  const { values } = parseArgs({
    options: {
      endpoint: { type: "string" },
      profile: { type: "string" },
      fixture: { type: "string" },
      entrypoint: { type: "string", default: "scripts/rea.mjs" },
    },
  });
  const connection = corpusConnectionSchema.parse({
    endpoint: values.endpoint,
    profile: values.profile,
  });
  assert.equal(connection.profile, "source-54aed90b");
  assert.ok(values.fixture);
  const fixtureBytes = await readFile(values.fixture);
  const fixtureManifestSha256 = factHash(fixtureBytes);
  assert.equal(fixtureManifestSha256, FIXTURE_MANIFEST_SHA256);
  const fixture = JSON.parse(fixtureBytes.toString("utf8"));
  assert.equal(
    fixture.source_commit,
    "54aed90bacb13c484404018101527c72d0bff6c5",
  );
  assert.equal(fixture.profile, connection.profile);
  assert.equal(fixture.uid, FIXTURE_UID);
  assert.equal(fixture.sha256, FIXTURE_SHA256);
  assert.equal(fixture.size, 787);
  // A fixture cannot turn this GET-result check into an arbitrary plugin/route.
  assert.equal(fixture.analysis_plugin, "dummy");
  assert.deepEqual(fixture.analysis_result, { content: "abcd" });
  temporary = await mkdtemp(`${tmpdir()}/rea-fact-live-`);
  const env = {
    PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
    HOME: temporary,
    REA_LOG_LEVEL: "silent",
    NO_COLOR: "1",
  };
  const entrypoint = resolve(values.entrypoint);
  transport = new OwnedLiveRestTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  client = new Client({ name: "fact-live-rest-acceptance", version: "1" });
  await client.connect(transport);
  const selected = [
    ["status", "inspect_firmware_corpus", {}, "/rest/status"],
    ["statistics", "inspect_corpus_statistics", {}, "/rest/statistics"],
    [
      "search",
      "search_corpus_objects",
      { kind: "firmware", query: {}, offset: 0, limit: 10 },
      "/rest/firmware?query=%7B%7D&offset=0&limit=10&recursive=false&inverted=false",
    ],
    ["gaps", "inspect_corpus_gaps", {}, "/rest/missing"],
    [
      "object",
      "inspect_corpus_object",
      { kind: "firmware", uid: fixture.uid },
      `/rest/firmware/${fixture.uid}`,
    ],
    [
      "analysis",
      "inspect_corpus_analysis",
      { uid: fixture.uid, plugin: "dummy" },
      `/rest/analysis/${fixture.uid}/dummy`,
    ],
    [
      "absent-object",
      "inspect_corpus_object",
      { kind: "firmware", uid: fixture.absent_uid },
      `/rest/firmware/${fixture.absent_uid}`,
    ],
  ];
  for (const [key, operation, selection, path] of selected) {
    phase = key;
    const resources = new FactResponseResources();
    let http;
    try {
      const signal = AbortSignal.timeout(15000);
      const response = await fetch(new URL(path, connection.endpoint), {
        method: "GET",
        redirect: "error",
        signal,
      });
      const bytes = await readFactResponse(
        response,
        FACT_LIMITS.jsonBytes,
        signal,
        resources,
      );
      http = {
        http_status: response.status,
        content_type: response.headers.get("content-type"),
        raw_sha256: factHash(bytes),
        bytes: bytes.length,
      };
    } finally {
      await resources.close();
    }
    const input = { connection, ...selection };
    let cli;
    try {
      const result = await execute(
        process.execPath,
        [
          entrypoint,
          operation.replaceAll("_", "-"),
          JSON.stringify(input),
          "--json",
        ],
        { env, timeout: 20000, maxBuffer: 16 * 1024 * 1024 },
      );
      cli = {
        exit_code: 0,
        evidence: parseEvidence(JSON.parse(result.stdout)),
      };
    } catch (cause) {
      assert.ok(cause && (cause.code === 1 || cause.code === 130));
      cli = {
        exit_code: cause.code,
        evidence: parseEvidence(JSON.parse(cause.stdout)),
      };
    }
    const answer = await client.callTool(
      { name: operation, arguments: input },
      { timeout: 20000 },
    );
    const mcp = parseEvidence(answer.structuredContent);
    for (const evidence of [cli.evidence, mcp]) {
      assert.equal(evidence.subject, null);
      assert.equal(evidence.authority, "external-service");
      assert.equal(evidence.operation, operation);
      assert.equal(evidence.normalized_result.http_status, http.http_status);
      if (key === "status") {
        assert.equal(http.http_status, 500);
        assert.equal(evidence.normalized_result.state, "failed");
        assert.ok(!Object.hasOwn(evidence.normalized_result.data, "plugins"));
      } else if (key === "absent-object") {
        assert.equal(evidence.normalized_result.state, "failed");
        assert.match(
          evidence.normalized_result.data.error_message,
          /^No firmware with UID /u,
        );
        assert.equal(
          evidence.normalized_result.data.request.uid,
          fixture.absent_uid,
        );
        assert.ok(!Object.hasOwn(evidence.normalized_result.data, "firmware"));
      } else {
        assert.equal(http.http_status, 200);
        assert.equal(evidence.normalized_result.state, "completed");
      }
      const data = evidence.normalized_result.data;
      if (key === "object") {
        assert.equal(data.request.uid, fixture.uid);
        assert.equal(data.firmware.meta_data.size, fixture.size);
      }
      if (key === "search") assert.deepEqual(data.uids, [fixture.uid]);
      if (key === "analysis") {
        assert.equal(data.request.uid, fixture.uid);
        assert.equal(data.request.plugin, "dummy");
        assert.ok(
          isDeepStrictEqual(data.analysis.result, fixture.analysis_result),
        );
      }
    }
    assert.equal(
      cli.exit_code,
      key === "status" || key === "absent-object" ? 1 : 0,
    );
    const row = {
      key,
      operation,
      method: "GET",
      path,
      ...http,
      cli: cli.evidence.normalized_result,
      mcp: mcp.normalized_result,
      cli_exit_code: cli.exit_code,
      evidence_ids: [cli.evidence.evidence_id, mcp.evidence_id],
    };
    observations.push(row);
  }
  report = {
    verified: true,
    acceptance_lane: "frontend-only",
    readiness: "read-workflows-completed",
    status_diagnosis: { kind: "generic-http-500", cause: "unverified" },
    backend_started_by_harness: false,
    service_backend_state: "unverified",
    source_revision_attested: false,
    declared_profile: connection.profile,
    fixture_manifest_sha256: fixtureManifestSha256,
    expected_fixture: fixture,
    observations,
    unverified: [
      "download_corpus_binary",
      "collect_corpus_yara",
      "inspect_corpus_comparison",
      "inspect_corpus_parent_analysis",
      "export_corpus_firmware",
      "backend_runtime_isolation",
    ],
    measurement: {
      elapsed_ms: performance.now() - started,
      harness_cpu_us: process.cpuUsage(cpu),
      harness_max_rss_kib: process.resourceUsage().maxRSS,
      process_family_cpu_and_peak_memory: "unmeasured",
      token_usage: "unmeasured",
      comparison_baseline: "unmeasured",
      cli_processes: "fresh process per operation",
      mcp_session: "one initialization followed by sequential calls",
      operating_system_and_service_cache: "uncontrolled",
    },
  };
} catch (error) {
  // Retain the actual cause privately; subprocess bodies never enter diagnostics.
  operationFailed = true;
  primaryError = error;
  report = {
    verified: false,
    error: "FACT_LIVE_ACCEPTANCE_FAILED",
    phase,
  };
} finally {
  const settled = await settleLiveRestResources({
    client,
    transport,
    temporary,
    primaryError,
    operationFailed,
    processOwner: transport?.processOwner,
  });
  if (settled.failures.length > 0) {
    report = {
      ...report,
      verified: false,
      error: "FACT_LIVE_ACCEPTANCE_FAILED",
      phase: operationFailed ? phase : "cleanup",
      observations,
      cleanup: {
        attempted: settled.attempted,
        failed: settled.failures.map(({ resource }) => resource),
        operation_failed: operationFailed,
        ...(settled.process ? { process: settled.process } : {}),
      },
    };
  }
  // One report only, after every owner has had its cleanup attempt. The retained
  // AggregateError and failed owners remain private, including on terminal exit.
  if (report.measurement) {
    report.measurement.elapsed_ms = performance.now() - started;
    report.measurement.harness_cpu_us = process.cpuUsage(cpu);
    report.measurement.harness_max_rss_kib = process.resourceUsage().maxRSS;
  }
  if (!report.verified) process.exitCode = 1;
  console.log(JSON.stringify(report));
}
