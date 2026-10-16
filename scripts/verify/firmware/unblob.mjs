import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { firmwareResultSchemas } from "../../../dist/domain/firmware/firmwareAnalysis.js";
import { parseEvidence } from "../../../dist/domain/evidence.js";
import { hashFirmwareFile } from "../../../dist/firmware/FirmwareFiles.js";
import {
  assertOracleOutputFiles,
  closeClientAndRemoveWorkspace,
  runWithCleanup,
} from "./acceptanceSupport.mjs";
import { assertRequiredDependencies } from "./dependencyGate.mjs";

const exec = promisify(execFile);
const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const entrypoint = resolve(
  process.env.REA_FIRMWARE_TEST_ENTRYPOINT ??
    join(repository, "scripts/rea.mjs"),
);
if (process.platform !== "linux")
  throw new Error(
    "verify:unblob-firmware requires Linux; other hosts are not verified",
  );
for (const variable of ["REA_UNBLOB_RUNTIME_ROOT", "REA_UNBLOB_COMMAND"]) {
  const path = process.env[variable];
  if (path === undefined)
    throw new Error(
      `verify:unblob-firmware requires ${variable}; see docs/firmware-analysis.md`,
    );
  await access(path);
}

const fixtureRoot = resolve(
  process.env.REA_FIRMWARE_FIXTURE_ROOT ??
    join(repository, "_reference/firmware-integration/generated"),
);
const oracle = JSON.parse(
  await readFile(join(fixtureRoot, "oracle.json"), "utf8"),
);
const input = join(fixtureRoot, "firmware.bin");
assert.equal(await hashFirmwareFile(input), oracle.sha256);

const workspace = await mkdtemp(join(tmpdir(), "rea-unblob-acceptance-"));
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => value !== undefined),
);
const client = new Client({ name: "rea-unblob-verifier", version: "1" });
const cli = async (args) => {
  const { stdout } = await exec(
    process.execPath,
    [entrypoint, ...args, "--format", "json"],
    {
      env: environment,
      cwd: repository,
      timeout: 150_000,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  return parseEvidence(JSON.parse(stdout));
};
const call = async (name, args) => {
  const response = await client.callTool(
    { name, arguments: args },
    { timeout: 150_000 },
  );
  assert.notEqual(response.isError, true, JSON.stringify(response));
  assert.ok(response.structuredContent !== undefined);
  return response.structuredContent;
};
const requireSevenZip = (evidence) => {
  const inventory = firmwareResultSchemas.inspect_firmware_provider.parse(
    evidence.normalized_result,
  );
  assertRequiredDependencies(inventory, ["7z"]);
};
const verifyScan = (evidence) => {
  assert.equal(evidence.operation, "inspect_firmware_regions");
  assert.equal(evidence.provider.id, "unblob");
  assert.equal(evidence.subject.digest.sha256, oracle.sha256);
  const result = firmwareResultSchemas.inspect_firmware_regions.parse(
    evidence.normalized_result,
  );
  assert.equal(result.coverage, "partial");
  assert.ok(result.chunks.some((chunk) => chunk.handler === "gzip"));
  return result;
};
const verifyExtraction = async (evidence) => {
  assert.equal(evidence.operation, "extract_firmware");
  assert.equal(evidence.provider.id, "unblob");
  assert.equal(evidence.subject.digest.sha256, oracle.sha256);
  const result = firmwareResultSchemas.extract_firmware.parse(
    evidence.normalized_result,
  );
  assert.equal(result.coverage, "partial");
  assert.ok(result.chunks.some((chunk) => chunk.handler === "gzip"));
  assert.ok(
    !result.diagnostics.some(
      (diagnostic) =>
        typeof diagnostic === "object" &&
        diagnostic !== null &&
        "missing_dependencies" in diagnostic &&
        Array.isArray(diagnostic.missing_dependencies) &&
        diagnostic.missing_dependencies.includes("7z"),
    ),
    "Fixture extraction reported its required 7z dependency missing",
  );
  await assertOracleOutputFiles(
    result.files,
    oracle.unblob_files,
    oracle.unblob_output_root,
    hashFirmwareFile,
  );
  for (const [suffix, expected] of Object.entries(oracle.files)) {
    const expectedPath = `${oracle.unblob_output_root}/64-${oracle.offset + oracle.length}.gzip_extract/gzip.uncompressed_extract/${suffix}`;
    const file = result.files.find(
      (candidate) => candidate.relative_path === expectedPath,
    );
    assert.ok(file !== undefined, `Missing extracted ${expectedPath}`);
    assert.equal(file.size, expected.size);
    assert.equal(file.sha256, expected.sha256);
    assert.equal(file.original_file_range, null);
    assert.equal(file.runtime_address, null);
  }
  return result.files.map((file) => ({
    relative_path: file.relative_path.slice(
      oracle.unblob_output_root.length + 1,
    ),
    sha256: file.sha256,
    size: file.size,
  }));
};

await runWithCleanup(
  async () => {
    requireSevenZip(
      await cli(["inspect-firmware-provider", "--provider-id", "unblob"]),
    );
    const inspected = await cli([
      "inspect-firmware-regions",
      input,
      "--provider-id",
      "unblob",
    ]);
    verifyScan(inspected);
    const cliFiles = await verifyExtraction(
      await cli([
        "extract-firmware",
        input,
        join(workspace, "cli-output"),
        "--workers",
        "3",
      ]),
    );

    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [entrypoint, "mcp"],
        cwd: repository,
        env: environment,
        stderr: "pipe",
      }),
      { timeout: 30_000 },
    );
    requireSevenZip(
      parseEvidence(
        await call("inspect_firmware_provider", { provider_id: "unblob" }),
      ),
    );
    verifyScan(
      parseEvidence(
        await call("inspect_firmware_regions", {
          provider_id: "unblob",
          path: input,
          options: { workers: 3 },
        }),
      ),
    );
    const mcpFiles = await verifyExtraction(
      parseEvidence(
        await call("extract_firmware", {
          provider_id: "unblob",
          path: input,
          output_directory: join(workspace, "mcp-output"),
          options: { workers: 3 },
        }),
      ),
    );
    assert.deepEqual(mcpFiles, cliFiles);
    console.log(
      "PASS real Unblob CLI/MCP: provider inventory, scan, extraction and independent oracle hashes",
    );
  },
  async () =>
    closeClientAndRemoveWorkspace(
      () => client.close(),
      workspace,
      (path) => rm(path, { recursive: true, force: true }),
    ),
);
