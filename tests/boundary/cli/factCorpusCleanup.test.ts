import { Cli } from "incur";
import { afterEach, expect, it } from "vitest";
import { silentLogger } from "../../../src/logger.js";
import { registerFirmwareCorpusCommands } from "../../../src/cli/firmwareCorpusCommands.js";
import { FirmwareCorpusService } from "../../../src/application/corpus/FirmwareCorpusService.js";
import { createAnalysisExecution } from "../../../src/application/AnalysisProvider.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { ok } from "../../../src/domain/result.js";

afterEach(() => {
  process.exitCode = 0;
});
it("retains completed corpus Evidence when one-shot cleanup fails before delivery", async () => {
  const result = {
    state: "completed",
    endpoint: "http://127.0.0.1",
    profile: "source-54aed90b",
    http_status: 200,
    observed_at: "fixture",
    raw_sha256: null,
    coverage: "producer-response",
    data: { finding: "postgres is ordinary text" },
    diagnostics: [],
  };
  let closed = false,
    calls = 0;
  const service = new FirmwareCorpusService({
    async execute() {
      calls++;
      return ok(
        createAnalysisExecution(result, {
          id: "fixture",
          name: "Boundary fixture",
          version: null,
        }),
      );
    },
    async close() {
      closed = true;
      throw new ProviderCleanupError(
        "fixture",
        ["owned-parser"],
        {},
        { operation: "inspect_firmware_corpus" },
      );
    },
  });
  const cli = Cli.create("corpus-cleanup-test", { sync: false });
  registerFirmwareCorpusCommands(cli, silentLogger, () => service);
  let stdout = "";
  await cli.serve(
    [
      "inspect-firmware-corpus",
      JSON.stringify({
        connection: {
          endpoint: "http://127.0.0.1",
          profile: "source-54aed90b",
        },
      }),
      "--json",
    ],
    {
      stdout: (text) => {
        expect(closed).toBe(true);
        stdout += text;
      },
      exit: () => {},
    },
  );
  expect(calls).toBe(1);
  expect(process.exitCode).toBe(1);
  expect(JSON.parse(stdout)).toMatchObject({
    code: "cleanup_incomplete",
    details: {
      resources: ["owned-parser"],
      partial_observation: {
        subject: null,
        operation: "inspect_firmware_corpus",
        normalized_result: result,
      },
    },
  });
});
