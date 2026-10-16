import { expect, it } from "vitest";
import { FirmwareCorpusService } from "./FirmwareCorpusService.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import { ok } from "../../domain/result.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import type { FirmwareCorpusOperation } from "../../domain/corpus/firmwareCorpus.js";

it("uses canonical default-port identity while retaining the first caller's display endpoint", async () => {
  let calls = 0;
  const service = new FirmwareCorpusService({
    async execute() {
      calls++;
      return ok(
        createAnalysisExecution(
          { captured: true },
          { id: "fact-core", name: "FACT Core", version: null },
        ),
      );
    },
  });
  for (const [explicit, canonical] of [
    ["http://127.0.0.1:80/", "http://127.0.0.1"],
    ["https://[::1]:443/", "https://[::1]"],
  ]) {
    const connection = { endpoint: explicit, profile: "source-54aed90b" };
    const first = await service.execute("collect_corpus_yara", {
      connection,
      search_id: "same",
    });
    const alias = await service.execute("collect_corpus_yara", {
      connection: { ...connection, endpoint: canonical },
      search_id: "same",
    });
    if (!first.ok) throw first.error;
    if (!alias.ok) throw alias.error;
    expect(alias.value).toBe(first.value);
    expect(first.value.parameters).toMatchObject({
      connection: { endpoint: explicit },
    });
  }
  expect(calls).toBe(2);
  await service.close();
});

it("refuses excluded FACT operations before provider dispatch, including removed runtime names", async () => {
  let calls = 0;
  const service = new FirmwareCorpusService({
    async execute() {
      calls++;
      throw Error("excluded operations reached provider dispatch");
    },
  });
  for (const operation of [
    "upload_corpus_firmware",
    "reanalyze_corpus_firmware",
    "enqueue_corpus_analysis",
    "start_corpus_comparison",
    "start_corpus_yara",
    "delete_corpus_firmware",
    "import_corpus_firmware",
  ]) {
    const result = await service.execute(
      operation as FirmwareCorpusOperation,
      {},
    );
    expect(result.ok, operation).toBe(false);
    if (!result.ok)
      expect(result.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
  }
  expect(calls).toBe(0);
  await service.close();
});

it("reserves aggregate YARA Evidence capacity before consuming and bounds retained identifiers", async () => {
  let calls = 0;
  const service = new FirmwareCorpusService({
    async execute() {
      calls++;
      return ok(
        createAnalysisExecution(
          { captured: true },
          { id: "fact-core", name: "FACT Core", version: null },
        ),
      );
    },
  });
  const connection = {
    endpoint: "http://127.0.0.1:5000",
    profile: "source-54aed90b" as const,
  };
  try {
    for (let index = 0; index < 7; index++) {
      const result = await service.execute("collect_corpus_yara", {
        connection,
        search_id: `search-${index}`,
      });
      expect(result.ok).toBe(true);
    }
    const full = await service.execute("collect_corpus_yara", {
      connection,
      search_id: "search-7",
    });
    expect(full.ok).toBe(false);
    if (!full.ok) {
      expect(full.error).toBeInstanceOf(AnalysisResourceConstraintError);
      expect(full.error).toMatchObject({ resource: "capacity" });
    }
    expect(calls).toBe(7);

    const retained = await service.execute("collect_corpus_yara", {
      connection,
      search_id: "search-0",
    });
    expect(retained.ok).toBe(true);
    expect(calls).toBe(7);

    const oversizedId = await service.execute("collect_corpus_yara", {
      connection,
      search_id: "x".repeat(1025),
    });
    expect(oversizedId.ok).toBe(false);
    if (!oversizedId.ok)
      expect(oversizedId.error).toMatchObject({ resource: "capacity" });
    expect(calls).toBe(7);
  } finally {
    await service.close();
  }
});
