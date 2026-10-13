import { expect, it } from "vitest";
import { FirmwareCorpusService } from "./FirmwareCorpusService.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import { ok } from "../../domain/result.js";

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
    const connection = { endpoint: explicit!, profile: "source-54aed90b" };
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
