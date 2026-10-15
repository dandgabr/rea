import { fc, it } from "@fast-check/vitest";
import { expect } from "vitest";
import { corpusConnectionSchema } from "./firmwareCorpus.js";
import { firmwareCorpusInputs } from "./firmwareCorpus.js";
const native = {
  interpreter: "/usr/local/bin/python3",
  checkout: "/data/fact-source",
  profile: "source-54aed90b",
  uids: ["a".repeat(64) + "_1"],
  output_directory: "/host/output",
};
const runtime = {
  kind: "podman-existing",
  podman: "/usr/bin/podman",
  container_id: "a".repeat(64),
  image_id: "b".repeat(64),
  existing_store_profile: "/host/profile.json",
  staging_parent: "/data/staging",
};
it("admits explicit existing-container native export authority", () => {
  expect(
    firmwareCorpusInputs.export_corpus_firmware.parse({ ...native, runtime }),
  ).toMatchObject({
    ...native,
    runtime: { ...runtime, namespace_prlimit: "/usr/bin/prlimit" },
  });
});
it.each([
  { container_id: "alias" },
  { image_id: "latest" },
  { podman: "podman" },
  { staging_parent: "/data/../caller" },
  { namespace_prlimit: "/usr/bin/prlimit\0" },
  { args: ["stop"] },
  { environment: { HOME: "/human" } },
  { kind: "container" },
])("refuses unsupported export runtime selectors %j", (invalid) => {
  expect(
    firmwareCorpusInputs.export_corpus_firmware.safeParse({
      ...native,
      runtime: { ...runtime, ...invalid },
    }).success,
  ).toBe(false);
});

it("does not publish FACT operations outside the recorded authority scope", () => {
  for (const operation of [
    "upload_corpus_firmware",
    "reanalyze_corpus_firmware",
    "enqueue_corpus_analysis",
    "start_corpus_yara",
    "delete_corpus_firmware",
  ])
    expect(Object.hasOwn(firmwareCorpusInputs, operation), operation).toBe(
      false,
    );
});

it.prop([fc.string({ maxLength: 512 })])(
  "keeps arbitrary endpoint text inside the literal-loopback connection contract",
  (endpoint) => {
    const parsed = corpusConnectionSchema.safeParse({
      endpoint,
      profile: "source-54aed90b",
      authorization: "test",
    });
    if (parsed.success)
      expect([
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://[::1]",
        "https://[::1]",
      ]).toContain(
        parsed.data.endpoint.replace(/:\\d+\/?$/u, "").replace(/\/$/u, ""),
      );
  },
);
