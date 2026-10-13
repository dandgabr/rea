import { expect, it } from "vitest";
import { normalizeUnblobReport } from "./FirmwareReports.js";
import { firmwareExtractionGaps } from "./FirmwareExtractionGaps.js";

const normalize = (extra: unknown[]) =>
  normalizeUnblobReport(
    [
      {
        task: {
          path: "/input/fw",
          depth: 0,
          blob_id: "",
          is_multi_file: false,
        },
        reports: [
          {
            __typename__: "StatReport",
            path: "/input/fw",
            size: 1024,
            is_file: true,
            is_dir: false,
            is_link: false,
            link_target: null,
          },
          { __typename__: "HashReport", sha256: "a".repeat(64) },
          {
            __typename__: "FileMagicReport",
            magic: "data",
            mime_type: "application/octet-stream",
          },
          ...extra,
        ],
        subtasks: [],
      },
    ],
    {
      inputPath: "/input/fw",
      outputRoot: "/work/output",
      sha256: "a".repeat(64),
      length: 1024,
      offset: 64,
      maxDepth: 3,
    },
  );

it("retains an informational custom extraction report without asserting an extractor failure", () => {
  const observed = normalize([
    {
      __typename__: "ChunkReport",
      id: "custom",
      start_offset: 0,
      end_offset: 1024,
      size: 1024,
      handler_name: "trusted",
      is_encrypted: false,
      extraction_reports: [
        { __typename__: "TrustedInfo", note: "producer information" },
      ],
    },
  ]);
  expect(observed.chunks[0]?.extraction_failed).toBe(false);
  expect(firmwareExtractionGaps(observed, 3)).toEqual([]);
  expect(observed.diagnostics).toHaveLength(1);
});

it("retains unknown and encrypted regions with original correspondence only for the root", () => {
  const observed = normalize([
    {
      __typename__: "UnknownChunkReport",
      id: "u",
      start_offset: 0,
      end_offset: 512,
      size: 512,
      randomness: null,
    },
    {
      __typename__: "ChunkReport",
      id: "e",
      start_offset: 512,
      end_offset: 1024,
      size: 512,
      handler_name: "zip",
      is_encrypted: true,
      extraction_reports: [],
    },
  ]);
  expect(firmwareExtractionGaps(observed, 3)).toMatchObject([
    {
      kind: "encrypted-chunk",
      provider_id: "e",
      root_file_range: { offset: 576, length: 512 },
    },
    {
      kind: "unknown-chunk-handler",
      provider_id: "u",
      root_file_range: { offset: 64, length: 512 },
    },
  ]);
});

it("keeps multifile extraction stage identity and nameless reports without fabricated dependencies", () => {
  const observed = normalize([
    {
      __typename__: "MultiFileReport",
      id: "parts",
      handler_name: "split",
      name: "volume",
      paths: [],
      extraction_reports: [
        {
          __typename__: "ExtractorDependencyNotFoundReport",
          dependencies: ["", "helper", "helper"],
        },
      ],
    },
    { __typename__: "ExtractorDependencyNotFoundReport" },
  ]);
  expect(firmwareExtractionGaps(observed, 3)).toMatchObject([
    {
      kind: "missing-extractor-dependency",
      handler: "split",
      provider_id: "parts",
      range: null,
      root_file_range: null,
      dependencies: ["helper"],
    },
  ]);
  expect(observed.diagnostics).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        report: { __typename__: "ExtractorDependencyNotFoundReport" },
      }),
    ]),
  );
});

it("seeded gap campaign preserves root correspondence once and rejects selected-range escapes", () => {
  // xorshift32 seed 0x1892a11; 128 valid + 128 independently invalid ranges.
  let seed = 0x1892a11;
  for (let index = 0; index < 128; index++) {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    const start = (seed >>> 0) % 1000;
    const length = 1 + ((seed >>> 8) % (1024 - start));
    const record = {
      __typename__: "UnknownChunkReport",
      id: `unknown-${index}`,
      start_offset: start,
      end_offset: start + length,
      size: length,
      randomness: null,
    };
    const observed = normalize([record]);
    const gap = firmwareExtractionGaps(observed, 3)[0];
    expect(gap).toMatchObject({
      provider_id: `unknown-${index}`,
      range: { offset: start, length },
      root_file_range: { offset: 64 + start, length },
      kind: "unknown-chunk-handler",
    });
    expect(gap?.continuation).not.toMatch(/encrypted|password/u);
    expect(() =>
      normalize([{ ...record, end_offset: 1025, size: 1025 - start }]),
    ).toThrow();
  }
});

it("never offers a depth-reset artifact before that same child is independently committed", () => {
  const observed = normalize([]);
  observed.depth_limited_paths.push("$output/depth");
  expect(firmwareExtractionGaps(observed, 10)[0]?.continuation).toContain(
    "no verified committed child",
  );
  expect(
    firmwareExtractionGaps(observed, 10, [
      { relative_path: "unrelated/child", size: 10 },
    ])[0]?.continuation,
  ).toContain("no verified committed child");
  expect(
    firmwareExtractionGaps(observed, 10, [
      { relative_path: "depth/child", size: 0 },
    ])[0]?.continuation,
  ).toContain("no verified committed child");
  expect(
    firmwareExtractionGaps(observed, 10, [
      { relative_path: "depth/child", size: 134217729 },
    ])[0]?.continuation,
  ).toContain("no verified committed child");
  expect(
    firmwareExtractionGaps(observed, 10, [
      { relative_path: "depth/child", size: 134217728 },
    ])[0]?.continuation,
  ).toContain("new extraction restarts its depth budget");
});
