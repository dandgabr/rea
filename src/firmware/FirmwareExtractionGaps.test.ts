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

it("aggregates repeated task-wide dependencies without erasing native occurrences or assigning a chunk", () => {
  const reports = [
    {
      __typename__: "ExtractorDependencyNotFoundReport",
      dependencies: ["sasquatch", "sasquatch"],
    },
    {
      __typename__: "ExtractorDependencyNotFoundReport",
      dependencies: ["jefferson", "sasquatch", ""],
    },
    {
      __typename__: "ExtractorDependencyNotFoundReport",
      dependencies: ["jefferson"],
    },
  ];
  const observed = normalize(reports);
  expect(firmwareExtractionGaps(observed, 3)).toEqual([
    expect.objectContaining({
      kind: "missing-extractor-dependency",
      input_path: "$input",
      provider_id: null,
      handler: null,
      range: null,
      root_file_range: null,
      dependencies: ["jefferson", "sasquatch"],
    }),
  ]);
  expect(
    observed.diagnostics.map(
      (diagnostic) => (diagnostic as { report: unknown }).report,
    ),
  ).toEqual(reports);
});

it.each(["chunk", "multifile"])(
  "retains explicit unfamiliar ERROR at its %s extraction stage without inventing dependencies",
  (kind) => {
    const problem = {
      __typename__: "TrustedExtractorError",
      severity: "ERROR",
      note: "exact producer failure",
    };
    const stage =
      kind === "chunk"
        ? {
            __typename__: "ChunkReport",
            id: "stage",
            start_offset: 0,
            end_offset: 1024,
            size: 1024,
            handler_name: "trusted",
            is_encrypted: false,
            extraction_reports: [problem],
          }
        : {
            __typename__: "MultiFileReport",
            id: "stage",
            handler_name: "trusted",
            name: "volume",
            paths: [],
            extraction_reports: [problem],
          };
    const observed = normalize([stage]);
    expect(firmwareExtractionGaps(observed, 3)).toEqual([
      expect.objectContaining({
        kind: "extractor-failure",
        input_path: "$input",
        provider_id: "stage",
        handler: "trusted",
        dependencies: [],
        range: kind === "chunk" ? { offset: 0, length: 1024 } : null,
        root_file_range: kind === "chunk" ? { offset: 64, length: 1024 } : null,
      }),
    ]);
    expect(JSON.stringify(observed.diagnostics)).toContain(
      JSON.stringify(problem),
    );
  },
);

it.each([0, 134217729])(
  "withholds a nested fresh-input continuation for committed child size %s",
  (size) => {
    const observed = normalize([]);
    observed.chunks.push({
      input_path: "$output/nested/child",
      provider_id: "unknown",
      handler: null,
      encrypted: null,
      range: { offset: 0, length: 10 },
      root_file_range: null,
      extraction_failed: false,
    });
    const published = [
      { relative_path: "nested/child", size },
      { relative_path: "unrelated", size: 10 },
    ];
    const gap = firmwareExtractionGaps(observed, 3, published)[0];
    expect(gap?.continuation).not.toContain("as a fresh");
    expect(gap?.continuation).toContain(
      "no verified committed child within the firmware input limit",
    );
    expect(gap).toMatchObject({
      range: { offset: 0, length: 10 },
      root_file_range: null,
    });
  },
);

it.each([1, 134217728])(
  "allows nested reentry only through the exact usable committed child size %s",
  (size) => {
    const observed = normalize([]);
    observed.chunks.push({
      input_path: "$output/nested/child",
      provider_id: "unknown",
      handler: null,
      encrypted: null,
      range: { offset: 0, length: 1 },
      root_file_range: null,
      extraction_failed: false,
    });
    expect(
      firmwareExtractionGaps(observed, 3, [
        { relative_path: "nested/child", size },
      ])[0]?.continuation,
    ).toContain("as a fresh");
    expect(
      firmwareExtractionGaps(observed, 3, [
        { relative_path: "nested/child-other", size },
      ])[0]?.continuation,
    ).not.toContain("as a fresh");
  },
);

it.each([undefined, "INFO", "WARNING", "ERROR-like"])(
  "keeps unfamiliar extraction severity %s as unknown information",
  (severity) => {
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
          {
            __typename__: "TrustedReport",
            ...(severity === undefined ? {} : { severity }),
          },
        ],
      },
    ]);
    expect(observed.chunks[0]?.extraction_failed).toBe(false);
    expect(firmwareExtractionGaps(observed, 3)).toEqual([]);
    expect(observed.diagnostics).toHaveLength(1);
  },
);

it("retains a native multifile command failure without requiring any chunk or derived child", () => {
  const observed = normalize([
    {
      __typename__: "MultiFileReport",
      id: "native",
      handler_name: "split",
      name: "volume",
      paths: [],
      extraction_reports: [
        {
          __typename__: "ExtractCommandFailedReport",
          severity: "WARNING",
          command: "extract",
          exit_code: 2,
          stdout: "",
          stderr: "",
        },
      ],
    },
  ]);
  expect(observed.chunks).toEqual([]);
  expect(firmwareExtractionGaps(observed, 3)).toEqual([
    expect.objectContaining({
      kind: "extractor-failure",
      input_path: "$input",
      handler: "split",
      provider_id: "native",
      range: null,
    }),
  ]);
});

it("indexes usable depth continuations without rescanning published rows per task", () => {
  const observed = normalize([]);
  let pathReads = 0;
  const published = Array.from({ length: 64 }, (_, index) => {
    observed.depth_limited_paths.push(`$output/depth-${index}`);
    return {
      get relative_path() {
        pathReads++;
        return `depth-${index}/child`;
      },
      size: 1,
    };
  });
  const gaps = firmwareExtractionGaps(observed, 10, published);
  expect(gaps).toHaveLength(64);
  for (const gap of gaps)
    expect(gap.continuation).toContain(
      "new extraction restarts its depth budget",
    );
  expect(pathReads).toBeLessThanOrEqual(128);
});

it("seeded stage recovery campaign preserves independent identities, explicit severity and exact committed capacity", () => {
  let seed = 0x1892b22;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  for (let index = 0; index < 64; index++) {
    const dependency = (dependencies: string[]) => ({
      __typename__: "ExtractorDependencyNotFoundReport",
      dependencies,
    });
    const ids = [`stage-${next()}-a`, `stage-${next()}-b`];
    const chunks = ids.map((id, position) => ({
      __typename__: "ChunkReport",
      id,
      start_offset: position * 512,
      end_offset: (position + 1) * 512,
      size: 512,
      handler_name: "same-handler",
      is_encrypted: false,
      extraction_reports: [
        dependency([`tool-${position}`, `tool-${position}`]),
      ],
    }));
    const taskReports = [
      dependency(["zeta", "zeta"]),
      dependency(["alpha", "zeta"]),
    ];
    const observed = normalize([...chunks, ...taskReports]);
    const gaps = firmwareExtractionGaps(observed, 3);
    expect(gaps).toHaveLength(3);
    for (const [position, id] of ids.entries())
      expect(gaps.find((gap) => gap.provider_id === id)).toMatchObject({
        dependencies: [`tool-${position}`],
        range: { offset: position * 512, length: 512 },
        root_file_range: { offset: 64 + position * 512, length: 512 },
        handler: "same-handler",
      });
    expect(gaps.find((gap) => gap.provider_id === null)).toMatchObject({
      dependencies: ["alpha", "zeta"],
      range: null,
      root_file_range: null,
    });
    expect(
      firmwareExtractionGaps(
        normalize([...taskReports.toReversed(), ...chunks.toReversed()]),
        3,
      ),
    ).toEqual(gaps);
    expect(observed.diagnostics).toHaveLength(4);

    const severity = ["ERROR", "WARNING", "INFO", undefined, "ERROR-like"][
      next() % 5
    ];
    const report = {
      __typename__: `CustomReport-${index}`,
      ...(severity === undefined ? {} : { severity }),
    };
    const stage =
      index % 2 === 0
        ? { ...chunks[0], extraction_reports: [report] }
        : {
            __typename__: "MultiFileReport",
            id: ids[0],
            handler_name: "same-handler",
            name: "volume",
            paths: [],
            extraction_reports: [report],
          };
    const stageObserved = normalize([stage]);
    expect(firmwareExtractionGaps(stageObserved, 3)).toHaveLength(
      severity === "ERROR" ? 1 : 0,
    );
    expect(JSON.stringify(stageObserved.diagnostics)).toContain(
      JSON.stringify(report),
    );

    const size = [0, 1, 134217728, 134217729][next() % 4]!;
    const exact = (next() & 1) === 1;
    const nested = normalize([]);
    nested.chunks.push({
      input_path: `$output/task-${index}/child`,
      provider_id: "nested",
      handler: null,
      encrypted: null,
      range: { offset: 0, length: 1 },
      root_file_range: null,
      extraction_failed: false,
    });
    const selected = `task-${index}/child${exact ? "" : "-other"}`;
    const continuation = firmwareExtractionGaps(nested, 3, [
      { relative_path: selected, size },
      { relative_path: "unrelated", size: 1 },
    ])[0]!.continuation;
    expect(continuation.includes("as a fresh")).toBe(
      exact && size > 0 && size <= 134217728,
    );
  }
});
