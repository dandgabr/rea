import { expect, it } from "vitest";
import { normalizeUnblobReport } from "./FirmwareReports.js";

const context = {
  inputPath: "/private/input.bin",
  outputRoot: "/private/output",
  sha256: "a".repeat(64),
  offset: 64,
  maxDepth: 3,
};
const stat = (path: string, size: number, directory = false) => ({
  __typename__: "StatReport",
  path,
  size,
  is_file: !directory,
  is_dir: directory,
  is_link: false,
  link_target: null,
});
const task = (path: string, depth = 0) => ({
  path,
  depth,
  blob_id: depth === 0 ? "" : "container",
  is_multi_file: false,
});
const root = (length: number) => ({
  task: task(context.inputPath),
  reports: [
    stat(context.inputPath, length),
    { __typename__: "HashReport", sha256: context.sha256 },
    {
      __typename__: "FileMagicReport",
      magic: "data",
      mime_type: "application/octet-stream",
    },
  ],
  subtasks: [],
});
const random = (blockSize: number, percentages: number[]) => ({
  __typename__: "RandomnessReport",
  shannon: { block_size: blockSize, percentages, mean: 12.345678901 },
  chi_square: { block_size: blockSize, percentages, mean: 50.000000003 },
});

it("retains the unrounded byte-weighted means of a native26.6.4 final-short-block producer golden", () => {
  const record = root(1025);
  const measurements = {
    __typename__: "RandomnessReport",
    shannon: {
      percentages: [99.1, 0],
      block_size: 1024,
      mean: 99.00027200744303,
    },
    chi_square: {
      percentages: [100, 48.82],
      block_size: 1024,
      mean: 99.95007048992882,
    },
  };
  const normalized = normalizeUnblobReport(
    [{ ...record, reports: [...record.reports, measurements] }],
    { ...context, length: 1025 },
  );
  expect(normalized.randomness[0]).toMatchObject({
    range: { offset: 0, length: 1025 },
    shannon: measurements.shannon,
    chi_square: measurements.chi_square,
  });
  expect(normalized.randomness[0]?.shannon.mean).not.toBe((99.1 * 1024) / 1025);
  expect(normalized.randomness[0]?.chi_square.mean).not.toBe(
    (100 * 1024 + 48.82) / 1025,
  );
});

it.each([
  { length: 20, window: 1024, count: 1 },
  { length: 1025, window: 1024, count: 2 },
  { length: 163841, window: 2048, count: 81 },
  { length: 83886081, window: 1048576, count: 81 },
])(
  "verifies native measurement coverage including final short blocks: $length",
  ({ length, window, count }) => {
    const record = root(length);
    const native = random(
      window,
      Array.from({ length: count }, () => 12.35),
    );
    const normalized = normalizeUnblobReport(
      [{ ...record, reports: [...record.reports, native] }],
      { ...context, length },
    );
    expect(normalized.randomness).toMatchObject([
      {
        range: { offset: 0, length },
        root_file_range: { offset: 64, length },
        shannon: native.shannon,
        chi_square: native.chi_square,
      },
    ]);
    expect(normalized.randomness[0]?.shannon.mean).not.toBe(12.35);
    expect(normalized.diagnostics).toEqual([]);
  },
);

it.each([
  { name: "empty", length: 20, report: random(1024, []) },
  { name: "truncated", length: 1025, report: random(1024, [12.35]) },
  { name: "overlong", length: 20, report: random(1024, [12.35, 12.35]) },
  {
    name: "wrong-native-window",
    length: 20,
    report: random(10, [12.35, 12.35]),
  },
  {
    name: "different-windows",
    length: 20,
    report: {
      ...random(1024, [12.35]),
      chi_square: { ...random(2048, [12.35]).chi_square },
    },
  },
  {
    name: "missing-second-vector",
    length: 20,
    report: {
      ...random(1024, [12.35]),
      chi_square: { ...random(1024, []).chi_square },
    },
  },
])(
  "retains malformed randomness as unknown coverage rather than a measured full scope: $name",
  ({ length, report }) => {
    const record = root(length);
    const normalized = normalizeUnblobReport(
      [{ ...record, reports: [...record.reports, report] }],
      { ...context, length },
    );
    expect(normalized.randomness).toEqual([]);
    expect(normalized.diagnostics).toMatchObject([
      {
        input_path: "$input",
        stage: "randomness",
        measurement_coverage: "unknown",
        object_range: { offset: 0, length },
        report,
      },
    ]);
    expect(normalized.coverage).toBe("partial");
  },
);

it.each([false, true])(
  "retains incomplete directory enumeration and any discovered children: %s",
  (hasChild) => {
    const parent = root(20);
    const directory = task(`${context.outputRoot}/archive.rlib`, 1);
    const child = task(`${directory.path}/known.txt`, 1);
    const records = [
      { ...parent, subtasks: [directory] },
      {
        task: directory,
        reports: [
          stat(directory.path, 4096, true),
          {
            __typename__: "UnknownError",
            severity: "ERROR",
            exception: "PermissionError during iterdir",
          },
        ],
        subtasks: hasChild ? [child] : [],
      },
      ...(hasChild
        ? [{ task: child, reports: [stat(child.path, 4)], subtasks: [] }]
        : []),
    ];
    const normalized = normalizeUnblobReport(records, {
      ...context,
      length: 20,
    });
    expect(
      normalized.tasks.find((item) => item.path === "$output/archive.rlib"),
    ).toMatchObject({
      processing_disposition: "directory_enumeration_incomplete",
      skip_reasons: [],
    });
    expect(
      normalized.derivations.filter(
        (edge) => edge.parent_path === "$output/archive.rlib",
      ),
    ).toHaveLength(hasChild ? 1 : 0);
    expect(normalized.coverage).toBe("partial");
  },
);

it("does not evaluate extension skip policy for a successfully enumerated directory", () => {
  const parent = root(20);
  const directory = task(`${context.outputRoot}/archive.rlib`, 1);
  const normalized = normalizeUnblobReport(
    [
      { ...parent, subtasks: [directory] },
      {
        task: directory,
        reports: [stat(directory.path, 4096, true)],
        subtasks: [],
      },
    ],
    { ...context, length: 20 },
  );
  expect(
    normalized.tasks.find((item) => item.path === "$output/archive.rlib"),
  ).toMatchObject({
    processing_disposition: "directory_enumerated",
    skip_reasons: [],
  });
});

it.each(["native-early-return", "unfamiliar-positive-report"])(
  "does not claim successful enumeration from a directory's stat after interrupted or unknown control flow: %s",
  (failure) => {
    const parent = root(20);
    const directory = task(`${context.outputRoot}/directory`, 1);
    const extra =
      failure === "native-early-return"
        ? {
            __typename__: "MultiFileReport",
            id: "multifile",
            handler_name: "multipart",
            name: "volume",
            paths: [`${directory.path}/part`],
            extraction_reports: [
              {
                __typename__: "OutputDirectoryExistsReport",
                severity: "ERROR",
                path: `${directory.path}/volume_extract`,
              },
            ],
          }
        : { __typename__: "CustomDirectoryFact", observed_name: "retained" };
    const normalized = normalizeUnblobReport(
      [
        { ...parent, subtasks: [directory] },
        {
          task: directory,
          reports: [stat(directory.path, 4096, true), extra],
          subtasks: [],
        },
      ],
      { ...context, length: 20 },
    );
    expect(
      normalized.tasks.find((item) => item.path === "$output/directory"),
    ).toMatchObject({
      processing_disposition:
        failure === "native-early-return"
          ? "directory_enumeration_incomplete"
          : "unknown_processing",
      skip_reasons: [],
    });
    expect(normalized.coverage).toBe("partial");
  },
);

it("does not promote matching policies to executed skip reasons when hashing failed", () => {
  const parent = root(20);
  const child = task(`${context.outputRoot}/unreadable.rlib`, 1);
  const normalized = normalizeUnblobReport(
    [
      { ...parent, subtasks: [child] },
      {
        task: child,
        reports: [
          stat(child.path, 20),
          {
            __typename__: "FileMagicReport",
            magic: "PNG image data",
            mime_type: "image/png",
          },
          {
            __typename__: "UnknownError",
            severity: "ERROR",
            exception: "PermissionError during HashReport.from_path",
          },
        ],
        subtasks: [],
      },
    ],
    { ...context, length: 20 },
  );
  expect(
    normalized.tasks.find((item) => item.path === "$output/unreadable.rlib"),
  ).toMatchObject({
    processing_disposition: "unknown_processing",
    hashes: null,
    skip_reasons: [],
  });
});

it("reports both executed skip reasons only after successful regular-file metadata", () => {
  const record = root(20);
  const path = "/private/image.rlib";
  const normalized = normalizeUnblobReport(
    [
      {
        ...record,
        task: task(path),
        reports: [
          stat(path, 20),
          record.reports[1],
          {
            __typename__: "FileMagicReport",
            magic: "PNG image data",
            mime_type: "image/png",
          },
        ],
      },
    ],
    { ...context, inputPath: path, length: 20 },
  );
  expect(normalized.tasks[0]).toMatchObject({
    processing_disposition: "skipped_magic",
    skip_reasons: ["magic", "extension"],
  });
});
