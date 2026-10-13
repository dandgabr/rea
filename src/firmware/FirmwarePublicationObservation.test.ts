import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { normalizeUnblobReport } from "./FirmwareReports.js";
import { publishFirmwareExtraction } from "./FirmwarePublication.js";

it("the publisher itself retains producer facts without provider fallback or authority over an existing output", async () => {
  const root = await createTestTempDirectory("rea-firmware-publication-facts-");
  const path = join(root, "input.bin");
  const bytes = Buffer.concat([
    Buffer.from(
      Array.from(
        { length: 1024 },
        (_, index) => (index * 13 + Math.floor(index / 7)) % 256,
      ),
    ),
    Buffer.from([0]),
  ]);
  await writeFile(path, bytes);
  const sha256 =
    "f94fb31966cd02ba57e7818208d3bf95061c21c76e58cd2978b1fe03b161830c";
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(sha256);
  const report = [
    {
      task: { path, depth: 0, blob_id: "", is_multi_file: false },
      reports: [
        {
          __typename__: "StatReport",
          path,
          size: 1025,
          is_file: true,
          is_dir: false,
          is_link: false,
          link_target: null,
        },
        { __typename__: "HashReport", sha256 },
        {
          __typename__: "FileMagicReport",
          magic: "data",
          mime_type: "application/octet-stream",
        },
        {
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
        },
      ],
      subtasks: [],
    },
  ];
  const normalized = normalizeUnblobReport(report, {
    inputPath: path,
    outputRoot: join(root, "staging"),
    sha256,
    length: 1025,
    offset: 0,
    maxDepth: 3,
  });
  const output = join(root, "caller-output");
  await mkdir(output);
  await writeFile(join(output, "sentinel"), "caller bytes");
  const retainCleanup = vi.fn();
  await expect(
    publishFirmwareExtraction({
      outputDirectory: output,
      entries: [],
      normalized,
      selection: { offset: 0, length: 1025, sha256 },
      engine: {
        name: "unblob",
        version: "26.6.4",
        executable_path: "/fixture/unblob",
        executable_sha256: "a".repeat(64),
        source_revision: null,
        worker_count: 1,
      },
      signal: new AbortController().signal,
      retainCleanup,
    }),
  ).rejects.toMatchObject({
    _tag: "ProviderAdapterError",
    cleanupIncomplete: false,
    partialObservation: {
      kind: "firmware",
      result: {
        publication_state: "not_committed",
        requested_output_directory: output,
        tasks: [
          expect.objectContaining({
            path: "$input",
            hashes: expect.objectContaining({ sha256 }),
          }),
        ],
        randomness: [
          expect.objectContaining({
            shannon: expect.objectContaining({ mean: 99.00027200744303 }),
          }),
        ],
      },
    },
  });
  expect(retainCleanup).not.toHaveBeenCalled();
  expect(await readdir(output)).toEqual(["sentinel"]);
  expect(await readFile(join(output, "sentinel"), "utf8")).toBe("caller bytes");
  expect(await readFile(path)).toEqual(bytes);
});
