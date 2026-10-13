import { access, readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { expect, it as test, vi } from "vitest";
import {
  firmwareFixture,
  assertFirmwareCleanup,
} from "../../fixtures/firmware/provider.js";

const it = test.skipIf(process.platform !== "linux");

it("preserves measured command output through caller cancellation and workspace cleanup", async () => {
  const fixture = await firmwareFixture("stall");
  const controller = new AbortController();
  const operation = fixture.service.execute(
    "inspect_firmware_regions",
    { provider_id: "unblob", path: fixture.path },
    { signal: controller.signal },
  );
  await vi.waitFor(async () => {
    expect(fixture.launches).toHaveLength(2);
    await access(`${fixture.launches[1]?.cwd ?? ""}/ready`);
  });
  controller.abort();
  const outcome = await operation;
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisCancelledError",
      operation: "inspect_firmware_regions",
      capturedOutput: {
        stdout: "native output before cancellation\n",
        stdout_utf8_valid: true,
        stdout_observed_bytes: 34,
        stdout_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it.each(["append", "replace"])(
  "executes caller Unblob options with native skip semantics: %s",
  async (mode) => {
    const fixture = await firmwareFixture();
    const outcome = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      options: {
        workers: 3,
        randomness_depth: 2,
        keep_extracted_chunks: true,
        skip_magic: { mode, values: ["PNG", "--force"] },
        skip_extensions: [".bin"],
        delete_extracted_files: { mode: "selected", handlers: ["gzip", "zip"] },
        carve_suffix: ".carved",
        extract_suffix: ".expanded",
      },
    });
    expect(outcome).toMatchObject({
      ok: true,
      value: { normalized_result: { engine: { worker_count: 3 } } },
    });
    expect(fixture.launches[1]?.args).toEqual(
      expect.arrayContaining([
        "--process-num",
        "3",
        "--randomness-depth",
        "2",
        "--keep-extracted-chunks",
        "--skip-magic=PNG",
        "--skip-magic=--force",
        "--skip-extension=.bin",
        "--delete-extracted-files=selected:gzip,zip",
        "--carve-suffix=.carved",
        "--extract-suffix=.expanded",
      ]),
    );
    expect(fixture.launches[1]?.args.includes("--clear-skip-magics")).toBe(
      mode === "replace",
    );
    expect(fixture.launches[1]?.args).not.toContain("--force");
    expect(fixture.launches[1]?.args).not.toContain("--no-sandbox");
    expect(await readFile(fixture.path, "utf8")).toBe("fixture-input-data");
    await assertFirmwareCleanup(fixture.launches);
  },
);

it.each([0, 1])(
  "inspects no-chunk inputs with native whole-file randomness depth %s",
  async (randomness_depth) => {
    const fixture = await firmwareFixture("unrecognized");
    await writeFile(fixture.path, Buffer.alloc(100, 0xff));
    const outcome = await fixture.service.execute("inspect_firmware_regions", {
      path: fixture.path,
      provider_id: "unblob",
      range: { offset: 64, length: 20 },
      options: { randomness_depth },
    });
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw outcome.error;
    expect(outcome.value.normalized_result).toMatchObject({
      provider_id: "unblob",
      mode: "inspection",
      input_size: 100,
      selection: { offset: 64, length: 20 },
      chunks: [],
      coverage: "partial",
      randomness:
        randomness_depth === 0
          ? []
          : [
              expect.objectContaining({
                scope: "whole_file",
                range: { offset: 0, length: 20 },
                root_file_range: { offset: 64, length: 20 },
                shannon: {
                  algorithm: "shannon_entropy",
                  unit: "percent",
                  block_size: 1024,
                  percentages: [0],
                  mean: 0,
                },
              }),
            ],
    });
    expect(basename(fixture.launches[1]?.args.at(-1) ?? "")).toBe(
      basename(fixture.path),
    );
    expect(outcome.value.normalized_result).not.toHaveProperty(
      "output_directory",
    );
    expect(outcome.value.normalized_result).not.toHaveProperty("files");
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(await readFile(fixture.path)).toEqual(Buffer.alloc(100, 0xff));
    await assertFirmwareCleanup(fixture.launches);
  },
);

it("rejects a malformed Unblob inspection with the exact operation owner", async () => {
  const fixture = await firmwareFixture("wrong-hash");
  const outcome = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
    provider_id: "unblob",
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      operation: "inspect_firmware_regions",
      reason: "Unblob input hash disagrees with selected snapshot",
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});
