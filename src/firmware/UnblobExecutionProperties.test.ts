import { expect, it } from "vitest";
import {
  firmwareRequestSchema,
  unblobRegionResultSchema,
} from "../domain/firmware/firmwareAnalysis.js";
import { unblobExecutionOptions } from "./UnblobOptions.js";

const input = {
  path: "/fixtures/name.rlib",
  provider_id: "unblob",
  output_directory: "/fixtures/output",
};

it("rejects a different engine identity in the explicit Unblob inspection result branch", () => {
  expect(
    unblobRegionResultSchema.safeParse({
      provider_id: "unblob",
      mode: "inspection",
      input_size: 10,
      selection: { offset: 0, length: 10, sha256: "a".repeat(64) },
      engine: {
        name: "binwalk",
        version: "3.1.0",
        executable_path: "/fixture/binwalk",
        executable_sha256: "b".repeat(64),
        source_revision: null,
        worker_count: 1,
      },
      coverage: "partial",
      chunks: [],
      derivations: [],
      depth_limited_paths: [],
      diagnostics: [],
      tasks: [],
      randomness: [],
      multifiles: [],
      deleted_files: [],
    }).success,
  ).toBe(false);
});

it("rejects unrepresentable native argv text before invoking a producer", () => {
  for (const options of [
    { skip_magic: { values: ["PNG\0--force"] } },
    { skip_extensions: [".rlib\0"] },
    { skip_magic: { values: ["PNG\ud800"] } },
    { skip_extensions: [".rlib\udc00"] },
    { delete_extracted_files: { mode: "selected", handlers: ["gzip\0"] } },
  ])
    expect(
      firmwareRequestSchema.safeParse({
        operation: "extract_firmware",
        input: { ...input, options },
      }).success,
    ).toBe(false);
});

it("bounded seed0x51a71 preserves caller values, native modes and strict provider choices across256 generated requests", () => {
  let state = 0x51a71;
  const next = () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
  const texts = [
    "",
    "--force",
    "--skip-extraction",
    "PNG",
    " ASCII ",
    "line\nbreak",
    "雪",
    "🔧",
    "password=value",
    'quote"value',
    "semi;$(literal)",
  ];
  for (let index = 0; index < 256; index += 1) {
    const inspection = next() % 2 === 0;
    const mode = next() % 2 === 0 ? "append" : "replace";
    const magic = `${texts[next() % texts.length]}${index}`;
    const extension = texts[next() % texts.length] ?? "";
    const workers = 1 + (next() % 7);
    const randomness_depth = next() % 5;
    const deletionMode = ["none", "all", "selected"][next() % 3];
    const extractionOptions = {
      keep_extracted_chunks: next() % 2 === 0,
      delete_extracted_files:
        deletionMode === "selected"
          ? { mode: deletionMode, handlers: ["gzip", "handler-name"] }
          : { mode: deletionMode },
      carve_suffix: `.carved-${index}`,
      extract_suffix: `.expanded-${index}`,
    };
    const request = firmwareRequestSchema.parse({
      operation: inspection ? "inspect_firmware_regions" : "extract_firmware",
      input: {
        path: input.path,
        provider_id: input.provider_id,
        ...(inspection ? {} : { output_directory: input.output_directory }),
        options: {
          workers,
          randomness_depth,
          skip_magic: { mode, values: [magic] },
          skip_extensions: [extension],
          ...(inspection ? {} : extractionOptions),
        },
      },
    });
    if (request.input.provider_id !== "unblob")
      throw new Error("Generated Unblob request lost its selected provider");
    const native = unblobExecutionOptions(request);
    expect(native.args).toContain(`--skip-magic=${magic}`);
    expect(native.args).toContain(`--skip-extension=${extension}`);
    expect(native.args.includes("--clear-skip-magics")).toBe(
      mode === "replace",
    );
    expect(native.args.includes("--skip-extraction")).toBe(inspection);
    expect(native.args).not.toContain("--force");
    expect(native.args).not.toContain("--no-sandbox");
    expect(native.skipMagic).toContain(magic);
    expect(native.skipMagic.includes("PNG")).toBe(mode === "append");
    expect(native.skipExtensions).toEqual([extension]);
    expect(native.args[native.args.indexOf("--process-num") + 1]).toBe(
      String(workers),
    );
    expect(native.args[native.args.indexOf("--randomness-depth") + 1]).toBe(
      String(randomness_depth),
    );
    if (!inspection) {
      expect(native.args).toContain(
        `--delete-extracted-files=${deletionMode === "selected" ? "selected:gzip,handler-name" : deletionMode}`,
      );
      expect(native.args).toContain(
        `--carve-suffix=${extractionOptions.carve_suffix}`,
      );
      expect(native.args.includes("--keep-extracted-chunks")).toBe(
        extractionOptions.keep_extracted_chunks,
      );
    }
    expect(
      firmwareRequestSchema.safeParse({
        operation: request.operation,
        input: {
          ...request.input,
          provider_id: "binwalk",
          options: request.input.options,
        },
      }).success,
    ).toBe(false);
  }
});
