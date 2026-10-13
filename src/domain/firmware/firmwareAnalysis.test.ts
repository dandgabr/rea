import { expect, it } from "vitest";
import { firmwareInputSchemas } from "./firmwareAnalysis.js";

it("preserves legacy provider defaults while selecting strict Unblob inspection options", () => {
  expect(
    firmwareInputSchemas.inspect_firmware_regions.parse({
      path: "/tmp/fw.bin",
    }),
  ).toMatchObject({ provider_id: "binwalk" });
  expect(
    firmwareInputSchemas.inspect_firmware_regions.parse({
      path: "/tmp/fw.rlib",
      provider_id: "unblob",
      range: { offset: 64, length: 20 },
      options: {
        randomness_depth: 2,
        workers: 3,
        skip_magic: { mode: "replace", values: ["PDF"] },
        skip_extensions: [".bin"],
      },
    }),
  ).toMatchObject({
    provider_id: "unblob",
    options: { randomness_depth: 2, workers: 3, skip_extensions: [".bin"] },
  });
  expect(
    firmwareInputSchemas.inspect_firmware_regions.safeParse({
      path: "/tmp/fw.bin",
      provider_id: "binwalk",
      options: { randomness_depth: 2 },
    }).success,
  ).toBe(false);
});

it("validates real Unblob option grammars without silently dropping caller choices", () => {
  const base = {
    path: "/tmp/fw.bin",
    output_directory: "/tmp/new-output",
    provider_id: "unblob",
  };
  expect(
    firmwareInputSchemas.extract_firmware.parse({
      ...base,
      options: {
        workers: 2,
        keep_extracted_chunks: true,
        delete_extracted_files: { mode: "selected", handlers: ["gzip"] },
        carve_suffix: ".carved",
        extract_suffix: ".expanded",
      },
    }),
  ).toMatchObject({
    options: {
      workers: 2,
      keep_extracted_chunks: true,
      delete_extracted_files: { mode: "selected", handlers: ["gzip"] },
    },
  });
  for (const options of [
    { workers: 0 },
    { skip_extensions: [] },
    { carve_suffix: "../escape" },
    { extract_suffix: "" },
    { delete_extracted_files: { mode: "selected", handlers: [] } },
    { delete_extracted_files: { mode: "selected", handlers: ["gzip,zip"] } },
    { no_sandbox: true },
    { force: true },
  ])
    expect(
      firmwareInputSchemas.extract_firmware.safeParse({ ...base, options })
        .success,
    ).toBe(false);
});
