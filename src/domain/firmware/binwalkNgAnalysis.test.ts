import { expect, it } from "vitest";
import { binwalkNgInputSchemas } from "./binwalkNgAnalysis.js";

it("preserves native default scanning, explicit threads and search choices", () => {
  const input = binwalkNgInputSchemas.inspect_firmware_regions.parse({
    path: "/tmp/fw",
    provider_id: "binwalk-ng",
  });
  expect(input.options).toEqual({
    search_all: false,
    include: [],
    exclude: [],
    no_mmap: false,
    workers: 1,
  });
  expect(
    binwalkNgInputSchemas.inspect_firmware_regions.parse({
      path: "/tmp/fw",
      provider_id: "binwalk-ng",
      options: { workers: 3, search_all: true, include: ["gzip"] },
    }).options,
  ).toMatchObject({ workers: 3, search_all: true, include: ["gzip"] });
});
it("rejects include/exclude conflicts and zero threads, with explicit positive controls", () => {
  const parse = (options: unknown) =>
    binwalkNgInputSchemas.inspect_firmware_regions.parse({
      path: "/tmp/fw",
      provider_id: "binwalk-ng",
      options,
    });
  expect(() => parse({ include: ["gzip"], exclude: ["tar"] })).toThrow(
    "mutually exclusive",
  );
  expect(() => parse({ workers: 0 })).toThrow();
  expect(parse({ exclude: ["gzip"], workers: 2 }).options.exclude).toEqual([
    "gzip",
  ]);
});
it("expresses bounded extraction, optional native carving and one-pass recursion intent", () => {
  expect(
    binwalkNgInputSchemas.extract_firmware.parse({
      path: "/tmp/fw",
      output_directory: "/tmp/new",
      provider_id: "binwalk-ng",
      options: { carve: true, recursive: false },
    }),
  ).toMatchObject({
    max_depth: 3,
    max_output_bytes: 256 * 1024 * 1024,
    max_output_files: 10000,
    options: { carve: true, recursive: false },
  });
});
it("accepts entropy without publication and rejects ignored scan options", () => {
  expect(
    binwalkNgInputSchemas.inspect_firmware_entropy.parse({
      path: "/tmp/fw",
      provider_id: "binwalk-ng",
    }),
  ).not.toHaveProperty("output_directory");
  expect(() =>
    binwalkNgInputSchemas.inspect_firmware_entropy.parse({
      path: "/tmp/fw",
      provider_id: "binwalk-ng",
      options: { search_all: true },
    }),
  ).toThrow();
});
