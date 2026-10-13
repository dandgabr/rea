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

it("refuses only unpaired UTF16 signature names after lossless JSON transport", () => {
  for (const operation of [
    "inspect_firmware_regions",
    "extract_firmware",
    "carve_firmware",
  ] as const) {
    for (const field of ["include", "exclude"] as const) {
      for (const name of [
        "\ud800",
        "\udfff",
        "prefix\ud800suffix",
        "\udc00\ud800",
      ]) {
        const input = JSON.parse(
          JSON.stringify({
            path: "/tmp/fw",
            provider_id: "binwalk-ng",
            ...(operation === "inspect_firmware_regions"
              ? {}
              : { output_directory: "/tmp/new" }),
            options: { [field]: [name] },
          }),
        );
        expect(binwalkNgInputSchemas[operation].safeParse(input).success).toBe(
          false,
        );
      }
      for (const name of ["😀", "\ufffd", "two words", "--help", "é", " a "]) {
        const input = {
          path: "/tmp/fw",
          provider_id: "binwalk-ng",
          ...(operation === "inspect_firmware_regions"
            ? {}
            : { output_directory: "/tmp/new" }),
          options: { [field]: [name] },
        };
        expect(
          binwalkNgInputSchemas[operation].parse(input).options[field],
        ).toEqual([name]);
      }
    }
  }
});

it("keeps UTF8 argv representability across a bounded seeded UTF16 campaign", () => {
  let seed = 0x4e4733a1;
  const next = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
  for (let index = 0; index < 128; index++) {
    const high = String.fromCharCode(0xd800 + (next() % 1024));
    const low = String.fromCharCode(0xdc00 + (next() % 1024));
    for (const name of [
      `n${high}x`,
      `n${low}x`,
      `n${high}${low}x`,
      "n\ufffdx",
    ]) {
      const input = {
        path: "/tmp/fw",
        provider_id: "binwalk-ng",
        options: { include: [name] },
      };
      const valid = Buffer.from(name, "utf8").toString("utf8") === name;
      const parsed = binwalkNgInputSchemas.inspect_firmware_regions.safeParse(
        JSON.parse(JSON.stringify(input)),
      );
      expect(parsed.success).toBe(valid);
      if (parsed.success) expect(parsed.data.options.include).toEqual([name]);
    }
  }
});
