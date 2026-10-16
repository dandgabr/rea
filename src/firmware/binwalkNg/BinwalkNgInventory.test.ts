import { expect, it } from "vitest";
import {
  parseBinwalkNgInventory,
  validateBinwalkNgHelperBindings,
} from "./BinwalkNgInventory.js";
const listing = (
  description = "gzip compressed data",
  name = "gzip",
  extractor = "Built-in",
) =>
  [
    "-".repeat(90),
    "Signature Description".padEnd(35) +
      "Signature Name".padEnd(35) +
      "Extraction Utility",
    "-".repeat(90),
    description.padEnd(35) + name.padEnd(35) + extractor,
    "-".repeat(90),
    "Total signatures: 1",
    "Extractable signatures: 1",
  ].join("\n");
it("preserves native format columns and unknown search-all/dependency facts when colors are absent", () => {
  expect(parseBinwalkNgInventory(listing())).toEqual({
    formats: [
      {
        name: "gzip",
        description: "gzip compressed data",
        extractor: "Built-in",
        requires_search_all: null,
      },
    ],
    reported_signature_count: 1,
    reported_extractable_count: 1,
    unparsed_lines: [],
    inventory_coverage: "native_reported",
  });
  expect(
    parseBinwalkNgInventory(
      listing()
        .replace("gzip compressed data", "\u001b[33mgzip compressed data")
        .replace("Built-in", "Built-in\u001b[0m"),
    ).formats[0]?.requires_search_all,
  ).toBe(true);
});
it("retains ambiguous presentation lines and partial inventory without guessing a signature name", () => {
  const line = "native description exceeds the minimum column width";
  const name = "signature_name_that_exceeds_column_width";
  const text = listing(line, name);
  const result = parseBinwalkNgInventory(text);
  expect(result.formats).toEqual([]);
  expect(result.inventory_coverage).toBe("partial");
  expect(result.unparsed_lines).toEqual([line + name.padEnd(35) + "Built-in"]);
  expect(result.reported_signature_count).toBe(1);
  expect(() =>
    parseBinwalkNgInventory(
      listing().replace(
        "Extractable signatures: 1",
        "Extractable signatures: 2",
      ),
    ),
  ).toThrow("valid reported totals");
});
it("bounded inventory presentation fuzz: seed 0x4e473301, 64 cases preserve every actual listed identifier and refuse missing totals", () => {
  let seed = 0x4e473301;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  for (let index = 0; index < 64; index++) {
    const name = `sig_${next().toString(16)}`,
      description = `Format${index % 2 === 0 ? "  tag  " : " "}${next().toString(16)}`,
      extractor = index % 2 === 0 ? "Built-in" : "external-helper";
    const text = listing(description, name, extractor),
      result = parseBinwalkNgInventory(text);
    expect(result.formats).toEqual([
      { name, description, extractor, requires_search_all: null },
    ]);
    expect(result.inventory_coverage).toBe("native_reported");
    expect(() =>
      parseBinwalkNgInventory(text.replace(/Total signatures: 1/u, "")),
    ).toThrow("valid reported totals");
  }
});
it("parses the native fixed-width columns when descriptions contain repeated internal spaces", () => {
  const description = "ISO  9660  filesystem image";
  expect(
    parseBinwalkNgInventory(listing(description, "iso9660", "external-helper"))
      .formats,
  ).toEqual([
    {
      name: "iso9660",
      description,
      extractor: "external-helper",
      requires_search_all: null,
    },
  ]);
});

it("parses source-formatted inventory rows whose descriptions overflow the first column", () => {
  const inventory = parseBinwalkNgInventory(
    listing(
      "Broadcom ProgramStore firmware image",
      "program_store",
      "Built-in",
    ),
  );
  expect(inventory.inventory_coverage).toBe("native_reported");
  expect(inventory.formats).toEqual([
    {
      name: "program_store",
      description: "Broadcom ProgramStore firmware image",
      extractor: "Built-in",
      requires_search_all: null,
    },
  ]);
});

it("admits explicitly configured helper subsets and source-backed dynamic mappings", () => {
  const inventory = parseBinwalkNgInventory(
    listing("7z archive", "7z", "sevenzip"),
  );
  const helper = {
    name: "sevenzip",
    expected_version: "7-Zip 26.00",
    supported_signatures: ["7z"],
  };
  expect(validateBinwalkNgHelperBindings(inventory, [helper])).toEqual([
    helper,
  ]);
  expect(validateBinwalkNgHelperBindings(inventory, [])).toEqual([]);
  expect(() =>
    validateBinwalkNgHelperBindings(inventory, [
      { ...helper, supported_signatures: ["gzip"] },
    ]),
  ).toThrow("complete native and source-backed signature mapping");
  expect(() =>
    validateBinwalkNgHelperBindings(inventory, [
      helper,
      { ...helper, name: "unexpected" },
    ]),
  ).toThrow("complete native and source-backed signature mapping");
  expect(
    validateBinwalkNgHelperBindings(
      parseBinwalkNgInventory(listing("xz stream", "xz", "Built-in")),
      [{ ...helper, name: "7z", supported_signatures: ["xz"] }],
    ),
  ).toHaveLength(1);
});

it("requires the complete helper signature set including dynamic XZ dispatch", () => {
  const inventory = parseBinwalkNgInventory(
    listing("7zip archive", "7zip", "7z"),
  );
  expect(() =>
    validateBinwalkNgHelperBindings(inventory, [
      {
        name: "7z",
        expected_version: "7-Zip 26.00",
        supported_signatures: ["7zip"],
      },
    ]),
  ).toThrow("complete native and source-backed signature mapping");
});

it("rejects helper admission when the native inventory is partial", () => {
  const text = `${listing("7z archive", "7z", "sevenzip")}\nambiguous native display row`;
  const inventory = parseBinwalkNgInventory(text);
  expect(inventory.inventory_coverage).toBe("partial");
  const helper = {
    name: "sevenzip",
    expected_version: "7-Zip 26.00",
    supported_signatures: ["7z"],
  };
  expect(() =>
    validateBinwalkNgHelperBindings(inventory, [
      { ...helper, supported_signatures: ["unknown-format"] },
    ]),
  ).toThrow("complete native format inventory");
  expect(() => validateBinwalkNgHelperBindings(inventory, [helper])).toThrow(
    "complete native format inventory",
  );
});
