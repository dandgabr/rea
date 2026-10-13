import { expect, it } from "vitest";
import { parseBinwalkNgInventory } from "./BinwalkNgInventory.js";
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
  const text = listing(line);
  const result = parseBinwalkNgInventory(text);
  expect(result.formats).toEqual([]);
  expect(result.inventory_coverage).toBe("partial");
  expect(result.unparsed_lines).toEqual([
    line + "gzip".padEnd(35) + "Built-in",
  ]);
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
