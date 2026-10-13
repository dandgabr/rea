import { expect, it } from "vitest";
import { normalizeUnblobInventory } from "./UnblobInventory.js";
import type { runFirmwareCommand } from "./FirmwareCommand.js";

const execution = {
  exit_code: 0,
  stdout: {
    text: "The following executables found installed, which are needed by unblob:\n    gzip    ✓\n",
  },
} as Awaited<ReturnType<typeof runFirmwareCommand>>;
const engine = {
  name: "unblob",
  version: "26.6.4",
  executable_path: "/tool/unblob",
  executable_sha256: "a".repeat(64),
  source_revision: null,
  worker_count: 1,
};
const header =
  '??? example "All supported formats"\n    | Format | Type | Fully supported? |\n    | :--- | :--- | :---: |\n';
const row = "    | [`GZIP`](#gzip) | COMPRESSION | :octicons-check-16: |";

it("retains valid format observations while refusing full table coverage after malformed rows", () => {
  const result = normalizeUnblobInventory(
    execution,
    `${header}${row}\n    | BROKEN ROW |\n\n## GZIP\n`,
    engine,
  );
  expect(result.formats).toHaveLength(1);
  expect(result.format_inventory_coverage).toBe("partial");
  expect(result.unparsed_format_lines).toEqual(["    | BROKEN ROW |"]);
});

it("seeded malformed-table campaign cannot invent public DOC coverage from remaining valid rows", () => {
  // xorshift32 seed 0x55424c4f; 128 independent malformed row/header variants.
  let seed = 0x55424c4f;
  for (let index = 0; index < 128; index++) {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    const malformed = `    | broken-${(seed >>> 0).toString(16)} | COMPRESSION | uncertain |`;
    const result = normalizeUnblobInventory(
      execution,
      `${header}${row}\n${malformed}\n\n## GZIP\n`,
      engine,
    );
    expect(result.format_inventory_coverage).toBe("partial");
    expect(result.formats).toEqual([
      { name: "GZIP", type: "COMPRESSION", fully_supported: true },
    ]);
    expect(result.unparsed_format_lines).toEqual([malformed]);
  }
  const positive = normalizeUnblobInventory(
    execution,
    `${header}${row}\n\n## GZIP\n`,
    engine,
  );
  expect(positive.format_inventory_coverage).toBe("documented_public_handlers");
});
