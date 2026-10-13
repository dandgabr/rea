import { expect, it } from "vitest";
import { interpretFactImport } from "./FactNativeInterpretation.js";

const uid = "a".repeat(64) + "_3";
const selected = {
  uid,
  db_revision: "archive-rev",
  binary_count: 2,
  object_count: 2,
  ignored_orphans: [] as string[],
  path: "/private/selected.zip",
};
const line = (level: string, message: string) =>
  `[12:34:56] ${level}     ${message}       firmware_import_export.py:129\n`;
it("keeps zero-exit unknown without an exact native import acknowledgement", () => {
  for (const output of [
    "",
    "Successfully imported 2 files and 2 DB entries from /private/selected.zip",
    line(
      "INFO",
      "Successfully imported 2 files and 2 DB entries from /different.zip",
    ),
    line(
      "INFO",
      "Successfully imported 999 files and 2 DB entries from /private/selected.zip",
    ),
  ])
    expect(interpretFactImport(selected, output, 0).disposition).toBe(
      "unknown",
    );
});
it("preserves producer-reported imports, skips and strict revision refusals independently", () => {
  expect(
    interpretFactImport(
      selected,
      line(
        "INFO",
        "Successfully imported 2 files and 2 DB entries from /private/selected.zip",
      ),
      0,
    ),
  ).toMatchObject({
    disposition: "producer-reported-import",
    reported_files: 2,
    reported_objects: 2,
  });
  expect(
    interpretFactImport(
      selected,
      line("WARNING", `Skipping firmware ${uid}. Reason: is already in the DB`),
      0,
    ),
  ).toMatchObject({ disposition: "skipped-existing" });
  expect(
    interpretFactImport(
      selected,
      line(
        "ERROR",
        "Error: import file was created with a different DB revision: archive-rev (current revision is current-rev). Please upgrade/downgrade to a compatible revision.",
      ),
      0,
    ),
  ).toMatchObject({
    disposition: "revision-refused",
    current_revision: "current-rev",
  });
});
it("retains shared-identity partial-write uncertainty on producer exceptions and contradictory reports", () => {
  expect(
    interpretFactImport(
      selected,
      "storage.db_interface_base.DbInterfaceError",
      1,
    ),
  ).toMatchObject({
    disposition: "unknown",
    database_effects: "possibly-partial",
  });
  expect(
    interpretFactImport(
      selected,
      line(
        "INFO",
        "Successfully imported 2 files and 2 DB entries from /private/selected.zip",
      ) +
        line(
          "WARNING",
          `Skipping firmware ${uid}. Reason: is already in the DB`,
        ),
      0,
    ).disposition,
  ).toBe("unknown");
});
it("runs seeded acknowledgement correlation properties with exact independent archive counts", () => {
  let seed = 0xfac70004;
  for (let index = 0; index < 128; index++) {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    const path = `/private/selected-${seed}-é.zip`;
    const subject = { ...selected, path };
    const valid = line(
      "INFO",
      `Successfully imported 2 files and 2 DB entries from ${path}`,
    );
    expect(interpretFactImport(subject, valid, 0).disposition).toBe(
      "producer-reported-import",
    );
    const wrong =
      seed % 2
        ? valid.replace(
            "imported 2 files",
            `imported ${3 + (seed % 1000)} files`,
          )
        : valid.replace(path, path + ".different");
    expect(interpretFactImport(subject, wrong, 0)).toMatchObject({
      disposition: "unknown",
      database_effects: "possibly-partial",
    });
    expect(interpretFactImport(subject, valid, 1).disposition).toBe("unknown");
  }
});
