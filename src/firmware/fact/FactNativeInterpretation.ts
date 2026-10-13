export type FactImportDisposition =
  | "producer-reported-import"
  | "skipped-existing"
  | "revision-refused"
  | "unknown";

/** A zero exit is process evidence, never proof that an archive was imported. */
export function interpretFactImport(
  selected: {
    uid: string;
    db_revision: string;
    binary_count: number;
    object_count: number;
    ignored_orphans: string[];
    path: string;
  },
  output: string,
  exit: number | null | undefined,
): {
  disposition: FactImportDisposition;
  database_effects:
    | "producer-reported-write"
    | "none-reported"
    | "possibly-partial";
  reported_files: number | null;
  reported_objects: number | null;
  current_revision: string | null;
} {
  const unknown = {
    disposition: "unknown" as const,
    database_effects: "possibly-partial" as const,
    reported_files: null,
    reported_objects: null,
    current_revision: null,
  };
  const observations: ReturnType<typeof interpretFactImport>[] = [];
  let at = 0;
  while (at < output.length) {
    const end = output.indexOf("\n", at);
    const line = output.slice(at, end < 0 ? undefined : end);
    at = end < 0 ? output.length : end + 1;
    // Read the controlled nonterminal Rich row, retaining unrecognized/wrapped
    // output as raw diagnostics. Do not concatenate repaired messages or paths.
    const location = line.lastIndexOf(" firmware_import_export.py:");
    if (
      location < 0 ||
      !/^[0-9]+\s*$/u.test(
        line.slice(location + " firmware_import_export.py:".length),
      )
    )
      continue;
    const prefix =
      /^(?:\[[0-9]{2}:[0-9]{2}:[0-9]{2}\]\s+)?(INFO|WARNING|ERROR)\s+/u.exec(
        line,
      );
    if (!prefix) continue;
    const message = line.slice(prefix[0].length, location).trimEnd();
    const imported =
      /^Successfully imported ([0-9]+) files and ([0-9]+) DB entries from /u.exec(
        message,
      );
    if (
      prefix[1] === "INFO" &&
      imported &&
      message.slice(imported[0].length) === selected.path
    ) {
      const files = Number(imported[1]),
        objects = Number(imported[2]);
      observations.push(
        files === selected.binary_count &&
          objects === selected.object_count - selected.ignored_orphans.length
          ? {
              disposition: "producer-reported-import",
              database_effects: "producer-reported-write",
              reported_files: files,
              reported_objects: objects,
              current_revision: null,
            }
          : unknown,
      );
    }
    if (
      prefix[1] === "WARNING" &&
      message ===
        `Skipping firmware ${selected.uid}. Reason: is already in the DB`
    )
      observations.push({
        disposition: "skipped-existing",
        database_effects: "none-reported",
        reported_files: null,
        reported_objects: null,
        current_revision: null,
      });
    const revisionPrefix = `Error: import file was created with a different DB revision: ${selected.db_revision} (current revision is `;
    const revisionSuffix =
      "). Please upgrade/downgrade to a compatible revision.";
    if (
      prefix[1] === "ERROR" &&
      message.startsWith(revisionPrefix) &&
      message.endsWith(revisionSuffix)
    )
      observations.push({
        disposition: "revision-refused",
        database_effects: "none-reported",
        reported_files: null,
        reported_objects: null,
        current_revision: message.slice(
          revisionPrefix.length,
          -revisionSuffix.length,
        ),
      });
  }
  // These acknowledgements are issued once per single-archive invocation. A
  // contradiction or interrupted/nonzero invocation remains possibly partial.
  return exit === 0 && observations.length === 1 ? observations[0]! : unknown;
}
