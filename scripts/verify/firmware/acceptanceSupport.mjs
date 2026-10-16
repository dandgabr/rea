import assert from "node:assert/strict";

export function oracleFilesForSelectedRange(oracleFiles, selectedPrefix) {
  assert.ok(selectedPrefix.length > 0);
  assert.ok(selectedPrefix.endsWith("/"));
  const selectedFiles = Object.fromEntries(
    Object.entries(oracleFiles)
      .filter(([relativePath]) => relativePath.startsWith(selectedPrefix))
      .map(([relativePath, file]) => [
        relativePath.slice(selectedPrefix.length),
        file,
      ]),
  );
  assert.ok(
    Object.keys(selectedFiles).length > 0,
    "The independent oracle must contain expected files inside the selected range",
  );
  return selectedFiles;
}

export async function assertOracleOutputFiles(
  files,
  expectedFiles,
  expectedOutputRoot,
  hashFile,
) {
  const rootPrefix = `${expectedOutputRoot}/`;
  const actual = files.map((file) => {
    assert.equal(typeof file.relative_path, "string");
    assert.ok(file.relative_path.startsWith(rootPrefix));
    const relativePath = file.relative_path.slice(rootPrefix.length);
    assert.ok(relativePath.length > 0);
    assert.ok(!relativePath.startsWith("/"));
    assert.ok(!relativePath.split("/").includes(".."));
    assert.ok(!relativePath.includes("\\"));
    return [relativePath, { size: file.size, sha256: file.sha256 }];
  });
  const ordered = (entries) =>
    entries.sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0,
    );
  assert.deepEqual(
    ordered(actual),
    ordered(Object.entries(expectedFiles)),
    "Published file paths, sizes and SHA-256 values must exactly match the independent oracle",
  );
  for (const file of files) {
    const expected = expectedFiles[file.relative_path.slice(rootPrefix.length)];
    assert.equal(await hashFile(file.path), expected.sha256);
  }
}

export async function runWithCleanup(operation, cleanup) {
  let result;
  let operationFailed = false;
  let operationFailure;
  try {
    result = await operation();
  } catch (cause) {
    operationFailed = true;
    operationFailure = cause;
  }

  let cleanupFailed = false;
  let cleanupFailure;
  try {
    await cleanup();
  } catch (cause) {
    cleanupFailed = true;
    cleanupFailure = cause;
  }

  if (operationFailed && cleanupFailed)
    throw new AggregateError(
      [operationFailure, cleanupFailure],
      "Unblob acceptance and cleanup both failed",
    );
  if (operationFailed) throw operationFailure;
  if (cleanupFailed) throw cleanupFailure;
  return result;
}

export async function closeClientAndRemoveWorkspace(
  closeClient,
  workspace,
  removeWorkspace,
) {
  const failures = [];
  try {
    await closeClient();
  } catch (cause) {
    failures.push(cause);
  }
  try {
    await removeWorkspace(workspace);
  } catch (cause) {
    failures.push(cause);
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, "Unblob verification cleanup failed");
}
