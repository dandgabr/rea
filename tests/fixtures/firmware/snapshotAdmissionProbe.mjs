import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [snapshotModulePath, root, mode] = process.argv.slice(2);
if (snapshotModulePath === undefined || root === undefined)
  throw new Error(
    "Firmware snapshot admission probe requires module and root paths",
  );
const { snapshotFirmware, hashFirmwareFile, readFirmwareReport } = await import(
  pathToFileURL(snapshotModulePath)
);
const request = (path) => ({
  operation: "inspect_firmware_regions",
  input: { path, provider_id: "binwalk" },
});

const path = join(root, "regular.bin");
const expectedDigest =
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
await writeFile(path, "abc");
if (mode === "snapshot") {
  const regularStage = join(root, "regular-stage");
  await mkdir(regularStage);
  const regular = await snapshotFirmware(
    request(path),
    regularStage,
    new AbortController().signal,
  );
  assert.equal(await readFile(regular.inputPath, "utf8"), "abc");
  assert.equal(regular.selection.sha256, expectedDigest);
} else if (mode === "hash") {
  assert.equal(await hashFirmwareFile(path), expectedDigest);
} else if (mode === "report") {
  await writeFile(path, JSON.stringify({ producer: "retained" }));
  assert.deepEqual(await readFirmwareReport(path, "inspect_firmware_regions"), {
    producer: "retained",
  });
} else {
  throw new Error("Expected snapshot, hash or report admission probe mode");
}
assert.equal(
  await readFile(path, "utf8"),
  mode === "report" ? '{"producer":"retained"}' : "abc",
);
const fifo = join(root, "writer-free-fifo");
execFileSync("mkfifo", [fifo]);
if (mode === "snapshot") {
  const fifoStage = join(root, "fifo-stage");
  await mkdir(fifoStage);
  await assert.rejects(
    snapshotFirmware(request(fifo), fifoStage, new AbortController().signal),
    { _tag: "AnalysisInputError" },
  );
  await assert.rejects(readdir(join(fifoStage, "source")), { code: "ENOENT" });
} else if (mode === "hash") {
  await assert.rejects(hashFirmwareFile(fifo), /Not a regular file/);
} else {
  await assert.rejects(readFirmwareReport(fifo, "inspect_firmware_regions"), {
    _tag: "AnalysisOutputError",
  });
}
process.stdout.write(
  JSON.stringify({ regular: "accepted", fifo: "rejected", mode }),
);
