import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readlinkSync } from "node:fs";
import { mkdir, open, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [filesModule, root, mode, requestedCases = "0"] = process.argv.slice(2);
const {
  hashFirmwareFile,
  snapshotFirmware,
  readFirmwareReport,
  withFirmwareFiles,
} = await import(filesModule);
const path = join(root, "input.bin");
const bytes = mode === "report" ? "{invalid-json" : "abc";
await writeFile(path, bytes);
assert.equal(
  await hashFirmwareFile(path),
  createHash("sha256").update(bytes).digest("hex"),
);
const second = join(root, "second.bin");
if (mode === "multiple") await writeFile(second, "second");
if (mode === "input-admission" || mode === "report-admission") {
  await rm(path);
  await mkdir(path);
}
const staging = join(root, "staging");
await mkdir(staging);
if (mode === "snapshot") await mkdir(join(staging, "source"));
const descriptor = await open(path, "r");
const prototype = Object.getPrototypeOf(descriptor);
const originalStat = prototype.stat;
await descriptor.close();
let allowClose = false;
const handles = [];
prototype.stat = async function (...args) {
  if (
    this.fd >= 0 &&
    (readlinkSync(`/proc/self/fd/${this.fd}`) === path ||
      readlinkSync(`/proc/self/fd/${this.fd}`) === second) &&
    !handles.some((entry) => entry.handle === this)
  ) {
    const originalClose = this.close.bind(this);
    handles.push({ handle: this, originalClose });
    this.close = async () => {
      if (!allowClose) throw Error("Injected owned descriptor close failure");
      await originalClose();
    };
  }
  return originalStat.apply(this, args);
};
try {
  let failure;
  try {
    if (mode === "multiple")
      await withFirmwareFiles(
        [path, second],
        "extract_firmware",
        undefined,
        undefined,
        async () => {
          throw Error("First independently observed operation failure");
        },
      );
    if (mode === "hash") await hashFirmwareFile(path);
    if (mode === "report" || mode === "report-admission")
      await readFirmwareReport(path, "inspect_firmware_regions");
    if (mode === "snapshot" || mode === "input-admission")
      await snapshotFirmware(
        { operation: "inspect_firmware_regions", input: { path } },
        staging,
        new AbortController().signal,
      );
  } catch (cause) {
    failure = cause;
  }
  assert.equal(
    failure?._tag,
    "ProviderAdapterError",
    "Failed close must retain a typed cleanup owner",
  );
  assert.equal(failure.cleanupIncomplete, true);
  assert.ok(failure.cleanupResources.includes(path));
  if (mode === "report")
    assert.equal(
      failure.diagnostics.primary_error.details.reason,
      "Tool report is not valid complete JSON",
    );
  if (mode === "multiple") {
    assert.ok(failure.cleanupResources.includes(second));
    assert.equal(
      failure.diagnostics.primary_error.reason,
      "First independently observed operation failure",
    );
  }
  if (mode === "snapshot")
    assert.match(failure.diagnostics.primary_error.reason, /EEXIST/);
  if (mode === "input-admission")
    assert.equal(failure.diagnostics.primary_error.code, "invalid_request");
  if (mode === "report-admission")
    assert.equal(failure.diagnostics.primary_error.code, "unreadable_output");
  assert.ok(
    failure.resourceScope,
    "Standalone file caller needs the same retryable resource scope",
  );
  await assert.rejects(failure.resourceScope.retryCleanup());
  assert.equal(handles.length, mode === "multiple" ? 2 : 1);
  assert.ok(handles[0].handle.fd >= 0);
  allowClose = true;
  await failure.resourceScope.retryCleanup();
  for (const { handle } of handles) {
    assert.equal(handle.fd, -1);
    await assert.rejects(handle.stat(), { code: "EBADF" });
  }
  if (!mode.endsWith("admission"))
    assert.equal(await readFile(path, "utf8"), bytes);
  let malformedCases = 0;
  if (mode === "report" && Number(requestedCases) > 0) {
    let seed = 0x5c0fe;
    for (let index = 0; index < Number(requestedCases); index++) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      const invalid = Buffer.concat([
        Buffer.from('{"value":"'),
        Buffer.from([0xf5 + (seed % 11)]),
        Buffer.from('"}'),
      ]);
      await writeFile(path, invalid);
      const invalidResult = await readFirmwareReport(
        path,
        "inspect_firmware_regions",
      ).catch((error) => error);
      assert.equal(invalidResult._tag, "AnalysisOutputError");
      assert.equal(
        invalidResult.reason,
        "Tool report is not valid complete JSON",
      );
      assert.ok(handles.every(({ handle }) => handle.fd === -1));
      malformedCases++;
    }
  }
  console.log(
    JSON.stringify({
      mode,
      retained: true,
      retried_close: true,
      source: "unchanged",
      malformed_cases: malformedCases,
    }),
  );
} finally {
  prototype.stat = originalStat;
  for (const { handle, originalClose } of handles) {
    handle.close = originalClose;
    if (handle.fd >= 0) await originalClose();
  }
}
