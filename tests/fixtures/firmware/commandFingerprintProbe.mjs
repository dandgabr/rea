import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readlinkSync } from "node:fs";
import { open, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [
  serviceModule,
  compositionModule,
  commandModule,
  root,
  mode,
  requestedChunk = "1",
] = process.argv.slice(2);
const { FirmwareAnalysisService } = await import(serviceModule);
const { createFirmwareAnalysisProvider } = await import(compositionModule);
const { resolveFirmwareCommand } = await import(commandModule);
const executable = join(root, "actual-tool");
const selected = join(root, "selected-entrypoint");
const input = join(root, "input.bin");
const abortChunk = Number(requestedChunk);
assert.ok(Number.isInteger(abortChunk) && abortChunk >= 1 && abortChunk <= 16);
const bytes = Buffer.alloc(1024 * 1024, 0x61);
const digest = createHash("sha256").update(bytes).digest("hex");
await writeFile(executable, bytes, { mode: 0o700 });
await symlink("actual-tool", selected);
await writeFile(input, "abc");
const admitted = await resolveFirmwareCommand(
  { REA_UNBLOB_COMMAND: selected, REA_UNBLOB_RUNTIME_ROOT: root },
  "unblob",
  "inspect_firmware_regions",
);
assert.equal(admitted.command, selected);
assert.equal(admitted.resolvedCommand, executable);
assert.equal(admitted.sha256, digest);

const descriptor = await open(executable, "r");
const prototype = Object.getPrototypeOf(descriptor);
const originalRead = prototype.read;
const originalTimeout = AbortSignal.timeout;
await descriptor.close();
const controller = new AbortController();
const handles = new Set();
const closeControls = [];
let allowClose = mode !== "cleanup";
const events = [];
let launches = 0;
const service = new FirmwareAnalysisService(
  createFirmwareAnalysisProvider(
    {
      REA_UNBLOB_COMMAND: selected,
      REA_UNBLOB_RUNTIME_ROOT: root,
    },
    async () => {
      launches++;
      throw Error("Canceled fingerprint must not launch a producer");
    },
  ),
);
if (mode === "deadline") AbortSignal.timeout = () => controller.signal;
prototype.read = async function (...args) {
  const tracked = readlinkSync(`/proc/self/fd/${this.fd}`) === executable;
  if (tracked && !handles.has(this)) {
    handles.add(this);
    if (mode === "cleanup") {
      const originalClose = this.close.bind(this);
      closeControls.push({ handle: this, originalClose });
      this.close = async () => {
        if (!allowClose)
          throw Error("Injected selected executable close failure");
        await originalClose();
      };
    }
  }
  const observed = await originalRead.apply(this, args);
  if (tracked && observed.bytesRead > 0) {
    events.push({
      bytes: observed.bytesRead,
      afterAbort: controller.signal.aborted,
    });
    if (!controller.signal.aborted && events.length === abortChunk)
      controller.abort(
        mode === "deadline"
          ? new DOMException("Controlled deadline", "TimeoutError")
          : undefined,
      );
  }
  return observed;
};
try {
  const outcome = await service.execute(
    "inspect_firmware_regions",
    {
      path: input,
      provider_id: "unblob",
    },
    mode === "deadline" ? undefined : { signal: controller.signal },
  );
  assert.equal(outcome.ok, false);
  assert.equal(
    outcome.error._tag,
    mode === "cleanup"
      ? "ProviderAdapterError"
      : mode === "deadline"
        ? "AnalysisTimeoutError"
        : "AnalysisCancelledError",
  );
  if (mode === "cleanup") {
    assert.equal(outcome.error.cleanupIncomplete, true);
    assert.ok(outcome.error.cleanupResources.includes(executable));
    assert.equal(outcome.error.diagnostics.primary_error.code, "cancelled");
    const refused = await service.execute("inspect_firmware_regions", {
      path: input,
      provider_id: "unblob",
    });
    assert.equal(refused.ok, false);
    assert.equal(refused.error.cleanupIncomplete, true);
    assert.equal(handles.size, 1);
    await assert.rejects(service.close());
    allowClose = true;
    await service.close();
  }
  assert.equal(outcome.error.operation, "inspect_firmware_regions");
  assert.equal(launches, 0);
  assert.equal(
    events.length,
    abortChunk,
    "Fingerprint must stop at the aborting chunk",
  );
  assert.ok(events.every((event) => event.bytes === 64 * 1024));
  assert.equal(events.filter((e) => e.afterAbort).length, 0);
  assert.equal(handles.size, 1);
  for (const handle of handles) {
    assert.equal(handle.fd, -1);
    await assert.rejects(handle.stat(), { code: "EBADF" });
  }
  assert.equal(
    createHash("sha256")
      .update(await readFile(executable))
      .digest("hex"),
    digest,
  );
  assert.equal(await readFile(input, "utf8"), "abc");
  console.log(
    JSON.stringify({
      mode,
      positive_digest: digest,
      invocation: "preserved",
      bytes_read: events.reduce((total, event) => total + event.bytes, 0),
      chunks: events.length,
      chunks_after_abort: 0,
      closed_handles: handles.size,
      producer_launches: launches,
      error: outcome.error._tag,
    }),
  );
} finally {
  prototype.read = originalRead;
  AbortSignal.timeout = originalTimeout;
  for (const { handle, originalClose } of closeControls) {
    handle.close = originalClose;
    if (handle.fd >= 0) await originalClose();
  }
  await service.close();
}
