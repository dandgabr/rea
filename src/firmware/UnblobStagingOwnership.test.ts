import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { readFile, readlink, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { firmwareInputSchemas } from "../domain/firmware/firmwareAnalysis.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { FirmwareProvider } from "./FirmwareProvider.js";

const extractionFrame = () => {
  const bytes = Buffer.from("payload");
  const path = Buffer.from("payload.bin");
  const report = Buffer.from(
    JSON.stringify([
      {
        task: {
          path: "/tmp/rea-input",
          depth: 0,
          blob_id: "",
          is_multi_file: false,
        },
        reports: [
          {
            __typename__: "StatReport",
            path: "/tmp/rea-input",
            size: 6,
            is_file: true,
            is_dir: false,
            is_link: false,
            link_target: null,
          },
          {
            __typename__: "HashReport",
            sha256: createHash("sha256").update("source").digest("hex"),
          },
        ],
        subtasks: [],
      },
    ]),
  );
  const metrics = Buffer.from(
    JSON.stringify({
      stdout_observed_bytes: 0,
      stderr_observed_bytes: 0,
      stdout_truncated: false,
      stderr_truncated: false,
    }),
  );
  const header = Buffer.alloc(40);
  Buffer.from("REAUB1\0\0").copy(header);
  header.writeUInt32BE(report.length, 20);
  header.writeUInt32BE(metrics.length, 24);
  header.writeUInt32BE(1, 28);
  header.writeBigUInt64BE(BigInt(bytes.length), 32);
  const entry = Buffer.alloc(45);
  entry.writeUInt8(1, 0);
  entry.writeUInt16BE(path.length, 1);
  entry.writeBigUInt64BE(BigInt(bytes.length), 5);
  createHash("sha256").update(bytes).digest().copy(entry, 13);
  return Buffer.concat([header, report, metrics, entry, path, bytes]);
};

it.each([
  "none",
  "create",
  "write",
  "readback",
  "body-cancel",
  "process-cancel",
] as const)(
  "owns transfer, publication and cleanup with staging fault %s",
  async (stage) => {
    const root = await createTestTempDirectory("rea-unblob-staging-owner-");
    const command = join(root, "unblob");
    const input = join(root, "input.bin");
    await writeFile(command, "#!/bin/sh\n", { mode: 0o700 });
    await writeFile(input, "source");
    const close = OwnedFileHandle.prototype.close;
    let allowClose = false;
    let failedOwner: OwnedFileHandle | undefined;
    let payloadCloses = 0;
    let workspace = "";
    let calls = 0;
    const closeFailure = Error(`staging ${stage} close refused`);
    const controller = new AbortController();
    const cancellation = Error("cancel while waiting for file body");
    const closeSpy = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (this: OwnedFileHandle) {
        if (this.handle.fd >= 0) {
          const path = await readlink(`/proc/self/fd/${this.handle.fd}`);
          if (stage === "create" && path.endsWith("/unblob-transfer-stage"))
            failedOwner ??= this;
          if (
            stage !== "none" &&
            path.endsWith("/unblob-transfer-stage/payload.bin") &&
            failedOwner === undefined
          ) {
            payloadCloses++;
            if (payloadCloses === (stage === "readback" ? 2 : 1))
              failedOwner = this;
          }
        }
        if (this === failedOwner && !allowClose) throw closeFailure;
        await Reflect.apply(close, this, []);
      });
    const provider = new FirmwareProvider(
      { REA_UNBLOB_COMMAND: command, REA_UNBLOB_RUNTIME_ROOT: root },
      async (options) => {
        calls++;
        workspace = options.cwd!;
        const child = Object.assign(new EventEmitter(), {
          stdout: new PassThrough(),
          stderr: new PassThrough(),
          exitCode: null,
          signalCode: null,
          kill: () => false,
        });
        setImmediate(() => {
          if (calls === 2 && stage === "process-cancel") {
            setImmediate(() => controller.abort(cancellation));
          } else if (calls === 2 && stage === "body-cancel") {
            const frame = extractionFrame();
            child.stdout.write(frame.subarray(0, frame.length - 7));
            setImmediate(() => controller.abort(cancellation));
          } else
            child.stdout.end(
              calls === 1 ? Buffer.from("26.6.4\n") : extractionFrame(),
            );
          child.stderr.end();
          child.emit("exit", 0, null);
          child.emit("close", 0, null);
        });
        return {
          process: child,
          ownership: {
            runId: options.runId,
            leaderPid: 123,
            processGroupId: 123,
          },
          cleanup: async () =>
            calls === 2 && stage === "process-cancel" && !allowClose
              ? { cleaned: false, reason: "service cleanup pending" }
              : { cleaned: true, signaled: false },
        };
      },
    );
    try {
      const result = await provider.execute(
        {
          operation: "extract_firmware",
          input: firmwareInputSchemas.extract_firmware.parse({
            path: input,
            output_directory: join(root, "output"),
          }),
        },
        { signal: controller.signal },
      );
      if (stage === "none") {
        expect(result.ok).toBe(true);
        expect(
          await readFile(join(root, "output", "payload.bin"), "utf8"),
        ).toBe("payload");
        await provider.close();
        await expect(stat(workspace)).rejects.toMatchObject({ code: "ENOENT" });
        expect(calls).toBe(2);
        return;
      }
      expect(result.ok).toBe(false);
      if (result.ok) throw Error("Expected retained staging cleanup");
      if (stage !== "process-cancel") expect(failedOwner).toBeDefined();
      expect(projectAnalysisError(result.error)).toMatchObject({
        code: "cleanup_incomplete",
        details: { diagnostics: { primary_error: expect.any(Object) } },
      });
      expect(result.error.cleanupResources).toContain(
        join(workspace, "unblob-transfer-stage"),
      );
      if (stage !== "create" && stage !== "process-cancel")
        expect(result.error.partialObservation).toMatchObject({
          kind: "firmware",
          result: { publication_state: "not_committed" },
        });
      await expect(provider.close()).rejects.toMatchObject({
        cleanupIncomplete: true,
      });
      await stat(workspace);
      if (stage !== "process-cancel")
        expect(failedOwner?.handle.fd).toBeGreaterThanOrEqual(0);
      expect(calls).toBe(stage === "create" ? 1 : 2);
      allowClose = true;
      await provider.close();
      if (stage !== "process-cancel") expect(failedOwner?.handle.fd).toBe(-1);
      expect(result.error).toBeInstanceOf(AnalysisError);
      expect(result.error.cleanupIncomplete).toBe(false);
      expect(result.error.cleanupResources).toEqual([]);
      if (stage === "body-cancel" || stage === "process-cancel") {
        expect(projectAnalysisError(result.error).code).toBe("cancelled");
        expect(result.error.cleanupPrimary?.cause).toBe(cancellation);
      }
      await expect(stat(workspace)).rejects.toMatchObject({ code: "ENOENT" });
      expect(calls).toBe(stage === "create" ? 1 : 2);
    } finally {
      allowClose = true;
      // Only the uncorrected implementation loses this owner; keep RED runs hygienic.
      await failedOwner?.close();
      await provider.close();
      closeSpy.mockRestore();
    }
  },
);
