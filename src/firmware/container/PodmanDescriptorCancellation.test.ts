import { createHash } from "node:crypto";
import { open, readFile, readlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { observePodmanDatabase } from "./PodmanDatabase.js";
import { identifyPodmanProfileFile } from "./PodmanProfileFiles.js";
import type { PodmanExistingStoreProfile } from "./PodmanStoreProfile.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";

it.each(["close", "close-cancel", "primary-with-late-cancel"] as const)(
  "exposes the retained source FD under %s and resolves the same public error on retry",
  async (mode) => {
    const root = await createTestTempDirectory("rea-podman-source-close-");
    const path = join(root, "source.bin");
    await writeFile(path, "source bytes");
    const scope = new ArtifactResourceScope();
    const controller = new AbortController();
    const reason = new Error("cancel during source close");
    const primary = new AnalysisOutputError(
      "firmware_container_runtime",
      "source read failed before final cancellation",
      {
        capturedOutput: {
          stdout: "prior capture",
          stderr: "",
          truncated: false,
        },
        partialObservation: {
          kind: "firmware",
          result: { stage: "source read" },
        },
      },
    );
    const sample = await open(path, "r");
    const prototype = Object.getPrototypeOf(sample) as typeof sample;
    await sample.close();
    const originalRead = prototype.read;
    const readSpy = vi
      .spyOn(prototype, "read")
      .mockImplementation(async function (
        this: typeof sample,
        ...args: Parameters<typeof originalRead>
      ) {
        if (mode === "primary-with-late-cancel") throw primary;
        return Reflect.apply(originalRead, this, args);
      });
    const close = OwnedFileHandle.prototype.close;
    let allowClose = false;
    let sourceCloses = 0;
    const closeSpy = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (this: OwnedFileHandle) {
        if (
          this.handle.fd >= 0 &&
          (await readlink(`/proc/self/fd/${this.handle.fd}`)) === path
        ) {
          sourceCloses++;
          if (!allowClose) {
            if (mode !== "close") controller.abort(reason);
            throw Error("source FD close refused");
          }
        }
        await Reflect.apply(close, this, []);
      });
    let launches = 0;
    try {
      const failure = await observePodmanDatabase(
        { database: { path } } as PodmanExistingStoreProfile,
        controller.signal,
        scope,
        async () => {
          launches++;
          throw Error("no launch after source close failure");
        },
      ).catch((cause: unknown) => cause);
      expect(failure).toBeInstanceOf(AnalysisError);
      if (!(failure instanceof AnalysisError))
        throw Error("Expected analysis error");
      expect(projectAnalysisError(failure)).toMatchObject({
        code: "cleanup_incomplete",
        details: { resources: [path] },
      });
      expect(scope.cleanupResources).toEqual([path]);
      expect(sourceCloses).toBe(1);
      expect(launches).toBe(0);
      if (mode !== "close")
        expect(failure.diagnostics).toMatchObject({
          primary_error: {
            code: mode === "close-cancel" ? "cancelled" : "unreadable_output",
          },
        });
      if (mode === "primary-with-late-cancel")
        expect(failure).toMatchObject({
          capturedOutput: primary.capturedOutput,
          partialObservation: primary.partialObservation,
        });
      allowClose = true;
      await scope.retryCleanup();
      expect(sourceCloses).toBe(2);
      expect(failure.cleanupIncomplete).toBe(false);
      expect(failure.cleanupResources).toEqual([]);
      if (mode !== "close")
        expect(projectAnalysisError(failure).code).toBe(
          mode === "close-cancel" ? "cancelled" : "unreadable_output",
        );
      expect(launches).toBe(0);
    } finally {
      allowClose = true;
      await scope.close();
      readSpy.mockRestore();
      closeSpy.mockRestore();
    }
  },
);

it.each(["identity", "database"] as const)(
  "cancels %s after real bytes without a competing FD close",
  async (mode) => {
    const root = await createTestTempDirectory("rea-podman-descriptor-");
    const path = join(root, "source.bin");
    const bytes = Buffer.alloc(128 * 1024, 0x51);
    await writeFile(path, bytes);
    const sample = await open(path, "r");
    const prototype = Object.getPrototypeOf(sample) as typeof sample;
    await sample.close();
    const scope = new ArtifactResourceScope();
    const controller = new AbortController();
    const read = prototype.read;
    let bytesRead = 0;
    const readSpy = vi
      .spyOn(prototype, "read")
      .mockImplementation(async function (
        this: typeof sample,
        ...args: Parameters<typeof read>
      ) {
        const result = await Reflect.apply(read, this, args);
        if (result.bytesRead > 0 && bytesRead === 0) {
          bytesRead = result.bytesRead;
          controller.abort(new Error("abort after actual descriptor bytes"));
        }
        return result;
      });
    const stream = prototype.createReadStream;
    const streamSpy = vi
      .spyOn(prototype, "createReadStream")
      .mockImplementation(function (
        this: typeof sample,
        ...args: Parameters<typeof stream>
      ) {
        const stream = Reflect.apply(prototypeStream, this, args);
        stream.once("data", () =>
          controller.abort(new Error("abort after actual stream bytes")),
        );
        return stream;
      });
    const prototypeStream = stream;
    const close = OwnedFileHandle.prototype.close;
    const closedFds: number[] = [];
    const owners = new Set<OwnedFileHandle>();
    const closeSpy = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(function (this: OwnedFileHandle) {
        if (!owners.has(this)) {
          owners.add(this);
          closedFds.push(this.handle.fd);
        }
        return Reflect.apply(close, this, []);
      });
    let launches = 0;
    const selected = { database: { path } } as PodmanExistingStoreProfile;
    try {
      const failure = await (
        mode === "identity"
          ? identifyPodmanProfileFile(path, controller.signal, scope)
          : observePodmanDatabase(
              selected,
              controller.signal,
              scope,
              async () => {
                launches++;
                throw Error("no helper allowed after cancellation");
              },
            )
      ).catch((cause: unknown) => cause);
      expect(controller.signal.aborted).toBe(true);
      expect(closedFds, "actual owner FD observations before close").toEqual(
        expect.arrayContaining([expect.any(Number)]),
      );
      expect(
        closedFds.every((fd) => fd >= 0),
        `preclose FDs ${closedFds}`,
      ).toBe(true);
      expect(streamSpy).not.toHaveBeenCalled();
      expect(bytesRead).toBe(64 * 1024);
      expect(failure).toMatchObject(
        mode === "database"
          ? { _tag: "AnalysisCancelledError", cleanupIncomplete: false }
          : { message: "abort after actual descriptor bytes" },
      );
      expect(launches).toBe(0);
      await scope.close();
    } finally {
      readSpy.mockRestore();
      streamSpy.mockRestore();
      closeSpy.mockRestore();
    }
    expect(await readFile(path)).toEqual(bytes);
    const identity = await identifyPodmanProfileFile(
      path,
      new AbortController().signal,
      new ArtifactResourceScope(),
    );
    expect({ size: identity.size, sha256: identity.sha256 }).toEqual({
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  },
);

const partialWriteCases = Array.from(
  { length: 8 },
  (_, index) => `partial-${(0x504f4431 + index * 1664525) >>> 0}`,
);
it.each([
  "partial",
  "zero",
  "write-error",
  "write-cancel",
  "output-close-cancel",
  "input-close-cancel",
  ...partialWriteCases,
] as const)("owns snapshot read/write/cleanup under %s", async (mode) => {
  const root = await createTestTempDirectory("rea-podman-copy-");
  const path = join(root, "source.bin");
  const bytes = Buffer.alloc(128 * 1024, 0x72);
  await writeFile(path, bytes);
  const sample = await open(path, "r");
  const prototype = Object.getPrototypeOf(sample) as typeof sample;
  await sample.close();
  const scope = new ArtifactResourceScope();
  const controller = new AbortController();
  const originalRead = prototype.read,
    originalWrite = prototype.write;
  let inputFd = -1,
    outputFd = -1,
    writes = 0,
    outputCloses = 0,
    inputCloses = 0,
    copied: Buffer | undefined;
  const readSpy = vi
    .spyOn(prototype, "read")
    .mockImplementation(async function (
      this: typeof sample,
      ...args: Parameters<typeof originalRead>
    ) {
      const result = await Reflect.apply(originalRead, this, args);
      if (result.bytesRead > 0 && inputFd === -1) {
        inputFd = this.fd;
        if (mode === "input-close-cancel")
          controller.abort(new Error("cancel after source read"));
      }
      return result;
    });
  const writeSpy = vi
    .spyOn(prototype, "write")
    .mockImplementation(async function (
      this: typeof sample,
      ...args: unknown[]
    ) {
      outputFd = this.fd;
      writes++;
      if (mode === "zero") return { bytesWritten: 0, buffer: args[0] };
      if (mode === "write-error")
        throw new Error("actual output write refusal");
      const partial = [...args];
      if (mode.startsWith("partial") && typeof partial[2] === "number")
        partial[2] = Math.min(
          mode === "partial" ? 1024 : 1 + (Number(mode.slice(8)) % 8192),
          partial[2],
        );
      const result = await Reflect.apply(originalWrite, this, partial);
      if (mode === "write-cancel" || mode === "output-close-cancel")
        controller.abort(new Error("cancel after actual output write"));
      return result;
    });
  const originalClose = OwnedFileHandle.prototype.close;
  const closeSpy = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(function (this: OwnedFileHandle) {
      if (this.handle.fd === outputFd && outputFd >= 0) {
        outputCloses++;
        if (mode === "output-close-cancel" && outputCloses <= 2)
          return Promise.reject(new Error("retained exact snapshot FD close"));
      }
      if (this.handle.fd === inputFd && inputFd >= 0) {
        inputCloses++;
        if (mode === "input-close-cancel" && inputCloses === 1)
          return Promise.reject(new Error("retained exact source FD close"));
      }
      return Reflect.apply(originalClose, this, []);
    });
  let launches = 0,
    snapshotPath: string | undefined;
  const { PrivateRuntimeRoot } =
    await import("../../process/PrivateRuntimeRoot.js");
  const originalCreate = PrivateRuntimeRoot.create;
  const createSpy = vi
    .spyOn(PrivateRuntimeRoot, "create")
    .mockImplementation(async (options) => {
      const result = await originalCreate({ ...options, parent: root });
      if (options?.prefix === "rea-podman-db-admission-")
        snapshotPath = join(result.path, "db.sql");
      return result;
    });
  try {
    const failure = await observePodmanDatabase(
      { database: { path } } as PodmanExistingStoreProfile,
      controller.signal,
      scope,
      async (options) => {
        launches++;
        copied = await readFile(join(options.cwd!, "db.sql"));
        throw Error("stop at owned parser boundary");
      },
    ).catch((cause: unknown) => cause);
    expect(snapshotPath).toBeDefined();
    if (mode.startsWith("partial")) {
      expect(launches).toBe(1);
      expect(copied).toEqual(bytes);
      expect(writes).toBeGreaterThan(2);
    } else {
      expect(launches).toBe(0);
      if (mode.endsWith("cancel")) expect(controller.signal.aborted).toBe(true);
      if (mode === "zero")
        expect(failure).toMatchObject({
          userMessage: expect.stringContaining("no progress"),
        });
      if (mode === "write-error")
        expect(failure).toMatchObject({
          userMessage: expect.stringContaining("output write refusal"),
        });
    }
    if (mode === "output-close-cancel") {
      expect(failure).toMatchObject({
        cleanupIncomplete: true,
        diagnostics: {
          primary_error: {
            code: "cleanup_incomplete",
            details: { diagnostics: { primary_error: { code: "cancelled" } } },
          },
        },
      });
      expect(await readFile(snapshotPath!)).toEqual(
        bytes.subarray(0, 64 * 1024),
      );
      expect(outputCloses).toBe(2);
      await scope.retryCleanup();
      expect(outputCloses).toBe(3);
      expect(writes).toBe(1);
    } else if (mode === "input-close-cancel") {
      expect(failure).toMatchObject({
        cleanupIncomplete: true,
        diagnostics: { primary_error: { code: "cancelled" } },
      });
      await scope.retryCleanup();
      expect(inputCloses).toBe(2);
      expect(writes).toBe(0);
    }
    await expect(readFile(snapshotPath!)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await scope.close();
  } finally {
    await scope.close();
    readSpy.mockRestore();
    writeSpy.mockRestore();
    closeSpy.mockRestore();
    createSpy.mockRestore();
  }
  expect(await readFile(path)).toEqual(bytes);
});
