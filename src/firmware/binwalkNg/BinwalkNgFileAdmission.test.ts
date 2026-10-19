import { FirmwareProvider } from "../FirmwareProvider.js";
import { firmwareInputSchemas } from "../../domain/firmware/firmwareAnalysis.js";
import { execFile, spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { FirmwareFileAccess } from "../FirmwareFiles.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
it.each(["hash", "snapshot", "report", "png", "carving"])(
  "rejects a writer-free FIFO without blocking descriptor admission: %s",
  async (mode) => {
    const root = await createTestTempDirectory("rea-ng-fifo-");
    const path = join(root, "input.bin_0_gzip.raw");
    const stage = join(root, "stage");
    await mkdir(stage);
    await promisify(execFile)("/usr/bin/mkfifo", [path]);
    const child = spawn(
      process.execPath,
      [
        resolve("tests/fixtures/firmware/binwalkNgFileAdmission.mjs"),
        mode,
        path,
        stage,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "",
      err = "",
      expired = false;
    let bound: NodeJS.Timeout | undefined;
    const watchdog = setTimeout(() => {
      expired = true;
      child.kill("SIGKILL");
    }, 10000);
    child.stdout.on("data", (data) => {
      out += String(data);
      if (out.includes("entered") && bound === undefined)
        bound = setTimeout(() => {
          expired = true;
          child.kill("SIGKILL");
        }, 800);
    });
    child.stderr.on("data", (data) => {
      err += String(data);
    });
    const code = await new Promise<number | null>((r) =>
      child.once("close", r),
    );
    clearTimeout(watchdog);
    clearTimeout(bound);
    expect({ expired, code, err }).toEqual({
      expired: false,
      code: 0,
      err: "",
    });
    expect(out).toContain("regular-file rejection");
  },
  15000,
);
it("retains every generic descriptor close failure for caller-owned scope retry", async () => {
  const root = await createTestTempDirectory("rea-ng-file-close-");
  const path = join(root, "input.json");
  await writeFile(path, '{"ok":true}');
  for (const mode of ["hash", "snapshot", "report"]) {
    const files = new FirmwareFileAccess();
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockRejectedValueOnce(new Error("injected descriptor close"));
    const stage = join(root, mode);
    await mkdir(stage);
    try {
      const signal = new AbortController().signal;
      const work =
        mode === "hash"
          ? files.hash(path, signal)
          : mode === "snapshot"
            ? files.snapshot(
                { operation: "inspect_firmware_regions", input: { path } },
                stage,
                signal,
              )
            : files.report(path, "inspect_firmware_regions", signal);
      await expect(work).rejects.toMatchObject({
        name: "ArtifactReaderFailure",
        cleanup: { resources: [path] },
        cleanupLease: expect.any(Object),
      });
      expect(close).toHaveBeenCalledTimes(1);
      await files.retryCleanup();
      expect(close).toHaveBeenCalledTimes(2);
    } finally {
      close.mockRestore();
      await files.close();
    }
  }
});

it("retains a descriptor whose authoritative admission and close both fail", async () => {
  const root = await createTestTempDirectory("rea-ng-admission-close-");
  const files = new FirmwareFileAccess();
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(new Error("admission close failure"))
    .mockRejectedValueOnce(new Error("retained close failure"));
  try {
    await expect(files.hash(root)).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      cleanup: { resources: [root] },
      cleanupLease: expect.any(Object),
    });
    expect(close).toHaveBeenCalledTimes(1);
    await expect(files.retryCleanup()).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      cleanup: { resources: [root] },
    });
    expect(close).toHaveBeenCalledTimes(2);
    await files.retryCleanup();
    expect(close).toHaveBeenCalledTimes(3);
  } finally {
    close.mockRestore();
    await files.close();
  }
});
it("legacy firmware owns and retries a generic fingerprint descriptor after cleanup failure", async () => {
  const provider = new FirmwareProvider({
    REA_BINWALK_COMMAND: "/usr/bin/true",
  });
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(new Error("fingerprint close failure"));
  try {
    const outcome = await provider.execute({
      operation: "inspect_firmware_regions",
      input: firmwareInputSchemas.inspect_firmware_regions.parse({
        path: "/unused-input.bin",
      }),
    });
    expect(outcome).toMatchObject({
      ok: false,
      error: {
        cleanupIncomplete: true,
        operation: "inspect_firmware_regions",
        cleanupResources: ["/usr/bin/true"],
      },
    });
    expect(close).toHaveBeenCalledTimes(1);
    await provider.close();
    expect(close).toHaveBeenCalledTimes(2);
  } finally {
    close.mockRestore();
    await provider.close();
  }
});

it("keeps report validation as the primary failure when its descriptor close also fails", async () => {
  const root = await createTestTempDirectory("rea-ng-report-close-");
  const path = join(root, "report.json");
  await writeFile(path, "{broken");
  const files = new FirmwareFileAccess();
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockRejectedValueOnce(new Error("report close failure"));
  try {
    await expect(
      files.report(path, "inspect_firmware_regions"),
    ).rejects.toMatchObject({
      name: "ArtifactReaderFailure",
      reason: "io",
      cleanup: { resources: [path] },
      fileCleanupFailure: expect.objectContaining({ path }),
    });
    await files.retryCleanup();
    expect(close).toHaveBeenCalledTimes(2);
  } finally {
    close.mockRestore();
    await files.close();
  }
});
