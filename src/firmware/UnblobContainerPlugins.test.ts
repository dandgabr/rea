import {
  mkdir,
  open,
  readFile,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { afterEach, expect, it as test, vi } from "vitest";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import { fingerprintUnblobPlugins } from "./UnblobPlugins.js";
import { stageUnblobContainerPlugins } from "./UnblobContainerPlugins.js";

const it = test.skipIf(process.platform !== "linux");
// A setup failure must not leave global FileHandle instrumentation in later cases.
afterEach(() => vi.restoreAllMocks());

it.each(["file", "tree"] as const)(
  "stages trusted %s bytes and namespace identity without losing empty directories",
  async (kind) => {
    const root = await createTestTempDirectory("rea-container-plugin-");
    const source = join(root, kind === "file" ? "plugin 🔧.py" : "plugins");
    if (kind === "tree") {
      await mkdir(source);
      await mkdir(join(source, "empty"));
      await mkdir(join(source, "nested"));
      await writeFile(
        join(source, "nested", "plugin.py"),
        "trusted plugin bytes",
      );
    } else await writeFile(source, "trusted plugin bytes");
    const scope = new ArtifactResourceScope();
    const signal = new AbortController().signal;
    const baseline = await fingerprintUnblobPlugins(
      source,
      "inspect_firmware_provider",
      signal,
      scope,
    );
    const staged = await stageUnblobContainerPlugins(
      baseline,
      join(root, "staged"),
      "inspect_firmware_provider",
      signal,
      scope,
    );
    expect(staged).toMatchObject({
      source_identity_sha256: baseline.identity_sha256,
      namespace_path:
        kind === "tree" ? "/rea-plugins" : "/rea-plugins/plugin 🔧.py",
      copied_bytes: 20,
      files: baseline.files,
      directories: kind === "tree" ? ["empty", "nested"] : [],
    });
    expect(
      await readFile(
        join(staged.host_path, baseline.files[0]!.relative_path),
        "utf8",
      ),
    ).toBe("trusted plugin bytes");
    expect(
      await fingerprintUnblobPlugins(
        source,
        "inspect_firmware_provider",
        signal,
        scope,
      ),
    ).toEqual(baseline);
    await scope.close();
  },
);

it.each([false, true])(
  "retains the actual staging descriptor after failed close (cancel=%s), then retries cleanup without copying",
  async (cancel) => {
    const root = await createTestTempDirectory("rea-container-plugin-close-");
    const source = join(root, "plugin.py");
    await writeFile(source, Buffer.alloc(128 * 1024, 0x61));
    const stage = join(root, "staged");
    const destination = join(stage, "plugin.py");
    const scope = new ArtifactResourceScope();
    const controller = new AbortController();
    const baseline = await fingerprintUnblobPlugins(
      source,
      "extract_firmware",
      controller.signal,
      scope,
    );
    const control = await open(source, "r");
    const prototype = Object.getPrototypeOf(control);
    await control.close();
    const originalRead = prototype.read;
    const originalWrite = prototype.write;
    const originalClose = OwnedFileHandle.prototype.close;
    let writes = 0;
    let reads = 0;
    let ownedDescriptor: number | undefined;
    let refuseClose = true;
    const read = vi.spyOn(prototype, "read").mockImplementation(async function (
      this: typeof control,
      ...args: unknown[]
    ) {
      const path = await readlink(`/proc/self/fd/${this.fd}`);
      const result = await originalRead.apply(this, args);
      if (path === source) {
        reads++;
        if (cancel) controller.abort();
      }
      return result;
    });
    const write = vi
      .spyOn(prototype, "write")
      .mockImplementation(async function (
        this: typeof control,
        ...args: unknown[]
      ) {
        if ((await readlink(`/proc/self/fd/${this.fd}`)) === destination) {
          writes++;
          ownedDescriptor = this.fd;
        }
        return await originalWrite.apply(this, args);
      });
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (
        this: OwnedFileHandle<typeof control>,
      ) {
        const path = await readlink(`/proc/self/fd/${this.handle.fd}`);
        if (
          path === destination &&
          (cancel || this.handle.fd === ownedDescriptor)
        ) {
          ownedDescriptor = this.handle.fd;
          if (refuseClose)
            throw new Error("injected staging descriptor close refusal");
        }
        return await originalClose.call(this);
      });
    try {
      const failure = await stageUnblobContainerPlugins(
        baseline,
        stage,
        "extract_firmware",
        controller.signal,
        scope,
      ).catch((cause: unknown) => cause);
      expect(failure).toMatchObject({
        cleanupIncomplete: true,
        cleanupResources: [destination],
      });
      expect(Reflect.get(failure as object, "resourceScope")).toBe(scope);
      if (cancel)
        expect(failure).toMatchObject({
          diagnostics: {
            primary_error: { code: "cancelled", category: "cancelled" },
          },
        });
      expect(ownedDescriptor).toBeDefined();
      expect(await readlink(`/proc/self/fd/${ownedDescriptor}`)).toBe(
        destination,
      );
      const readsBeforeRetry = reads;
      const writesBeforeRetry = writes;
      await expect(scope.retryCleanup()).rejects.toThrow();
      await expect(scope.close()).rejects.toThrow();
      expect(await readlink(`/proc/self/fd/${ownedDescriptor}`)).toBe(
        destination,
      );
      expect(reads).toBe(readsBeforeRetry);
      expect(writes).toBe(writesBeforeRetry);
      refuseClose = false;
      await scope.close();
      await expect(
        readlink(`/proc/self/fd/${ownedDescriptor}`),
      ).rejects.toMatchObject({ code: "ENOENT" });
      expect(reads).toBe(readsBeforeRetry);
      expect(writes).toBe(writesBeforeRetry);
      if (cancel) {
        expect(reads).toBe(1);
        expect(writes).toBe(0);
      }
    } finally {
      refuseClose = false;
      read.mockRestore();
      write.mockRestore();
      close.mockRestore();
      await scope.close();
    }
  },
);

it("rejects a writer-free FIFO replacing an admitted plugin promptly and preserves regular-file admission", async () => {
  const root = await createTestTempDirectory("rea-container-plugin-fifo-");
  const source = join(root, "plugin.py");
  await writeFile(source, "trusted");
  const scope = new ArtifactResourceScope();
  const signal = AbortSignal.timeout(1000);
  const baseline = await fingerprintUnblobPlugins(
    source,
    "extract_firmware",
    signal,
    scope,
  );
  await rm(source);
  await promisify(execFile)("/usr/bin/mkfifo", [source]);
  await expect(
    stageUnblobContainerPlugins(
      baseline,
      join(root, "fifo-stage"),
      "extract_firmware",
      signal,
      scope,
    ),
  ).rejects.toMatchObject({ code: "ENOTFILE" });
  expect(signal.aborted).toBe(false);
  await rm(source);
  await writeFile(source, "trusted");
  expect(
    await stageUnblobContainerPlugins(
      baseline,
      join(root, "regular-stage"),
      "extract_firmware",
      signal,
      scope,
    ),
  ).toMatchObject({ files: baseline.files });
  await scope.close();
});

it("seed0x55424331 preserves 16 actual plugin byte generations and rejects all 16 different copies", async () => {
  const root = await createTestTempDirectory("rea-container-plugin-seed-");
  const source = join(root, "plugin 雪.py");
  const scope = new ArtifactResourceScope();
  const signal = new AbortController().signal;
  let seed = 0x55424331;
  for (let index = 0; index < 16; index++) {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    const bytes = Buffer.alloc(256 + ((seed >>> 0) % 4096), index);
    await writeFile(source, bytes);
    const baseline = await fingerprintUnblobPlugins(
      source,
      "inspect_firmware_provider",
      signal,
      scope,
    );
    const staged = await stageUnblobContainerPlugins(
      baseline,
      join(root, `stable-${index}`),
      "inspect_firmware_provider",
      signal,
      scope,
    );
    expect(staged.files[0]).toEqual({
      relative_path: "plugin 雪.py",
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    expect(await readFile(join(staged.host_path, "plugin 雪.py"))).toEqual(
      bytes,
    );
    bytes[bytes.length - 1] = (index + 1) % 256;
    await writeFile(source, bytes);
    await expect(
      stageUnblobContainerPlugins(
        baseline,
        join(root, `changed-${index}`),
        "inspect_firmware_provider",
        signal,
        scope,
      ),
    ).rejects.toThrow(/fingerprint/u);
  }
  await scope.close();
});

it("rejects a changed plugin generation rather than attributing copied bytes to the baseline", async () => {
  const root = await createTestTempDirectory("rea-container-plugin-drift-");
  const source = join(root, "plugin.py");
  await writeFile(source, "first");
  const scope = new ArtifactResourceScope();
  const signal = new AbortController().signal;
  const baseline = await fingerprintUnblobPlugins(
    source,
    "extract_firmware",
    signal,
    scope,
  );
  await writeFile(source, "other");
  await expect(
    stageUnblobContainerPlugins(
      baseline,
      join(root, "staged"),
      "extract_firmware",
      signal,
      scope,
    ),
  ).rejects.toThrow(/identity|fingerprint|generation/u);
  await scope.close();
});

it("rejects a newly introduced link or file in a previously fingerprinted tree", async () => {
  const root = await createTestTempDirectory("rea-container-plugin-link-");
  const source = join(root, "plugins");
  await mkdir(source);
  await writeFile(join(source, "plugin.py"), "trusted");
  const scope = new ArtifactResourceScope();
  const signal = new AbortController().signal;
  const baseline = await fingerprintUnblobPlugins(
    source,
    "extract_firmware",
    signal,
    scope,
  );
  await symlink(join(source, "plugin.py"), join(source, "alias.py"));
  await expect(
    stageUnblobContainerPlugins(
      baseline,
      join(root, "staged"),
      "extract_firmware",
      signal,
      scope,
    ),
  ).rejects.toThrow(/link|special/u);
  await scope.close();
});

it("cancels after the first actual source read with one FD owner and no further reads", async () => {
  const root = await createTestTempDirectory("rea-container-plugin-abort-");
  const source = join(root, "plugin.py");
  await writeFile(source, Buffer.alloc(256 * 1024, 0x61));
  const scope = new ArtifactResourceScope();
  const controller = new AbortController();
  const baseline = await fingerprintUnblobPlugins(
    source,
    "extract_firmware",
    controller.signal,
    scope,
  );
  const fs = await import("node:fs/promises");
  const control = await fs.open(source, "r");
  const prototype = Object.getPrototypeOf(control);
  await control.close();
  const originalRead = prototype.read;
  let sourceReads = 0;
  let readDescriptor: number | undefined;
  const read = vi.spyOn(prototype, "read").mockImplementation(async function (
    this: typeof control,
    ...args: unknown[]
  ) {
    const path = await readlink(`/proc/self/fd/${this.fd}`);
    const result = await originalRead.apply(this, args);
    if (path === source) {
      sourceReads++;
      readDescriptor = this.fd;
      controller.abort();
    }
    return result;
  });
  try {
    await expect(
      stageUnblobContainerPlugins(
        baseline,
        join(root, "staged"),
        "extract_firmware",
        controller.signal,
        scope,
      ),
    ).rejects.toBeDefined();
    expect(sourceReads).toBe(1);
    expect(readDescriptor).toBeDefined();
    await expect(
      readlink(`/proc/self/fd/${readDescriptor}`),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await scope.close();
  } finally {
    read.mockRestore();
  }
});
