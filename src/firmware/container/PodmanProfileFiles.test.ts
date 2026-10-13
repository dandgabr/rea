import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, expect, it, vi } from "vitest";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import * as regularFile from "../../filesystem/RegularFile.js";
import {
  decodePodmanProfileText,
  observePodmanProfileFile,
} from "./PodmanProfileFiles.js";

const roots: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});
const fixture = async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-podman-fd-"));
  roots.push(root);
  return root;
};
it("refuses a writerless FIFO and symlink promptly and admits exactly the bounded regular source bytes", async () => {
  const root = await fixture();
  const scope = new ArtifactResourceScope();
  const signal = AbortSignal.timeout(1000);
  const fifo = join(root, "fifo");
  await promisify(execFile)("/usr/bin/mkfifo", [fifo]);
  await expect(
    observePodmanProfileFile(fifo, 2, signal, scope),
  ).rejects.toThrow(/regular file/i);
  const path = join(root, "file");
  await writeFile(path, "ab", { mode: 0o600 });
  await symlink(path, join(root, "link"));
  await expect(
    observePodmanProfileFile(join(root, "link"), 2, signal, scope),
  ).rejects.toThrow();
  expect(
    (await observePodmanProfileFile(path, 2, signal, scope)).bytes.toString(),
  ).toBe("ab");
  await writeFile(path, "abc");
  await expect(
    observePodmanProfileFile(path, 2, signal, scope),
  ).rejects.toThrow(/budget/i);
  expect(
    decodePodmanProfileText(Buffer.from("valid \ufffd \ud83d\udd2c")),
  ).toBe("valid \ufffd \ud83d\udd2c");
  expect(() => decodePodmanProfileText(Buffer.from([0xff]))).toThrow(/UTF-8/i);
  await scope.close();
}, 2000);
it("preserves primary cancellation through actual FD close failure and retries only the same retained descriptor owner", async () => {
  const root = await fixture();
  const path = join(root, "cancelled");
  await writeFile(path, "actual bytes", { mode: 0o600 });
  const scope = new ArtifactResourceScope();
  const controller = new AbortController();
  const originalOpen = regularFile.openRegularFile;
  let closes = 0;
  vi.spyOn(regularFile, "openRegularFile").mockImplementationOnce(
    async (selected, options) => {
      const handle = await originalOpen(selected, options);
      const originalStat = handle.stat.bind(handle);
      const originalClose = handle.close.bind(handle);
      vi.spyOn(handle, "stat").mockImplementationOnce(async () => {
        const state = await originalStat({ bigint: true });
        controller.abort();
        return state;
      });
      vi.spyOn(handle, "close").mockImplementation(async () => {
        closes++;
        if (closes === 1)
          throw Error("injected actual descriptor close failure");
        await originalClose();
      });
      return handle;
    },
  );
  const failure: unknown = await observePodmanProfileFile(
    path,
    100,
    controller.signal,
    scope,
  ).catch((cause: unknown) => cause);
  expect(failure).toMatchObject({
    _tag: "ProviderAdapterError",
    cleanupIncomplete: true,
    resourceScope: scope,
    diagnostics: {
      primary_error: { code: "cancelled", category: "cancelled" },
    },
  });
  expect(closes).toBe(1);
  await scope.retryCleanup();
  expect(closes).toBe(2);
  await scope.close();
  expect(closes).toBe(2);
});
