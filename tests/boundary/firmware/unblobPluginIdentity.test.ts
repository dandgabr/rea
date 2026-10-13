import { writeFile } from "node:fs/promises";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import {
  fingerprintUnblobPlugins,
  recheckUnblobPlugins,
} from "../../../src/firmware/UnblobPlugins.js";
import { identifyFirmwareFile } from "../../../src/firmware/FirmwareFiles.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, lstat: vi.fn(actual.lstat), open: vi.fn(actual.open) };
});

it("keeps the descriptor close owner when identity hashing is cancelled after its first actual read", async () => {
  const root = await createTestTempDirectory("rea-plugin-cancel-");
  const path = join(root, "trusted.py");
  const bytes = Buffer.alloc(128 * 1024, 0x61);
  await writeFile(path, bytes);
  const positive = await identifyFirmwareFile(path);
  expect(positive).toEqual({
    size: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
  const controller = new AbortController();
  const actual =
    await vi.importActual<typeof import("node:fs/promises")>(
      "node:fs/promises",
    );
  let acquired: import("node:fs/promises").FileHandle | undefined;
  let reads = 0,
    confirmedCloses = 0;
  const spy = vi.spyOn(fs, "open").mockImplementation(async (...args) => {
    const handle = await actual.open(...args);
    acquired = handle;
    const read = handle.read.bind(handle),
      close = handle.close.bind(handle);
    handle.read = async (...readArgs: Parameters<typeof read>) => {
      reads++;
      const observed = await read(...readArgs);
      controller.abort();
      return observed;
    };
    handle.close = async () => {
      await close();
      confirmedCloses++;
    };
    return handle;
  });
  const scope = new ArtifactResourceScope();
  try {
    await expect(
      identifyFirmwareFile(
        path,
        controller.signal,
        scope,
        "inspect_firmware_provider",
      ),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(reads).toBe(1);
    expect(confirmedCloses).toBe(1);
    expect(acquired?.fd).toBe(-1);
    await expect(scope.retryCleanup()).resolves.toBeUndefined();
  } finally {
    spy.mockRestore();
    if (acquired !== undefined && acquired.fd >= 0) await acquired.close();
  }
});

it("distinguishes a single plugin fingerprint from a completed comparison and preserves known drift", async () => {
  const root = await createTestTempDirectory("rea-plugin-attribution-");
  const path = join(root, "trusted.py");
  await writeFile(path, "# baseline\n");
  const scope = new ArtifactResourceScope();
  const signal = new AbortController().signal;
  const baseline = await fingerprintUnblobPlugins(
    path,
    "inspect_firmware_provider",
    signal,
    scope,
  );
  expect(baseline).toMatchObject({
    recheck: "unverified",
    attribution: "unknown",
  });
  expect(
    await recheckUnblobPlugins(
      baseline,
      "inspect_firmware_provider",
      signal,
      scope,
    ),
  ).toMatchObject({
    recheck: "unchanged",
    attribution: "pre_and_post_fingerprint",
  });
  await writeFile(path, "# changed\n");
  const changed = await recheckUnblobPlugins(
    baseline,
    "inspect_firmware_provider",
    signal,
    scope,
  );
  expect(changed).toMatchObject({ recheck: "changed", attribution: "unknown" });
  await writeFile(path, "# baseline\n");
  expect(
    await recheckUnblobPlugins(
      changed,
      "inspect_firmware_provider",
      signal,
      scope,
    ),
  ).toMatchObject({ recheck: "changed", attribution: "unknown" });
});

it("checks seeded plugin generations against independent byte identities and explicit unknowns", async () => {
  const root = await createTestTempDirectory("rea-plugin-generations-");
  const path = join(root, "trusted.py"),
    scope = new ArtifactResourceScope();
  const signal = new AbortController().signal;
  let seed = 0x55425048;
  for (let index = 0; index < 32; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const bytes = Buffer.alloc(1 + (seed % (64 * 1024 + 1)), seed >>> 24);
    await writeFile(path, bytes);
    const baseline = await fingerprintUnblobPlugins(
      path,
      "inspect_firmware_provider",
      signal,
      scope,
    );
    expect(baseline.files[0]).toMatchObject({
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    expect(baseline.attribution).toBe("unknown");
    const mode = index % 4;
    if (mode === 1)
      await writeFile(path, Buffer.concat([bytes, Buffer.from([0])]));
    if (mode === 2) await fs.unlink(path);
    const checked = await recheckUnblobPlugins(
      baseline,
      "inspect_firmware_provider",
      signal,
      scope,
    );
    expect(checked.recheck).toBe(
      mode === 1 ? "changed" : mode === 2 ? "unverified" : "unchanged",
    );
    expect(checked.attribution).toBe(
      mode === 1 || mode === 2 ? "unknown" : "pre_and_post_fingerprint",
    );
    expect(checked.identity_sha256).toBe(baseline.identity_sha256);
    await writeFile(path, bytes);
    const subsequent = await recheckUnblobPlugins(
      checked,
      "inspect_firmware_provider",
      signal,
      scope,
    );
    expect(subsequent.recheck).toBe(mode === 1 ? "changed" : "unchanged");
  }
});

it.skipIf(process.platform === "win32")(
  "preserves literal POSIX backslashes in plugin filenames",
  async () => {
    const root = await createTestTempDirectory("rea-plugin-filename-");
    await writeFile(
      join(root, "literal\\name.py"),
      "# selected trusted source\n",
    );
    const result = await fingerprintUnblobPlugins(
      root,
      "inspect_firmware_provider",
      new AbortController().signal,
      new ArtifactResourceScope(),
    );
    expect(result.files.map((file) => file.relative_path)).toEqual([
      "literal\\name.py",
    ]);
  },
);

it("binds plugin byte count and digest to the same admitted descriptor after a pre-open replacement", async () => {
  const directory = await createTestTempDirectory("rea-plugin-identity-");
  const path = join(directory, "trusted.py");
  const original = "# old\n";
  const replacement = "# replacement trusted plugin with different length\n";
  await writeFile(path, original);
  const actualLstat = (
    await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises")
  ).lstat;
  let observations = 0;
  const spy = vi.spyOn(fs, "lstat").mockImplementation(async (...args) => {
    const state = await actualLstat(...args);
    if (args[0] === path && ++observations === 2)
      await writeFile(path, replacement);
    return state;
  });
  try {
    const result = await fingerprintUnblobPlugins(
      path,
      "inspect_firmware_provider",
      new AbortController().signal,
      new ArtifactResourceScope(),
    );
    expect(result.files).toEqual([
      {
        relative_path: "trusted.py",
        size: Buffer.byteLength(replacement),
        sha256: createHash("sha256").update(replacement).digest("hex"),
      },
    ]);
  } finally {
    spy.mockRestore();
  }
});
