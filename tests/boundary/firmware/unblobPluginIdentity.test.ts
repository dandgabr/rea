import { writeFile } from "node:fs/promises";
import * as fs from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { expect, it, vi } from "vitest";
import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import { fingerprintUnblobPlugins } from "../../../src/firmware/UnblobPlugins.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  return { ...actual, lstat: vi.fn(actual.lstat) };
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
