import { expect, it } from "vitest";
import {
  assertOracleOutputFiles,
  closeClientAndRemoveWorkspace,
  oracleFilesForSelectedRange,
  runWithCleanup,
} from "../../../scripts/verify/firmware/acceptanceSupport.mjs";

const outputRoot = "rea-input_extract";
const expected = {
  "0-64.unknown": { size: 64, sha256: "a".repeat(64) },
  "64-2832.gzip_extract/gzip.uncompressed_extract/etc/rea.conf": {
    size: 17,
    sha256: "b".repeat(64),
  },
};
const file = (relativePath: string, size = 17, sha256 = "b".repeat(64)) => ({
  relative_path: relativePath,
  path: `/output/${relativePath}`,
  size,
  sha256,
});
const hashFile = async (path: string) =>
  path.endsWith("0-64.unknown") ? "a".repeat(64) : "b".repeat(64);

it("projects only exact selected-range oracle paths to local snapshot paths", () => {
  const selectedPrefix = "64-2832.gzip_extract/";
  const projected = oracleFilesForSelectedRange(
    {
      "0-64.unknown": { size: 64, sha256: "a".repeat(64) },
      "64-2832.gzip_extract/gzip.uncompressed": {
        size: 20_480,
        sha256: "c".repeat(64),
      },
      "64-2832.gzip_extract/gzip.uncompressed_extract/etc/rea.conf": {
        size: 17,
        sha256: "b".repeat(64),
      },
      "64-2832.gzip_extract2/outside.bin": {
        size: 1,
        sha256: "d".repeat(64),
      },
      "2832-2960.padding": { size: 128, sha256: "e".repeat(64) },
    },
    selectedPrefix,
  );

  expect(projected).toEqual({
    "gzip.uncompressed": { size: 20_480, sha256: "c".repeat(64) },
    "gzip.uncompressed_extract/etc/rea.conf": {
      size: 17,
      sha256: "b".repeat(64),
    },
  });
});

it("accepts the exact normalized oracle path, size and digest set", async () => {
  await expect(
    assertOracleOutputFiles(
      [
        file(`${outputRoot}/0-64.unknown`, 64, "a".repeat(64)),
        file(
          `${outputRoot}/64-2832.gzip_extract/gzip.uncompressed_extract/etc/rea.conf`,
        ),
      ],
      expected,
      outputRoot,
      hashFile,
    ),
  ).resolves.toBeUndefined();
});

it("rejects an expected suffix under a wrong output prefix", async () => {
  await expect(
    assertOracleOutputFiles(
      [file("wrong-root/etc/rea.conf")],
      expected,
      outputRoot,
      hashFile,
    ),
  ).rejects.toThrow();
});

it("rejects duplicate expected paths and unexpected extra files", async () => {
  const expectedFile = file(
    `${outputRoot}/64-2832.gzip_extract/gzip.uncompressed_extract/etc/rea.conf`,
  );
  await expect(
    assertOracleOutputFiles(
      [expectedFile, expectedFile],
      expected,
      outputRoot,
      hashFile,
    ),
  ).rejects.toThrow();
  await expect(
    assertOracleOutputFiles(
      [expectedFile, file(`${outputRoot}/surprise.bin`, 1, "c".repeat(64))],
      {
        ["64-2832.gzip_extract/gzip.uncompressed_extract/etc/rea.conf"]:
          expected[
            "64-2832.gzip_extract/gzip.uncompressed_extract/etc/rea.conf"
          ],
      },
      outputRoot,
      hashFile,
    ),
  ).rejects.toThrow();
});

it("always runs cleanup and preserves both operation and close failures", async () => {
  const operationFailure = new Error("operation failed");
  const closeFailure = new Error("client close failed");
  let workspaceRemoved = false;
  let observed: unknown;
  try {
    await runWithCleanup(
      async () => {
        throw operationFailure;
      },
      async () => {
        await closeClientAndRemoveWorkspace(
          async () => {
            throw closeFailure;
          },
          "workspace",
          async () => {
            workspaceRemoved = true;
          },
        );
      },
    );
  } catch (cause) {
    observed = cause;
  }
  expect(workspaceRemoved).toBe(true);
  expect(observed).toBeInstanceOf(AggregateError);
  expect((observed as AggregateError).errors).toEqual([
    operationFailure,
    closeFailure,
  ]);
});
