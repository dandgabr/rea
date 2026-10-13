import { expect, it, vi } from "vitest";
import {
  verifyFactNativeSources,
  readFactNativeFile,
  FactNativeFileCleanupFailure,
} from "./FactNativeIdentity.js";
import { FactFileResources } from "./FactFiles.js";
import { err } from "../../domain/result.js";
import { mkdtemp, writeFile, rm, open } from "node:fs/promises";
import { constants } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { factHash } from "./FactProtocol.js";
import { FACT_NATIVE_SOURCE_PINS } from "./FactNativeProfiles.js";

it("accepts exact selected critical profile hashes but refuses a substituted config/locality/mutation source", () => {
  for (const profile of ["release-4.4.1", "source-54aed90b"] as const) {
    const hashes = { ...FACT_NATIVE_SOURCE_PINS[profile] };
    expect(() => verifyFactNativeSources(profile, hashes)).not.toThrow();
    for (const path of [
      "firmware_import_export.py",
      "config.py",
      "storage/db_connection.py",
      "storage/db_interface_backend.py",
    ] as const) {
      expect(() =>
        verifyFactNativeSources(profile, { ...hashes, [path]: "0".repeat(64) }),
      ).toThrow(/identity|source|profile/iu);
    }
    expect(() => verifyFactNativeSources(profile, {})).toThrow();
  }
});
it.skipIf(process.platform !== "linux")(
  "owns nonblocking identity descriptors and rejects a writer-free FIFO with a bounded regular positive",
  async () => {
    const root = await mkdtemp(join(tmpdir(), "rea-fact-identity-"));
    const files = new FactFileResources();
    try {
      const regular = join(root, "regular");
      await writeFile(regular, "identity");
      const observed = await readFactNativeFile(
        regular,
        8,
        AbortSignal.timeout(1000),
        files,
      );
      expect(observed.identity).toMatchObject({
        sha256: factHash("identity"),
        size: 8,
      });
      const fifo = join(root, "fifo");
      execFileSync("/usr/bin/mkfifo", [fifo]);
      const reading = readFactNativeFile(
        fifo,
        8,
        AbortSignal.timeout(1000),
        files,
      ).catch((cause: unknown) => cause);
      const beforeDeadline = await Promise.race([
        reading.then(() => true),
        new Promise<boolean>((resolve) =>
          setTimeout(() => resolve(false), 300),
        ),
      ]);
      // A defective blocking reader must not strand the test runner's libuv thread.
      // This cleanup writer is created only AFTER the independent deadline failed.
      if (!beforeDeadline) {
        const writer = await open(
          fifo,
          constants.O_WRONLY | constants.O_NONBLOCK,
        );
        await writer.close();
      }
      const failure = await reading;
      expect(beforeDeadline).toBe(true);
      expect(String(failure)).toMatch(/regular/iu);
      expect(files.pendingResources).toEqual([]);
    } finally {
      await files.close();
      await rm(root, { recursive: true, force: true });
    }
  },
  3000,
);
it("retains a failed native descriptor owner and its verified identity for explicit cleanup retry", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-fact-identity-owner-"));
  const files = new FactFileResources();
  try {
    const path = join(root, "regular");
    await writeFile(path, "identity");
    const release = vi
      .spyOn(files, "release")
      .mockResolvedValueOnce(err(Error("descriptor close fault")));
    const failure: unknown = await readFactNativeFile(
      path,
      8,
      new AbortController().signal,
      files,
    ).catch((cause: unknown) => cause);
    expect(failure).toBeInstanceOf(FactNativeFileCleanupFailure);
    if (!(failure instanceof FactNativeFileCleanupFailure))
      throw Error("Expected retained identity observation");
    expect(failure.identity).toMatchObject({
      sha256: factHash("identity"),
      size: 8,
    });
    expect(files.pendingResources).toContain(path);
    release.mockRestore();
    await files.close();
    expect(files.pendingResources).toEqual([]);
  } finally {
    await files.close();
    await rm(root, { recursive: true, force: true });
  }
});
