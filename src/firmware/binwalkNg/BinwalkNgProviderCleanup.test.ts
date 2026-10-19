import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { readlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { binwalkNgInputSchemas } from "../../domain/firmware/binwalkNgAnalysis.js";
import { BinwalkNgProvider } from "./BinwalkNgProvider.js";

it("retains selected source cleanup with the original operation and resolves the same error on cleanup-only retry", async () => {
  const root = await createTestTempDirectory("rea-ng-public-cleanup-");
  const path = join(root, "vendor.FW");
  await writeFile(path, "source bytes");
  const close = OwnedFileHandle.prototype.close;
  let allowClose = false;
  let closes = 0;
  let launches = 0;
  const spy = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(async function (this: OwnedFileHandle) {
      if (
        this.handle.fd >= 0 &&
        (await readlink(`/proc/self/fd/${this.handle.fd}`)) === path
      ) {
        closes++;
        if (!allowClose) throw Error("selected source close refused");
      }
      await Reflect.apply(close, this, []);
    });
  const provider = new BinwalkNgProvider(
    {
      REA_BINWALK_NG_COMMAND: "/unused",
      REA_FIRMWARE_BWRAP_COMMAND: "/unused",
      REA_BINWALK_NG_RUNTIME_MANIFEST: "/unused",
    },
    async () => {
      launches++;
      throw Error("must not launch");
    },
  );
  const request = {
    operation: "inspect_firmware_regions" as const,
    input: binwalkNgInputSchemas.inspect_firmware_regions.parse({
      path,
      provider_id: "binwalk-ng",
    }),
  };
  try {
    const first = await provider.execute(request);
    expect(first.ok).toBe(false);
    if (first.ok) throw Error("Expected retained cleanup");
    expect(first.error).toMatchObject({
      cleanupIncomplete: true,
      operation: request.operation,
      cleanupResources: [path],
    });
    expect(closes).toBe(1);
    const retry = await provider.execute(request);
    expect(retry.ok).toBe(false);
    if (retry.ok) throw Error("Expected cleanup-only refusal");
    expect(retry.error).toMatchObject({
      cleanupIncomplete: true,
      operation: request.operation,
    });
    expect(closes).toBe(2);
    expect(launches).toBe(0);
    allowClose = true;
    await provider.close();
    expect(closes).toBe(3);
    expect(first.error).toMatchObject({
      cleanupIncomplete: false,
      cleanupResources: [],
    });
    expect(retry.error).toMatchObject({
      cleanupIncomplete: false,
      cleanupResources: [],
    });
    expect(launches).toBe(0);
  } finally {
    allowClose = true;
    await provider.close();
    spy.mockRestore();
  }
});

it.each([false, true])(
  "resolves the original command cleanup error when its retained workflow closes (entropy diagnostic=%s)",
  async (entropyDiagnostic) => {
    const root = await createTestTempDirectory("rea-ng-command-cleanup-");
    const path = join(root, "input.bin");
    const manifest = join(root, "runtime.json");
    await writeFile(path, "source bytes");
    await writeFile(
      manifest,
      JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts: [] }),
    );
    let allowClose = false;
    let launches = 0;
    const provider = new BinwalkNgProvider(
      {
        REA_BINWALK_NG_COMMAND: "/usr/bin/true",
        REA_FIRMWARE_BWRAP_COMMAND: "/usr/bin/true",
        REA_FIRMWARE_SYSTEMD_RUN_COMMAND: "/usr/bin/true",
        REA_BINWALK_NG_RUNTIME_MANIFEST: manifest,
      },
      async (options) => {
        launches++;
        const child = Object.assign(new EventEmitter(), {
          stdout: new PassThrough(),
          stderr: new PassThrough(),
          exitCode: null,
          signalCode: null,
          kill: () => false,
        });
        setImmediate(() => {
          child.stdout.end("binwalk-ng 4.0.0\n");
          child.stderr.end(
            entropyDiagnostic
              ? 'binwalk was built without the "entropy-plot" feature, entropy analysis isn\'t available'
              : "",
          );
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
            allowClose
              ? { cleaned: true, signaled: false }
              : { cleaned: false, reason: "command ownership retained" },
        };
      },
    );
    try {
      const outcome = await provider.execute({
        operation: "inspect_firmware_entropy",
        input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
          path,
          provider_id: "binwalk-ng",
        }),
      });
      expect(outcome.ok).toBe(false);
      if (outcome.ok) throw Error("Expected command cleanup failure");
      expect(outcome.error.cleanupIncomplete).toBe(true);
      expect(launches).toBe(1);
      allowClose = true;
      await provider.close();
      expect(outcome.error).toMatchObject({
        cleanupIncomplete: false,
        cleanupResources: [],
      });
      expect(launches).toBe(1);
    } finally {
      allowClose = true;
      await provider.close();
    }
  },
);
