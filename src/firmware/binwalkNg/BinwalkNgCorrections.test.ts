import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { createHash } from "node:crypto";
import { readlinkSync } from "node:fs";
import {
  mkdir,
  open,
  readFile,
  stat,
  writeFile,
  type FileHandle,
} from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { binwalkNgInputSchemas } from "../../domain/firmware/binwalkNgAnalysis.js";
import { spawnOwnedProviderProcess } from "../../process/ProviderProcess.js";
import { BinwalkNgProvider } from "./BinwalkNgProvider.js";
import { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";
interface TestFile {
  relative_path: string;
  path: string;
  sha256: string;
  byte_correspondence: string;
  original_file_range: unknown;
  local_range: unknown;
  carving_observation: unknown;
}
interface TestResult {
  files: TestFile[];
  unpublished_entries: TestFile[];
  diagnostics: string[];
  coverage: string;
  unexamined_files: unknown[];
}
const sha = (bytes: string) => createHash("sha256").update(bytes).digest("hex");
const fixture = resolve("tests/fixtures/firmware/binwalkNgProtocol.mjs");
const setup = async () => {
  const root = await createTestTempDirectory("rea-ng-corrections-");
  const path = join(root, "input.bin"),
    manifest = join(root, "manifest.json");
  await writeFile(path, "abcdef");
  await writeFile(
    manifest,
    JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts: [] }),
  );
  const runtime = {
    command: "/usr/bin/true",
    bubblewrap: "/usr/bin/true",
    limiter: "/usr/bin/prlimit",
    manifest,
  };
  const environment = {
    REA_BINWALK_NG_COMMAND: runtime.command,
    REA_FIRMWARE_BWRAP_COMMAND: runtime.bubblewrap,
    REA_BINWALK_NG_RUNTIME_MANIFEST: manifest,
  };
  return { root, path, runtime, environment };
};
const protocolLauncher =
  (mode: string) =>
  async (options: Parameters<typeof spawnOwnedProviderProcess>[0]) => {
    const args = options.arguments;
    const log = args[args.indexOf("--log") + 1];
    const pass = log === undefined ? "0000" : basename(log, ".json");
    const roIndex = args.lastIndexOf("--ro-bind");
    const input = args[roIndex + 1] ?? "input.bin";
    return spawnOwnedProviderProcess({
      ...options,
      command: process.execPath,
      arguments: [
        fixture,
        args.at(-1) === "--version" ? "version" : mode,
        options.cwd ?? "",
        pass,
        basename(input),
      ],
    });
  };
it.each(["stable", "mutate"])(
  "binds final carving ranges to actual published bytes across recursive passes: %s",
  async (mode) => {
    const { root, path, environment } = await setup();
    const provider = new BinwalkNgProvider(environment, protocolLauncher(mode));
    try {
      const outcome = await provider.execute({
        operation: "extract_firmware",
        input: binwalkNgInputSchemas.extract_firmware.parse({
          path,
          provider_id: "binwalk-ng",
          output_directory: join(root, "output"),
          options: { carve: true },
        }),
      });
      expect(outcome.ok).toBe(true);
      if (!outcome.ok) throw outcome.error;
      const result = outcome.value.result as unknown as TestResult;
      const file = result.files.find((f) =>
        f.relative_path.endsWith("input.bin_2_gzip.raw"),
      );
      if (file === undefined) throw Error("Missing carved artifact");
      expect(await readFile(file.path, "utf8")).toBe(
        mode === "stable" ? "cd" : "ZZ",
      );
      expect(file.sha256).toBe(sha(mode === "stable" ? "cd" : "ZZ"));
      expect(file.byte_correspondence).toBe(
        mode === "stable" ? "verified" : "unknown",
      );
      expect(file.original_file_range).toEqual(
        mode === "stable" ? { offset: 2, length: 2 } : null,
      );
      expect(file.local_range).toEqual(
        mode === "stable" ? { offset: 2, length: 2 } : null,
      );
      expect(file.carving_observation).toMatchObject({
        sha256: sha("cd"),
        original_file_range: { offset: 2, length: 2 },
      });
      if (mode === "mutate")
        expect(result.diagnostics.join(" ")).toContain("changed");
    } finally {
      await provider.close();
    }
  },
);
it.each(["inside", "outside"])(
  "accounts for regular and nonregular artifacts in final inventory: %s",
  async (mode) => {
    const { root, path, environment } = await setup();
    const provider = new BinwalkNgProvider(environment, protocolLauncher(mode));
    try {
      const outcome = await provider.execute({
        operation: "extract_firmware",
        input: binwalkNgInputSchemas.extract_firmware.parse({
          path,
          provider_id: "binwalk-ng",
          output_directory: join(root, "output"),
        }),
      });
      expect(outcome.ok).toBe(true);
      if (!outcome.ok) throw outcome.error;
      const result = outcome.value.result as unknown as TestResult;
      expect(result.coverage).toBe("partial");
      expect(result.unexamined_files).toHaveLength(2);
      for (const file of [...result.files, ...result.unpublished_entries]) {
        expect(file).toMatchObject({
          byte_correspondence: "unknown",
          original_file_range: null,
          local_range: null,
          runtime_address: null,
        });
        if (mode === "outside")
          expect(file).toMatchObject({
            parent_analysis_file: null,
            analysis_depth: null,
          });
      }
    } finally {
      await provider.close();
    }
  },
);
it.each(["refusal", "cancel", "cleanup"])(
  "retains established private PNG facts through publication %s",
  async (mode) => {
    const { root, path, environment } = await setup();
    const output = join(root, "output");
    const controller = new AbortController();
    if (mode !== "cancel") {
      await mkdir(output);
      await writeFile(join(output, "sentinel"), "caller bytes");
    }
    const create =
      mode === "cancel"
        ? vi
            .spyOn(SafeOutputTree, "create")
            .mockImplementationOnce(async () => {
              controller.abort();
              throw controller.signal.reason;
            })
        : undefined;
    const provider = new BinwalkNgProvider(
      environment,
      protocolLauncher("png"),
    );
    const close =
      mode === "cleanup"
        ? vi
            .spyOn(ArtifactResourceScope.prototype, "retryCleanup")
            .mockRejectedValueOnce(new Error("injected cleanup"))
        : undefined;
    try {
      const outcome = await provider.execute(
        {
          operation: "inspect_firmware_entropy",
          input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
            path,
            provider_id: "binwalk-ng",
            output_directory: output,
          }),
        },
        { signal: controller.signal },
      );
      expect(outcome.ok).toBe(false);
      if (outcome.ok) throw Error("Expected refusal");
      const partial = outcome.error.partialObservation;
      expect(partial && "kind" in partial ? partial.kind : undefined).toBe(
        "firmware",
      );
      if (
        partial === undefined ||
        !("kind" in partial) ||
        partial.kind !== "firmware"
      )
        throw Error("Missing firmware facts");
      expect(partial.result).toMatchObject({
        entropy: { examined_bytes: 6 },
        png: {
          width: 2048,
          height: 1024,
          size: 24,
          sha256:
            "a7fa5ad7f75cf1bf5d34ad2beaad5b0b2b2c8de4dcc11bceb8e9b0ac891b654a",
          validation: "png_header",
          path: null,
          publication_state: "unpublished",
        },
      });
      expect(partial.provenance).toBeDefined();
      if (mode !== "cancel")
        expect(await readFile(join(output, "sentinel"), "utf8")).toBe(
          "caller bytes",
        );
    } finally {
      create?.mockRestore();
      close?.mockRestore();
      await provider.close();
    }
  },
);
it("cancels runtime fingerprint admission before later manifest/support reads and launches", async () => {
  const { root, path, runtime } = await setup();
  const workRoot = join(root, "work");
  await mkdir(workRoot);
  runtime.command = join(root, "selected-runtime");
  await writeFile(runtime.command, Buffer.alloc(2 * 1024 * 1024, 1), {
    mode: 0o700,
  });
  const support = join(root, "support");
  await writeFile(support, "support bytes");
  await writeFile(
    runtime.manifest,
    JSON.stringify({
      profile: "binwalk-ng-4.0.0",
      mounts: [
        {
          source: support,
          destination: "/runtime/support/selected",
          kind: "support",
        },
      ],
    }),
  );
  const h = await open(path);
  const prototype = Object.getPrototypeOf(h) as FileHandle;
  await h.close();
  const original = prototype.createReadStream;
  const reads: string[] = [];
  let fingerprintChunks = 0;
  const controller = new AbortController();
  const observer = vi
    .spyOn(prototype, "createReadStream")
    .mockImplementation(function (
      this: FileHandle,
      ...args: Parameters<FileHandle["createReadStream"]>
    ) {
      reads.push(readlinkSync(`/proc/self/fd/${this.fd}`));
      const stream = original.apply(this, args);
      stream.on("data", () => {
        fingerprintChunks++;
        controller.abort();
      });
      return stream;
    });
  const scope = new ArtifactResourceScope();
  try {
    await expect(
      prepareBinwalkNgSandbox({
        ...runtime,
        inputPath: path,
        workRoot,
        signal: controller.signal,
        scope,
        operation: "extract_firmware",
      }),
    ).rejects.toThrow();
    expect(controller.signal.aborted).toBe(true);
    expect(reads).toHaveLength(1);
    expect(fingerprintChunks).toBe(1);
    expect(reads).not.toContain(support);
  } finally {
    observer.mockRestore();
    await scope.close();
  }
  const positive = await prepareBinwalkNgSandbox({
    ...runtime,
    inputPath: path,
    workRoot,
  });
  expect(positive.runtime_mounts[0]?.sha256).toBe(sha("support bytes"));
});
it("refuses a second admitted operation immediately, releases cancellation capacity and admits a later explicit request", async () => {
  const { path, environment } = await setup();
  let release!: () => void;
  let started!: () => void;
  const entered = new Promise<void>((r) => {
    started = r;
  });
  const held = new Promise<void>((r) => {
    release = r;
  });
  let launches = 0;
  const base = protocolLauncher("png");
  const provider = new BinwalkNgProvider(environment, async (options) => {
    launches++;
    if (launches === 1) {
      started();
      await held;
    }
    return base(options);
  });
  const request = {
    operation: "inspect_firmware_entropy" as const,
    input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
      path,
      provider_id: "binwalk-ng",
    }),
  };
  const controller = new AbortController();
  try {
    const first = provider.execute(request, { signal: controller.signal });
    const second = provider.execute(request);
    const result = await Promise.race([
      second,
      new Promise<null>((r) => setTimeout(() => r(null), 100)),
    ]);
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisResourceConstraintError",
        resource: "capacity",
        operation: "inspect_firmware_entropy",
      },
    });
    await entered;
    expect(launches).toBe(1);
    controller.abort();
    release();
    expect((await first).ok).toBe(false);
    await second;
    expect((await provider.execute(request)).ok).toBe(true);
  } finally {
    release();
    await provider.close();
  }
});

it("bounded workflow fuzz: seed 0x4e473208, 12 protocol cases bind final ranges, unknown coverage and workspace termination", async () => {
  let seed = 0x4e473208;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  for (let index = 0; index < 12; index++) {
    const { root, path, environment } = await setup();
    const prefix = next() % 33;
    await writeFile(path, "p".repeat(prefix) + "abcdef");
    const mode =
      ["stable", "mutate", "inside", "outside"][index % 4] ?? "outside";
    const recursive = next() % 2 === 0;
    const max_depth = next() % 2 === 0 ? 1 : 3;
    const provider = new BinwalkNgProvider(environment, protocolLauncher(mode));
    try {
      const outcome = await provider.execute({
        operation: "extract_firmware",
        input: binwalkNgInputSchemas.extract_firmware.parse({
          path,
          provider_id: "binwalk-ng",
          range: { offset: prefix, length: 6 },
          output_directory: join(root, "output"),
          options: { carve: true, recursive },
          max_depth,
        }),
      });
      expect(outcome.ok).toBe(true);
      if (!outcome.ok) throw outcome.error;
      const result = outcome.value.result as unknown as TestResult;
      const original = await readFile(path);
      for (const file of result.files) {
        const bytes = await readFile(file.path);
        expect(file.sha256).toBe(
          createHash("sha256").update(bytes).digest("hex"),
        );
        if (file.byte_correspondence === "verified") {
          const range = file.original_file_range as {
            offset: number;
            length: number;
          };
          expect(range.offset).toBeGreaterThanOrEqual(prefix);
          expect(range.offset + range.length).toBeLessThanOrEqual(
            original.length,
          );
          expect(bytes).toEqual(
            original.subarray(range.offset, range.offset + range.length),
          );
        } else {
          expect(file.original_file_range).toBeNull();
          expect(file.local_range).toBeNull();
        }
      }
      if (mode === "outside") {
        expect(result.coverage).toBe("partial");
        expect(result.unexamined_files).toHaveLength(2);
      }
      const raw = outcome.value.rawResult as {
        sandbox: { work_root: string };
      }[];
      for (const run of raw)
        await expect(stat(run.sandbox.work_root)).rejects.toMatchObject({
          code: "ENOENT",
        });
    } finally {
      await provider.close();
    }
  }
}, 45000);

it("keeps a durably published PNG facet through repeated directory-close failures and retries cleanup only", async () => {
  const { root, path, environment } = await setup();
  const output = join(root, "output");
  const originalClose = OwnedFileHandle.prototype.close;
  const originalCommit = SafeOutputTree.prototype.commit;
  let inCommit = false,
    launches = 0,
    failedHandle: OwnedFileHandle | undefined;
  let failedCloseAttempts = 0;
  const commit = vi
    .spyOn(SafeOutputTree.prototype, "commit")
    .mockImplementation(async function (this: SafeOutputTree) {
      inCommit = true;
      try {
        await originalCommit.call(this);
      } finally {
        inCommit = false;
      }
    });
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(async function (this: OwnedFileHandle) {
      if (
        this === failedHandle ||
        (inCommit &&
          this.handle.fd >= 0 &&
          readlinkSync(`/proc/self/fd/${this.handle.fd}`) === output)
      ) {
        failedHandle = this;
        failedCloseAttempts++;
        if (failedCloseAttempts <= 2)
          throw new Error("injected durable directory close failure");
      }
      await originalClose.call(this);
    });
  const launch = protocolLauncher("png");
  const provider = new BinwalkNgProvider(environment, async (options) => {
    launches++;
    return launch(options);
  });
  try {
    const outcome = await provider.execute({
      operation: "inspect_firmware_entropy",
      input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
        path,
        provider_id: "binwalk-ng",
        output_directory: output,
      }),
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw Error("Expected cleanup uncertainty");
    const partial = outcome.error.partialObservation;
    if (
      partial === undefined ||
      !("kind" in partial) ||
      partial.kind !== "firmware"
    )
      throw Error("Missing firmware facts");
    const bytes = await readFile(join(output, "entropy.png"));
    const digest = createHash("sha256").update(bytes).digest("hex");
    expect(bytes).toHaveLength(24);
    expect(outcome.error.cleanupIncomplete).toBe(true);
    expect(partial.result).toMatchObject({
      png: {
        path: join(output, "entropy.png"),
        publication_state: "published",
        sha256: digest,
        size: bytes.length,
      },
      retained_observation: {
        result: {
          files: [{ path: join(output, "entropy.png"), sha256: digest }],
        },
      },
    });
    expect(failedCloseAttempts).toBe(2);
    expect((await failedHandle?.handle.stat())?.isDirectory()).toBe(true);
    expect(launches).toBe(2);
    expect(commit).toHaveBeenCalledTimes(1);
    await provider.close();
    expect(failedCloseAttempts).toBe(3);
    expect(failedHandle?.handle.fd).toBe(-1);
    expect(launches).toBe(2);
    expect(commit).toHaveBeenCalledTimes(1);
    expect(await readFile(join(output, "entropy.png"))).toEqual(bytes);
  } finally {
    await provider.close();
    close.mockRestore();
    commit.mockRestore();
  }
});

it("keeps the PNG unpublished when commit fails before establishing durable publication", async () => {
  const { root, path, environment } = await setup();
  const output = join(root, "output");
  const commit = vi
    .spyOn(SafeOutputTree.prototype, "commit")
    .mockRejectedValueOnce(new Error("injected before durable commit"));
  const provider = new BinwalkNgProvider(environment, protocolLauncher("png"));
  try {
    const outcome = await provider.execute({
      operation: "inspect_firmware_entropy",
      input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
        path,
        provider_id: "binwalk-ng",
        output_directory: output,
      }),
    });
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw Error("Expected precommit failure");
    const partial = outcome.error.partialObservation;
    if (
      partial === undefined ||
      !("kind" in partial) ||
      partial.kind !== "firmware"
    )
      throw Error("Missing private PNG observation");
    expect(partial.result).toMatchObject({
      png: {
        path: null,
        publication_state: "unpublished",
        sha256:
          "a7fa5ad7f75cf1bf5d34ad2beaad5b0b2b2c8de4dcc11bceb8e9b0ac891b654a",
        size: 24,
      },
    });
    await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
    expect(commit).toHaveBeenCalledTimes(1);
    expect(outcome.error.cleanupIncomplete).toBe(false);
  } finally {
    await provider.close();
    commit.mockRestore();
  }
});
