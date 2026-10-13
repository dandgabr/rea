import { gzipSync } from "node:zlib";
import { readFile, writeFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { binwalkNgInputSchemas } from "../../domain/firmware/binwalkNgAnalysis.js";
import { BinwalkNgProvider } from "./BinwalkNgProvider.js";
import { spawnOwnedProviderProcess } from "../../process/ProviderProcess.js";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";

it("preserves the primary refusal beside failed workspace cleanup and retries the retained root on close", async () => {
  const root = await createTestTempDirectory("rea-ng-root-cleanup-");
  const path = join(root, "input.bin");
  await writeFile(path, "input");
  const provider = new BinwalkNgProvider({
    REA_BINWALK_NG_COMMAND: join(root, "missing-binwalk"),
    REA_FIRMWARE_BWRAP_COMMAND: "/usr/bin/true",
    REA_BINWALK_NG_RUNTIME_MANIFEST: join(root, "missing-manifest"),
  });
  const close = vi
    .spyOn(PrivateRuntimeRoot.prototype, "close")
    .mockRejectedValueOnce(new Error("injected root removal failure"));
  try {
    const outcome = await provider.execute({
      operation: "inspect_firmware_regions",
      input: binwalkNgInputSchemas.inspect_firmware_regions.parse({
        path,
        provider_id: "binwalk-ng",
      }),
    });
    expect(outcome).toMatchObject({
      ok: false,
      error: {
        cleanupIncomplete: true,
        operation: "inspect_firmware_regions",
        diagnostics: {
          primary_error: {
            code: "capability_unavailable",
            message: expect.stringContaining("missing-binwalk"),
          },
        },
      },
    });
    await provider.close();
    expect(close).toHaveBeenCalledTimes(2);
  } finally {
    close.mockRestore();
    await provider.close();
  }
});

it("reports native builds without entropy-plot as a named unavailable capability while preserving source stderr", async () => {
  const root = await createTestTempDirectory("rea-ng-feature-");
  const path = join(root, "input.bin"),
    manifest = join(root, "runtime.json");
  await writeFile(path, "input");
  await writeFile(
    manifest,
    JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts: [] }),
  );
  const nativeDiagnostic =
    'binwalk was built without the "entropy-plot" feature, entropy analysis isn\'t available';
  const provider = new BinwalkNgProvider(
    {
      REA_BINWALK_NG_COMMAND: "/usr/bin/true",
      REA_FIRMWARE_BWRAP_COMMAND: "/usr/bin/true",
      REA_BINWALK_NG_RUNTIME_MANIFEST: manifest,
    },
    async (options) =>
      spawnOwnedProviderProcess({
        ...options,
        command: process.execPath,
        arguments: [
          "-e",
          options.arguments.at(-1) === "--version"
            ? 'process.stdout.write("binwalk-ng 4.0.0\\n")'
            : "process.stderr.write(process.argv[1]);process.exitCode=1",
          nativeDiagnostic,
        ],
      }),
  );
  try {
    const outcome = await provider.execute({
      operation: "inspect_firmware_entropy",
      input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
        path,
        provider_id: "binwalk-ng",
      }),
    });
    expect(outcome).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        providerId: "binwalk-ng",
        reason: expect.stringContaining("entropy-plot"),
        diagnostics: { stderr: nativeDiagnostic },
      },
    });
  } finally {
    await provider.close();
  }
});

it("fails named unavailable for missing explicit confinement prerequisites without launching a provider", async () => {
  const root = await createTestTempDirectory("rea-ng-provider-");
  const path = join(root, "firmware.bin");
  await writeFile(path, "input");
  const provider = new BinwalkNgProvider({});
  try {
    const outcome = await provider.execute({
      operation: "inspect_firmware_regions",
      input: binwalkNgInputSchemas.inspect_firmware_regions.parse({
        path,
        provider_id: "binwalk-ng",
      }),
    });
    expect(outcome).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        providerId: "binwalk-ng",
      },
    });
  } finally {
    await provider.close();
  }
});

const nativeEnvironment = {
  REA_BINWALK_NG_COMMAND: process.env.REA_TEST_BINWALK_NG_COMMAND,
  REA_BINWALK_NG_RUNTIME_MANIFEST:
    process.env.REA_TEST_BINWALK_NG_RUNTIME_MANIFEST,
  REA_FIRMWARE_BWRAP_COMMAND: process.env.REA_TEST_BWRAP_COMMAND,
  REA_FIRMWARE_PRLIMIT_COMMAND: process.env.REA_TEST_PRLIMIT_COMMAND,
};
const real =
  nativeEnvironment.REA_BINWALK_NG_COMMAND !== undefined &&
  nativeEnvironment.REA_BINWALK_NG_RUNTIME_MANIFEST !== undefined &&
  nativeEnvironment.REA_FIRMWARE_BWRAP_COMMAND !== undefined;

it.runIf(real)(
  "retains exact native entropy windows at 2047/2048/2049 selected bytes and removes every private plot workspace",
  async () => {
    const root = await createTestTempDirectory("rea-ng-native-windows-");
    const provider = new BinwalkNgProvider(nativeEnvironment);
    try {
      for (const size of [2047, 2048, 2049]) {
        const path = join(root, `input-${size}.bin`);
        await writeFile(path, Buffer.alloc(size + 13, 255));
        const outcome = await provider.execute({
          operation: "inspect_firmware_entropy",
          input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
            path,
            provider_id: "binwalk-ng",
            range: { offset: 13, length: size },
          }),
        });
        expect(outcome.ok).toBe(true);
        if (!outcome.ok) throw outcome.error;
        const result = outcome.value.result as {
          entropy: {
            blocks: {
              start: number;
              end: number;
              entropy: number;
              root_file_range: { offset: number; length: number };
            }[];
            nominal_window_bytes: number;
            examined_bytes: number;
          };
        };
        expect(result.entropy.nominal_window_bytes).toBe(
          size === 2047 ? 2047 : 1,
        );
        expect(result.entropy.examined_bytes).toBe(size);
        expect(result.entropy.blocks).toHaveLength(size === 2047 ? 1 : size);
        expect(result.entropy.blocks[0]).toMatchObject({
          start: 0,
          end: size === 2047 ? size : 1,
          entropy: 0,
          root_file_range: { offset: 13, length: size === 2047 ? size : 1 },
        });
        expect(result.entropy.blocks.at(-1)?.end).toBe(size);
        const raw = outcome.value.rawResult as {
          sandbox: { work_root: string };
        }[];
        await expect(
          stat(raw[0]?.sandbox.work_root ?? ""),
        ).rejects.toMatchObject({ code: "ENOENT" });
      }
    } finally {
      await provider.close();
    }
  },
  120000,
);

it.runIf(real)(
  "runs native scan/carve/extract/entropy under the same real policy with byte-faithful lineage, recursion and optional PNG publication",
  async () => {
    const root = await createTestTempDirectory("rea-ng-native-");
    const path = join(root, "original.bin");
    const plaintext = Buffer.from("nested payload\n".repeat(25));
    const inner = gzipSync(plaintext);
    const outer = gzipSync(inner);
    const original = Buffer.concat([
      Buffer.alloc(64, 255),
      outer,
      Buffer.alloc(32),
    ]);
    await writeFile(path, original);
    const provider = new BinwalkNgProvider(nativeEnvironment);
    try {
      const inspect = await provider.execute({
        operation: "inspect_firmware_regions",
        input: binwalkNgInputSchemas.inspect_firmware_regions.parse({
          path,
          provider_id: "binwalk-ng",
          range: { offset: 16, length: original.length - 16 },
          options: { search_all: true, workers: 2, no_mmap: true },
        }),
      });
      expect(inspect).toMatchObject({
        ok: true,
        value: {
          provider: { id: "binwalk-ng", version: "4.0.0" },
          result: {
            engine: { worker_count: 2 },
            analyses: [
              {
                regions: [
                  expect.objectContaining({
                    offset: 48,
                    root_file_range: { offset: 64, length: outer.length },
                  }),
                ],
              },
            ],
          },
        },
      });
      const carveDir = join(root, "carved");
      const carve = await provider.execute({
        operation: "carve_firmware",
        input: binwalkNgInputSchemas.carve_firmware.parse({
          path,
          provider_id: "binwalk-ng",
          output_directory: carveDir,
        }),
      });
      expect(carve.ok).toBe(true);
      if (!carve.ok) throw carve.error;
      expect(carve.value.result).toMatchObject({
        files: expect.arrayContaining([
          expect.objectContaining({
            original_file_range: { offset: 64, length: outer.length },
            byte_correspondence: "verified",
          }),
        ]),
      });
      const extract = await provider.execute({
        operation: "extract_firmware",
        input: binwalkNgInputSchemas.extract_firmware.parse({
          path,
          provider_id: "binwalk-ng",
          output_directory: join(root, "extracted"),
          options: { carve: true },
          max_depth: 3,
        }),
      });
      expect(extract.ok).toBe(true);
      if (!extract.ok) throw extract.error;
      expect(extract.value.result).toMatchObject({
        analyses: expect.arrayContaining([
          expect.objectContaining({
            analysis_depth: 1,
            regions: [
              expect.objectContaining({
                signature: "gzip",
                root_file_range: null,
              }),
            ],
          }),
        ]),
        files: expect.arrayContaining([
          expect.objectContaining({
            analysis_depth: 2,
            original_file_range: null,
          }),
        ]),
      });
      const entropy = await provider.execute({
        operation: "inspect_firmware_entropy",
        input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
          path,
          provider_id: "binwalk-ng",
        }),
      });
      expect(entropy).toMatchObject({
        ok: true,
        value: {
          result: {
            entropy: {
              algorithm: "shannon",
              unit: "bits_per_byte",
              examined_bytes: original.length,
            },
            png: { width: 2048, height: 1024, path: null },
          },
        },
      });
      const publishDir = join(root, "entropy-output");
      const published = await provider.execute({
        operation: "inspect_firmware_entropy",
        input: binwalkNgInputSchemas.inspect_firmware_entropy.parse({
          path,
          provider_id: "binwalk-ng",
          output_directory: publishDir,
        }),
      });
      expect(published).toMatchObject({
        ok: true,
        value: { result: { png: { path: join(publishDir, "entropy.png") } } },
      });
      expect(
        (await stat(join(publishDir, "entropy.png"))).size,
      ).toBeGreaterThan(24);
      expect(await readFile(path)).toEqual(original);
      const collision = await provider.execute({
        operation: "carve_firmware",
        input: binwalkNgInputSchemas.carve_firmware.parse({
          path,
          provider_id: "binwalk-ng",
          output_directory: carveDir,
        }),
      });
      expect(collision.ok).toBe(false);
      expect(await readFile(path)).toEqual(original);
    } finally {
      await provider.close();
    }
  },
  120000,
);

it("refuses actual malformed captured inventory bytes while retaining the source digest and valid replacement-character controls", async () => {
  const { createHash } = await import("node:crypto");
  const root = await createTestTempDirectory("rea-ng-inventory-utf8-");
  const manifest = join(root, "runtime.json");
  await writeFile(
    manifest,
    JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts: [] }),
  );
  const header = Buffer.from(
    "Signature Description".padEnd(35) +
      "Signature Name".padEnd(35) +
      "Extraction Utility\n" +
      "source description".padEnd(35),
  );
  const suffix = Buffer.from(
    " ".repeat(31) +
      "Built-in\nTotal signatures: 1\nExtractable signatures: 1\n",
  );
  for (const name of [
    Buffer.from("gzip"),
    Buffer.from("gz�p"),
    Buffer.from([0x67, 0x7a, 0xff, 0x70]),
  ]) {
    const bytes = Buffer.concat([header, name, suffix]);
    const valid = !name.includes(0xff);
    const provider = new BinwalkNgProvider(
      {
        REA_BINWALK_NG_COMMAND: "/usr/bin/true",
        REA_FIRMWARE_BWRAP_COMMAND: "/usr/bin/true",
        REA_BINWALK_NG_RUNTIME_MANIFEST: manifest,
      },
      async (options) =>
        spawnOwnedProviderProcess({
          ...options,
          command: process.execPath,
          arguments: [
            "-e",
            options.arguments.at(-1) === "--version"
              ? 'process.stdout.write("binwalk-ng 4.0.0\\n")'
              : `process.stdout.write(Buffer.from(${JSON.stringify(bytes.toString("hex"))},"hex"))`,
          ],
        }),
    );
    try {
      const outcome = await provider.execute({
        operation: "inspect_firmware_provider",
        input: { provider_id: "binwalk-ng" },
      });
      const expected = {
        text: bytes.toString("utf8"),
        bytes: bytes.length,
        observedBytes: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        utf8Valid: valid,
      };
      if (valid) {
        expect(outcome.ok).toBe(true);
        if (!outcome.ok) throw outcome.error;
        expect(outcome.value.result).toMatchObject({
          formats: [{ name: name.toString("utf8") }],
          inventory_coverage: "native_reported",
        });
        expect(outcome.value.rawResult).toMatchObject({
          inventory_execution: { stdout: expected },
        });
      } else {
        expect(outcome).toMatchObject({
          ok: false,
          error: {
            _tag: "AnalysisOutputError",
            partialObservation: {
              result: { inventory_coverage: "partial" },
              provenance: {
                raw_result: {
                  version_execution: {
                    stdout: { text: "binwalk-ng 4.0.0\n", utf8Valid: true },
                  },
                  inventory_execution: { stdout: expected },
                },
              },
            },
          },
        });
        if (outcome.ok) throw Error("Invalid bytes were normalized");
        const partial = outcome.error.partialObservation;
        if (
          partial === undefined ||
          !("kind" in partial) ||
          partial.kind !== "firmware"
        )
          throw Error("Missing inventory observation");
        expect(partial.result).not.toHaveProperty("formats");
      }
    } finally {
      await provider.close();
    }
  }
});
