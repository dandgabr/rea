import { createHash } from "node:crypto";
import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { access, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { expect, it as test, vi } from "vitest";
import {
  firmwareFixture,
  assertFirmwareCleanup,
} from "../../fixtures/firmware/provider.js";
import {
  firmwareResultSchemas,
  binwalkRegionResultSchema,
  firmwareExtractionObservationSchema,
} from "../../../src/domain/firmware/firmwareAnalysis.js";
import { FirmwareAnalysisService } from "../../../src/application/firmware/FirmwareAnalysisService.js";
import { FirmwareProvider } from "../../../src/firmware/FirmwareProvider.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { AnalysisOutputError } from "../../../src/domain/analysisErrorCore.js";
import { FirmwareFileCleanupError } from "../../../src/firmware/FirmwareFiles.js";
import { FIRMWARE_LIMITS } from "../../../src/firmware/FirmwareRelease.js";
import { PrivateRuntimeRoot } from "../../../src/process/PrivateRuntimeRoot.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { ToolResultDelivery } from "../../../src/server/toolResult.js";
import { SafeOutputTree } from "../../../src/artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../../../src/artifacts/SafeOutputTreeCreationFailure.js";
import { jsonObjectSchema } from "../../../src/domain/jsonValue.js";

// Assert recovery behavior through the public reference table, while keeping
// row identity expectations independent of the instruction's digest.
const gapsWithContinuations = (
  result: ReturnType<typeof firmwareResultSchemas.extract_firmware.parse>,
) => {
  const instructions = new Map(
    result.extraction_continuations.map(({ id, instruction }) => [
      id,
      instruction,
    ]),
  );
  return result.extraction_gaps.map(({ continuation_id, ...gap }) => {
    const instruction = instructions.get(continuation_id);
    if (instruction === undefined)
      throw new Error("Missing recovery instruction");
    return { ...gap, continuation: instruction };
  });
};
const fileCloseFailure = vi.hoisted(() => ({
  enabled: false,
  rejectClose: false,
  acquisitions: 0,
  handles: [] as import("node:fs/promises").FileHandle[],
}));

const commitDurability = vi.hoisted(() => ({
  active: false,
  controller: undefined as AbortController | undefined,
  syncs: 0,
}));

const directoryCloseFailure = vi.hoisted(() => ({
  mode: "off" as "off" | "transient" | "persistent",
  attempts: 0,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const filesystem = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...filesystem,
    open: async (...args: Parameters<typeof filesystem.open>) => {
      const handle = await filesystem.open(...args);
      if (fileCloseFailure.enabled) fileCloseFailure.acquisitions += 1;
      if (
        fileCloseFailure.enabled &&
        String(args[0]).endsWith("/extracted/rootfs/config")
      ) {
        const close = handle.close.bind(handle);
        handle.close = async () => {
          if (fileCloseFailure.enabled && fileCloseFailure.rejectClose) {
            if (!fileCloseFailure.handles.includes(handle))
              fileCloseFailure.handles.push(handle);
            throw Error("injected extracted descriptor close failure");
          }
          await close();
        };
      }
      if (
        directoryCloseFailure.mode !== "off" &&
        (await handle.stat()).isDirectory()
      ) {
        const close = handle.close.bind(handle);
        let attempted = false;
        handle.close = async () => {
          directoryCloseFailure.attempts += 1;
          if (
            directoryCloseFailure.mode === "persistent" ||
            (directoryCloseFailure.mode === "transient" && !attempted)
          ) {
            attempted = true;
            throw new Error("injected published directory close failure");
          }
          await close();
        };
      }
      if (commitDurability.active && (await handle.stat()).isDirectory()) {
        const sync = handle.sync.bind(handle);
        handle.sync = async () => {
          await sync();
          commitDurability.syncs += 1;
          if (commitDurability.syncs === 2)
            commitDurability.controller?.abort();
        };
      }
      return handle;
    },
  };
});

const delivery = new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE);

const it = test.skipIf(process.platform !== "linux");

// Historical provider-level Unblob success paths remain as skipped regression
// scenarios while native Unblob is fail-closed. The active no-launch contract
// is asserted in unblobExecution.test.ts; source-only report, publication,
// file and output-tree safety coverage remains in their owning test suites.

it.skip.each([false, true])(
  "blocked: Unblob publication durability cancellation: abort=%s",
  async (abort) => {
    const fixture = await firmwareFixture("observation-facts");
    const controller = new AbortController();
    const commit = SafeOutputTree.prototype.commit;
    let committedTree: SafeOutputTree | undefined;
    const committing = vi.spyOn(SafeOutputTree.prototype, "commit");
    committing.mockImplementationOnce(async function (
      this: SafeOutputTree,
      signal,
    ) {
      committedTree = this;
      commitDurability.active = true;
      commitDurability.syncs = 0;
      commitDurability.controller = abort ? controller : undefined;
      try {
        await commit.call(this, signal);
      } finally {
        commitDurability.active = false;
        commitDurability.controller = undefined;
      }
    });
    try {
      const result = await fixture.service.execute(
        "extract_firmware",
        { path: fixture.path, output_directory: fixture.output },
        { signal: controller.signal },
      );
      expect(commitDurability.syncs).toBe(2);
      expect(committedTree?.published).toBe(!abort);
      if (abort) {
        expect(result).toMatchObject({
          ok: false,
          error: { _tag: "AnalysisCancelledError", cleanupIncomplete: false },
        });
        if (result.ok) throw Error("Canceled durability must not publish");
        expect(projectAnalysisError(result.error)).toMatchObject({
          details: {
            partial_observation: {
              kind: "firmware",
              result: {
                publication_state: "not_committed",
                requested_output_directory: fixture.output,
                tasks: expect.arrayContaining([
                  expect.objectContaining({ path: "$input" }),
                ]),
                randomness: expect.any(Array),
                multifiles: expect.any(Array),
                deleted_files: expect.any(Array),
              },
              provenance: {
                subject: { path: fixture.path },
                raw_result: {
                  report: expect.any(Array),
                  execution: { exit_code: 0 },
                },
              },
            },
          },
        });
        const partial = jsonObjectSchema.parse(result.error.partialObservation);
        const facts = jsonObjectSchema.parse(partial.result);
        expect(facts).not.toHaveProperty("files");
        await expect(access(fixture.output)).rejects.toMatchObject({
          code: "ENOENT",
        });
      } else {
        if (!result.ok) throw result.error;
        expect(await readFile(`${fixture.output}/rootfs/config`, "utf8")).toBe(
          "firmware=true\n",
        );
      }
      expect(await readFile(fixture.path, "utf8")).toBe("fixture-input-data");
      expect(fixture.launches).toHaveLength(2);
      await assertFirmwareCleanup(fixture.launches);
    } finally {
      commitDurability.active = false;
      commitDurability.controller = undefined;
      commitDurability.syncs = 0;
      committing.mockRestore();
    }
  },
);

it.skip.each([
  "existing-output",
  "missing-file",
  "write-failure",
  "cancelled-write",
])(
  "blocked: Unblob publication failure retains native facts: %s",
  async (failure) => {
    const fixture = await firmwareFixture(
      failure === "missing-file"
        ? "observation-facts-missing"
        : "observation-facts",
    );
    if (failure === "existing-output") {
      await mkdir(fixture.output);
      await writeFile(`${fixture.output}/sentinel`, "caller bytes");
    }
    const originalWrite = SafeOutputTree.prototype.write;
    const controller = new AbortController();
    let actualWriteCompleted = false;
    const write =
      failure === "write-failure" || failure === "cancelled-write"
        ? vi.spyOn(SafeOutputTree.prototype, "write")
        : undefined;
    if (write !== undefined) {
      write.mockImplementationOnce(async function (
        this: SafeOutputTree,
        ...args
      ) {
        await originalWrite.apply(this, args);
        expect(await readFile(`${this.outputRoot}/${args[0]}`, "utf8")).toBe(
          "firmware=true\n",
        );
        actualWriteCompleted = true;
        if (failure === "cancelled-write") {
          controller.abort();
          controller.signal.throwIfAborted();
        }
        throw new Error("injected after actual staged file write");
      });
    }
    try {
      const result = await fixture.service.execute(
        "extract_firmware",
        { path: fixture.path, output_directory: fixture.output },
        { signal: controller.signal },
      );
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error._tag).toBe(
        failure === "missing-file"
          ? "AnalysisOutputError"
          : failure === "cancelled-write"
            ? "AnalysisCancelledError"
            : "ProviderAdapterError",
      );
      expect(result.error.cleanupIncomplete).toBe(false);
      if (write !== undefined) expect(actualWriteCompleted).toBe(true);
      expect(projectAnalysisError(result.error)).toMatchObject({
        details: {
          partial_observation: {
            kind: "firmware",
            result: {
              publication_state: "not_committed",
              requested_output_directory: fixture.output,
              tasks: expect.arrayContaining([
                expect.objectContaining({
                  path: "$input",
                  hashes: expect.objectContaining({
                    md5: createHash("md5")
                      .update("fixture-input-data")
                      .digest("hex"),
                    sha1: createHash("sha1")
                      .update("fixture-input-data")
                      .digest("hex"),
                  }),
                  magic: { description: "ASCII text", mime_type: "text/plain" },
                }),
              ]),
              randomness: [
                expect.objectContaining({
                  input_path: "$output/rootfs/config",
                  root_file_range: null,
                  shannon: expect.objectContaining({ mean: 40.000000001 }),
                }),
              ],
              multifiles: [
                expect.objectContaining({
                  provider_id: "multifile-id",
                  constituents: [
                    expect.objectContaining({
                      path: "$output/rootfs/part",
                      is_multi_file: true,
                    }),
                  ],
                }),
              ],
              deleted_files: [
                {
                  path: "$output/rootfs/intermediate.gz",
                  handler: "gzip",
                  reported_sha256: createHash("sha256")
                    .update("firmware=true\n")
                    .digest("hex"),
                },
              ],
            },
            provenance: {
              subject: { path: fixture.path },
              raw_result: {
                report: expect.any(Array),
                execution: { exit_code: 0 },
              },
            },
          },
        },
      });
      const partial = jsonObjectSchema.parse(result.error.partialObservation);
      const facts = jsonObjectSchema.parse(partial.result);
      expect(facts).not.toHaveProperty("files");
      expect(facts).not.toHaveProperty("output_directory");
      if (failure === "existing-output") {
        expect(await readFile(`${fixture.output}/sentinel`, "utf8")).toBe(
          "caller bytes",
        );
        expect(await readdir(fixture.output)).toEqual(["sentinel"]);
      } else {
        await expect(access(fixture.output)).rejects.toMatchObject({
          code: "ENOENT",
        });
      }
      await assertFirmwareCleanup(fixture.launches);
    } finally {
      vi.restoreAllMocks();
    }
  },
);

it("keeps cleanup-failure state local to the selected factory instance", async () => {
  const failed = await firmwareFixture("cleanup-failure");
  const healthy = await firmwareFixture();
  const failure = await failed.service.execute("inspect_firmware_regions", {
    path: failed.path,
  });
  expect(failure).toMatchObject({
    ok: false,
    error: { cleanupIncomplete: true },
  });
  const result = await healthy.service.execute("inspect_firmware_regions", {
    path: healthy.path,
  });
  expect(result.ok).toBe(true);
  await assertFirmwareCleanup(healthy.launches);
});

it("binds region observations to exact bytes and preserves provider-reported uncertainty", async () => {
  const fixture = await firmwareFixture();
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  if (!result.ok) throw result.error;
  const normalized = binwalkRegionResultSchema.parse(
    result.value.normalized_result,
  );
  expect(normalized.regions[0]).toMatchObject({
    offset: 2,
    reported_size: 4,
    size_basis: "provider_reported_validation_unknown",
  });
  expect(normalized).not.toHaveProperty("selection");
  expect(normalized.regions[0]).not.toHaveProperty("local_offset");
  expect(result.value.subject?.local_path).toBe(fixture.path);
  expect(result.value.subject?.format).toBe("file");
  expect(result.value.raw_result).toMatchObject({
    report: [{ Analysis: { file_map: [{ id: "hit" }] } }],
  });
  expect(fixture.launches[1]?.args).toEqual(
    expect.arrayContaining(["--as=1073741824", "--threads", "1"]),
  );
  await assertFirmwareCleanup(fixture.launches);
});

it.each(["wrong-input", "bounds"])(
  "rejects a mismatched or out-of-bounds inspection: %s",
  async (mode) => {
    const fixture = await firmwareFixture(mode);
    const result = await fixture.service.execute("inspect_firmware_regions", {
      path: fixture.path,
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
    await assertFirmwareCleanup(fixture.launches);
  },
);

it.skip("blocked: Unblob intermediate deletion publication", async () => {
  const fixture = await firmwareFixture("deleted");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(normalized.files).toEqual([]);
  expect(normalized.published_bytes).toBe(0);
  expect(normalized.deleted_files).toEqual([
    {
      path: "$output/rootfs/config",
      handler: "gzip",
      reported_sha256: createHash("sha256")
        .update("firmware=true\n")
        .digest("hex"),
    },
  ]);
  expect(normalized.diagnostics).toEqual([]);
  expect(await readdir(fixture.output)).toEqual([]);
  await assertFirmwareCleanup(fixture.launches);
});

it.skip("blocked: Unblob selected interval publication and lineage", async () => {
  const fixture = await firmwareFixture();
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
    range: { offset: 2, length: 4 },
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(normalized.selection).toMatchObject({ offset: 2, length: 4 });
  expect(normalized.files[0]).toMatchObject({
    relative_path: "rootfs/config",
    size: 14,
    original_file_range: null,
    runtime_address: null,
  });
  expect(normalized.chunks[0]?.root_file_range).toEqual({
    offset: 2,
    length: 4,
  });
  expect(normalized.derivations[0]).toMatchObject({
    parent_path: "$input",
    child_path: "$output/rootfs/config",
    handler: "gzip",
    parent_file_range: { offset: 0, length: 4 },
  });
  expect(await readFile(normalized.files[0]?.path ?? "", "utf8")).toBe(
    "firmware=true\n",
  );
  expect(fixture.launches[1]?.args).toEqual(
    expect.arrayContaining(["--process-num", "1", "--randomness-depth", "0"]),
  );
  expect(fixture.launches[1]?.args).not.toContain("--no-sandbox");
  await assertFirmwareCleanup(fixture.launches);
});

it.skip("blocked: Unblob setup-failed publication cleanup retry", async () => {
  const fixture = await firmwareFixture();
  const createTree = SafeOutputTree.create.bind(SafeOutputTree);
  let cleanupAttempts = 0;
  const create = vi
    .spyOn(SafeOutputTree, "create")
    .mockImplementationOnce(async (outputRoot, platform) => {
      const tree = await createTree(outputRoot, platform);
      const rollbackTree = tree.rollback.bind(tree);
      vi.spyOn(tree, "rollback").mockImplementation(async () => {
        cleanupAttempts += 1;
        if (cleanupAttempts === 1)
          throw new Error("injected first cleanup failure");
        return rollbackTree();
      });
      throw new SafeOutputTreeCreationFailure(
        new Error("injected post-acquisition setup failure"),
        tree,
      );
    });
  try {
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      range: { offset: 2, length: 4 },
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        cleanupIncomplete: true,
        partialObservation: {
          kind: "firmware",
          result: {
            publication_state: "not_committed",
            requested_output_directory: fixture.output,
            tasks: expect.any(Array),
          },
          provenance: {
            raw_result: { report: expect.any(Array) },
            subject: { path: fixture.path },
          },
        },
        diagnostics: {
          previous_error: expect.stringContaining(
            "injected post-acquisition setup failure",
          ),
        },
      },
    });
    await expect(access(fixture.output)).resolves.toBeUndefined();
  } finally {
    create.mockRestore();
  }
  await fixture.close();
  expect(cleanupAttempts).toBe(2);
  await expect(access(fixture.output)).rejects.toMatchObject({
    code: "ENOENT",
  });
});

it.skip("blocked: Unblob output after transient directory close failure", async () => {
  const fixture = await firmwareFixture();
  const closeFailure = injectPublishedDirectoryCloseFailure(false);
  try {
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      range: { offset: 2, length: 4 },
    });
    if (!result.ok) throw result.error;
    const normalized = firmwareResultSchemas.extract_firmware.parse(
      result.value.normalized_result,
    );
    expect(normalized.output_directory).toBe(fixture.output);
    expect(await readFile(normalized.files[0]?.path ?? "", "utf8")).toBe(
      "firmware=true\n",
    );
    expect(closeFailure.attempts()).toBeGreaterThanOrEqual(4);
  } finally {
    closeFailure.restore();
  }
});

it.skip("blocked: Unblob result when output cleanup stays uncertain", async () => {
  const fixture = await firmwareFixture();
  const closeFailure = injectPublishedDirectoryCloseFailure(true);
  try {
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      range: { offset: 2, length: 4 },
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        cleanupIncomplete: true,
        partialObservation: {
          kind: "firmware",
          result: {
            output_directory: fixture.output,
            files: [
              expect.objectContaining({
                relative_path: "rootfs/config",
                size: 14,
              }),
            ],
          },
        },
      },
    });
    if (result.ok) throw new Error("Expected unresolved descriptor cleanup");
    expect(result.error).toBeInstanceOf(ProviderCleanupError);
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        partial_observation: {
          kind: "firmware",
          result: { output_directory: fixture.output },
        },
      },
    });
    expect(await readFile(`${fixture.output}/rootfs/config`, "utf8")).toBe(
      "firmware=true\n",
    );
    expect(closeFailure.attempts()).toBeGreaterThanOrEqual(4);
  } finally {
    closeFailure.restore();
  }
  await fixture.close();
  expect(await readFile(`${fixture.output}/rootfs/config`, "utf8")).toBe(
    "firmware=true\n",
  );
});

it("shares recovery prose across distinct unknown chunk identities", async () => {
  const fixture = await firmwareFixture("many-unknown");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(normalized.extraction_gaps).toHaveLength(1000);
  expect(
    new Set(normalized.extraction_gaps.map(({ provider_id }) => provider_id))
      .size,
  ).toBe(1000);
  expect(normalized.extraction_continuations).toHaveLength(1);
  const [instruction] = normalized.extraction_continuations;
  expect(instruction?.instruction).toContain("inspect_firmware_regions");
  expect(
    normalized.extraction_gaps.every(
      (gap) => gap.continuation_id === instruction?.id,
    ),
  ).toBe(true);
});

it("retains a task dependency failure when the producer names no executable", async () => {
  const fixture = await firmwareFixture("unnamed-dependency");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(gapsWithContinuations(normalized)).toEqual([
    {
      kind: "missing-extractor-dependency",
      input_path: "$input",
      relative_path: null,
      handler: null,
      provider_id: null,
      range: null,
      root_file_range: null,
      dependencies: [],
      continuation: expect.stringContaining("identity is unavailable"),
    },
  ]);
});

it("preserves an unnamed dependency failure on its owning chunk", async () => {
  const fixture = await firmwareFixture("unnamed-chunk-dependency");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(gapsWithContinuations(normalized)).toEqual([
    {
      kind: "missing-extractor-dependency",
      input_path: "$input",
      relative_path: null,
      handler: "gzip",
      provider_id: "gzip-id",
      range: { offset: 0, length: 18 },
      root_file_range: { offset: 0, length: 18 },
      dependencies: [],
      continuation: expect.stringContaining("identity is unavailable"),
    },
  ]);
});

it("routes a nested unknown chunk through its published child", async () => {
  const fixture = await firmwareFixture("nested-unknown");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(gapsWithContinuations(normalized)).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        kind: "unknown-chunk-handler",
        input_path: "$output/rootfs/config",
        provider_id: "unknown-id",
        range: { offset: 0, length: 14 },
        root_file_range: null,
        continuation: expect.stringContaining(
          "published child named by this gap's input_path",
        ),
      }),
    ]),
  );
  expect(gapsWithContinuations(normalized)[0]?.continuation).toContain(
    "only if Binwalk is configured with REA_BINWALK_COMMAND",
  );
  expect(gapsWithContinuations(normalized)[0]?.continuation).toContain(
    "unavailable without configured Binwalk",
  );
});

it("retains recovery references in public partial Evidence after publication failure", async () => {
  const fixture = await firmwareFixture("nested-unknown");
  const originalWrite = SafeOutputTree.prototype.write;
  let injected = false;
  const write = vi
    .spyOn(SafeOutputTree.prototype, "write")
    .mockImplementation(async function (this: SafeOutputTree, ...args) {
      if (this.outputRoot !== fixture.output || injected)
        return originalWrite.apply(this, args);
      await originalWrite.apply(this, args);
      injected = true;
      throw new Error("injected after staged firmware write");
    });
  try {
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected publication to fail");
    const projected = projectAnalysisError(result.error);
    expect(projected).toMatchObject({
      details: {
        partial_observation: {
          kind: "firmware",
          result: {
            publication_state: "not_committed",
            extraction_gaps: [
              expect.objectContaining({
                kind: "unknown-chunk-handler",
                input_path: "$output/rootfs/config",
                continuation_id: expect.any(String),
              }),
            ],
            extraction_continuations: [
              {
                id: expect.any(String),
                instruction: expect.stringContaining(
                  "no verified committed child",
                ),
              },
            ],
          },
        },
      },
    });
    const details = jsonObjectSchema.parse(projected.details);
    const partial = jsonObjectSchema.parse(details.partial_observation);
    const facts = firmwareExtractionObservationSchema.parse(partial.result);
    const [gap] = facts.extraction_gaps;
    expect(gap).toBeDefined();
    expect(facts.extraction_continuations).toContainEqual(
      expect.objectContaining({
        id: gap?.continuation_id,
        instruction: expect.stringContaining("no verified committed child"),
      }),
    );
    expect(facts).not.toHaveProperty("files");
  } finally {
    write.mockRestore();
    await fixture.close();
  }
  await assertFirmwareCleanup(fixture.launches);
});

it("retains unpublished entry metadata and linked gaps in partial Evidence", async () => {
  const fixture = await firmwareFixture("link");
  const originalWrite = SafeOutputTree.prototype.write;
  let injected = false;
  const write = vi
    .spyOn(SafeOutputTree.prototype, "write")
    .mockImplementation(async function (this: SafeOutputTree, ...args) {
      if (this.outputRoot !== fixture.output || injected)
        return originalWrite.apply(this, args);
      await originalWrite.apply(this, args);
      injected = true;
      throw new Error("injected after staged firmware write");
    });
  try {
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected publication to fail");
    const projected = projectAnalysisError(result.error);
    expect(projected).toMatchObject({
      details: {
        partial_observation: {
          kind: "firmware",
          result: {
            publication_state: "not_committed",
            unpublished_entries: [
              {
                relative_path: "escape",
                kind: "symlink",
                link_target: "/etc/passwd",
              },
            ],
            extraction_gaps: [
              expect.objectContaining({
                kind: "unpublished-entry",
                input_path: "$output/escape",
                relative_path: "escape",
                continuation_id: expect.any(String),
              }),
            ],
            extraction_continuations: [
              {
                id: expect.any(String),
                instruction: expect.stringContaining(
                  "Retain the link or special entry as metadata",
                ),
              },
            ],
          },
        },
      },
    });
    const details = jsonObjectSchema.parse(projected.details);
    const partial = jsonObjectSchema.parse(details.partial_observation);
    const facts = firmwareExtractionObservationSchema.parse(partial.result);
    const [gap] = facts.extraction_gaps;
    expect(gap?.continuation_id).toBe(facts.extraction_continuations[0]?.id);
    expect(facts.unpublished_entries).toEqual([
      {
        relative_path: "escape",
        kind: "symlink",
        link_target: "/etc/passwd",
      },
    ]);
    expect(facts).not.toHaveProperty("files");
    expect(facts).not.toHaveProperty("output_directory");
  } finally {
    write.mockRestore();
    await fixture.close();
  }
  await assertFirmwareCleanup(fixture.launches);
});

it("retains every eligible child in a maximum-depth continuation", async () => {
  const fixture = await firmwareFixture("depth-reentry");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
    max_depth: 10,
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  const gap = gapsWithContinuations(normalized).find(
    ({ kind, input_path }) =>
      kind === "depth-limited" && input_path === "$output/rootfs/config",
  );
  expect(gap?.continuation).toContain(
    JSON.stringify(`${fixture.output}/rootfs/config/inner.gz`),
  );
  expect(gap?.continuation).toContain(
    JSON.stringify(`${fixture.output}/rootfs/config/second.gz`),
  );
});

it("withholds the nested rerun advice when the published child exceeds the input limit", async () => {
  const testInputLimit = 20;
  const descriptor = Object.getOwnPropertyDescriptor(
    FIRMWARE_LIMITS,
    "inputBytes",
  );
  if (descriptor === undefined) throw new Error("Missing firmware input limit");
  Object.defineProperty(FIRMWARE_LIMITS, "inputBytes", {
    value: testInputLimit,
  });
  let fixture: Awaited<ReturnType<typeof firmwareFixture>> | undefined;
  try {
    fixture = await firmwareFixture("nested-unknown-oversized");
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (!result.ok) throw result.error;
    const normalized = firmwareResultSchemas.extract_firmware.parse(
      result.value.normalized_result,
    );
    expect(gapsWithContinuations(normalized)).toEqual([
      {
        kind: "unknown-chunk-handler",
        input_path: "$output/rootfs/config",
        relative_path: null,
        handler: null,
        provider_id: "unknown-id",
        range: { offset: 0, length: 14 },
        root_file_range: null,
        dependencies: [],
        continuation: expect.stringContaining(
          "cannot accept it as a fresh input",
        ),
      },
    ]);
    expect(normalized.files[0]?.size).toBeGreaterThan(testInputLimit);
  } finally {
    if (fixture !== undefined) await fixture.close();
    Object.defineProperty(FIRMWARE_LIMITS, "inputBytes", descriptor);
  }
  if (fixture !== undefined) await assertFirmwareCleanup(fixture.launches);
});

it.each([
  ["depth", 10, "rerun extract_firmware"],
  ["depth-orphan", 10, "cannot be restarted"],
] as const)(
  "bounds the maximum-depth continuation by a usable published child (%s)",
  async (mode, maxDepth, expected) => {
    const fixture = await firmwareFixture(mode);
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      max_depth: maxDepth,
    });
    if (!result.ok) throw result.error;
    const normalized = firmwareResultSchemas.extract_firmware.parse(
      result.value.normalized_result,
    );
    expect(normalized.depth_limited_paths.length).toBeGreaterThan(0);
    expect(
      gapsWithContinuations(normalized).filter(
        (gap) => gap.kind === "depth-limited",
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "depth-limited",
          continuation: expect.stringContaining(expected),
        }),
      ]),
    );
  },
);

it("reports a failed multi-file stage as an extractor-failure gap", async () => {
  const fixture = await firmwareFixture("multi-file-failure");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(gapsWithContinuations(normalized)).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        kind: "extractor-failure",
        input_path: "$input",
        handler: "tar",
        provider_id: "mf-id",
        range: null,
        root_file_range: null,
      }),
    ]),
  );
});

it("carries the owning multi-file stage on a task-level dependency gap", async () => {
  const fixture = await firmwareFixture("multi-file-dependency");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(gapsWithContinuations(normalized)).toEqual([
    {
      kind: "missing-extractor-dependency",
      input_path: "$input",
      relative_path: null,
      handler: "squashfs",
      provider_id: "sq-id",
      range: null,
      root_file_range: null,
      dependencies: ["sasquatch"],
      continuation: expect.stringContaining("installs nothing"),
    },
  ]);
  expect(normalized.diagnostics).toEqual([
    expect.objectContaining({ stage: "squashfs" }),
  ]);
});

const injectPublishedDirectoryCloseFailure = (persistent: boolean) => {
  directoryCloseFailure.attempts = 0;
  const commit = SafeOutputTree.prototype.commit;
  const spy = vi
    .spyOn(SafeOutputTree.prototype, "commit")
    .mockImplementation(async function (this: SafeOutputTree) {
      directoryCloseFailure.mode = persistent ? "persistent" : "transient";
      await commit.call(this);
    });
  return {
    attempts: () => directoryCloseFailure.attempts,
    restore: () => {
      directoryCloseFailure.mode = "off";
      spy.mockRestore();
    },
  };
};

it.skip.each(["depth", "dependency", "link"])(
  "blocked: Unblob partial extraction report for %s",
  async (mode) => {
    const fixture = await firmwareFixture(mode);
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (!result.ok) throw result.error;
    const normalized = firmwareResultSchemas.extract_firmware.parse(
      result.value.normalized_result,
    );
    expect(normalized.coverage).toBe("partial");
    expect(normalized.files).toHaveLength(1);
    if (mode === "depth")
      expect(normalized.depth_limited_paths).toEqual(["$output/rootfs/config"]);
    if (mode === "depth")
      expect(gapsWithContinuations(normalized)).toEqual([
        {
          kind: "depth-limited",
          input_path: "$output/rootfs/config",
          relative_path: null,
          handler: null,
          provider_id: null,
          range: null,
          root_file_range: null,
          dependencies: [],
          continuation: expect.stringMatching(
            /max_depth.*fresh output_directory/u,
          ),
        },
      ]);
    if (mode === "dependency")
      expect(normalized.diagnostics).toEqual([
        {
          input_path: "$input",
          stage: "gzip",
          missing_dependencies: ["sasquatch"],
          report: {
            __typename__: "ExtractorDependencyNotFoundReport",
            severity: "ERROR",
            dependencies: ["sasquatch"],
          },
        },
      ]);
    if (mode === "dependency")
      expect(gapsWithContinuations(normalized)).toEqual([
        {
          kind: "missing-extractor-dependency",
          input_path: "$input",
          relative_path: null,
          handler: "gzip",
          provider_id: "gzip-id",
          range: { offset: 0, length: 18 },
          root_file_range: { offset: 0, length: 18 },
          dependencies: ["sasquatch"],
          continuation: expect.stringContaining("installs nothing"),
        },
      ]);
    if (mode === "link") {
      expect(normalized.unpublished_entries).toEqual([
        {
          relative_path: "escape",
          kind: "symlink",
          link_target: "/etc/passwd",
        },
      ]);
      expect(gapsWithContinuations(normalized)).toEqual([
        {
          kind: "unpublished-entry",
          input_path: "$output/escape",
          relative_path: "escape",
          handler: null,
          provider_id: null,
          range: null,
          root_file_range: null,
          dependencies: [],
          continuation: expect.stringContaining("metadata"),
        },
      ]);
      await expect(access(`${fixture.output}/escape`)).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
    await assertFirmwareCleanup(fixture.launches);
  },
);

it.skip("blocked: Unblob output identity for a file named $input", async () => {
  const fixture = await firmwareFixture("reserved-name");
  const outcome = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (!outcome.ok) throw outcome.error;
  const result = firmwareResultSchemas.extract_firmware.parse(
    outcome.value.normalized_result,
  );
  expect(result.files[0]?.relative_path).toBe("$input");
  expect(result.derivations[0]).toMatchObject({
    parent_path: "$input",
    child_path: "$output/$input",
  });
  expect(await readFile(`${fixture.output}/$input`, "utf8")).toBe(
    "firmware=true\n",
  );
  await assertFirmwareCleanup(fixture.launches);
});

it.each(["hash", "malformed", "budget", "missing-file", "deleted-and-missing"])(
  "rejects invalid or over-budget extraction and rolls back output: %s",
  async (mode) => {
    const fixture = await firmwareFixture(mode);
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      ...(mode === "budget" ? { max_output_bytes: 1000 } : {}),
    });
    expect(result.ok).toBe(false);
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await assertFirmwareCleanup(fixture.launches);
  },
);

it.skip("blocked: Unblob output preservation and interval admission", async () => {
  const fixture = await firmwareFixture();
  await mkdir(fixture.output);
  await writeFile(`${fixture.output}/existing`, "keep");
  const existing = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  expect(existing.ok).toBe(false);
  expect(await readFile(`${fixture.output}/existing`, "utf8")).toBe("keep");
  const previous = fixture.launches.length;
  const invalid = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
    range: { offset: 100, length: 1 },
  });
  expect(invalid).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
  expect(fixture.launches).toHaveLength(previous);
  await assertFirmwareCleanup(fixture.launches);
});

it.skip("blocked: Unblob startup stderr without a report", async () => {
  const fixture = await firmwareFixture("startup");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (result.ok) throw new Error("Expected startup failure");
  const details = {
    diagnostics: {
      stderr: expect.stringContaining("Landlock sandbox is not available"),
      exit_code: 1,
    },
  };
  expect(projectAnalysisError(result.error)).toMatchObject({ details });
  expect(
    delivery.toCallToolResult(result, toolContract("extract_firmware"))
      .structuredContent,
  ).toMatchObject({ error: { details } });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "ProviderAdapterError",
      diagnostics: {
        exit_code: 1,
        stderr: expect.stringContaining("Landlock sandbox is not available"),
        report_failure: expect.stringContaining("ENOENT"),
      },
    },
  });
  await expect(access(fixture.output)).rejects.toMatchObject({
    code: "ENOENT",
  });
  await assertFirmwareCleanup(fixture.launches);
});

it.skip("blocked: Unblob missing output after successful process", async () => {
  const fixture = await firmwareFixture("missing-report");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      reason: expect.stringContaining("expected complete report"),
    },
  });
  if (result.ok) throw new Error("Expected missing-output failure");
  expect(projectAnalysisError(result.error)).toMatchObject({
    details: { reason: expect.stringContaining("Producer forgot its report") },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("cancels an owned active process and refuses already-cancelled admission", async () => {
  const fixture = await firmwareFixture("stall");
  const controller = new AbortController();
  const pending = fixture.service.execute(
    "inspect_firmware_regions",
    { path: fixture.path },
    { signal: controller.signal },
  );
  await expect.poll(() => fixture.launches.length).toBe(2);
  controller.abort();
  expect(await pending).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
  const cancelled = await fixture.service.execute(
    "inspect_firmware_regions",
    { path: fixture.path },
    { signal: AbortSignal.abort() },
  );
  expect(cancelled).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
  expect(fixture.launches).toHaveLength(2);
  await assertFirmwareCleanup(fixture.launches);
});

it.each(["admitted", "running"])(
  "rejects busy capacity without admitting a waiter: %s",
  async (stage) => {
    const fixture = await firmwareFixture("stall");
    const activeController = new AbortController();
    const active = fixture.service.execute(
      "inspect_firmware_regions",
      { path: fixture.path },
      { signal: activeController.signal },
    );
    try {
      if (stage === "running")
        await expect.poll(() => fixture.launches.length).toBe(2);
      const otherController = new AbortController();
      const refusal = fixture.service.execute(
        "inspect_firmware_regions",
        { path: fixture.path },
        { signal: otherController.signal },
      );
      const observed = await Promise.race([
        refusal,
        new Promise((resolve) => {
          const timer = setTimeout(() => {
            otherController.abort();
            resolve("admitted waiter");
          }, 200);
          void refusal.finally(() => clearTimeout(timer));
        }),
      ]);
      expect(observed).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisResourceConstraintError",
          resource: "capacity",
        },
      });
      if (stage === "running") expect(fixture.launches).toHaveLength(2);
    } finally {
      activeController.abort();
      expect((await active).ok).toBe(false);
    }
    await assertFirmwareCleanup(fixture.launches);
  },
);

it("retains an uncertain worker's workspace and blocks later launches", async () => {
  const fixture = await firmwareFixture("cleanup-failure");
  const first = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(first).toMatchObject({
    ok: false,
    error: { cleanupIncomplete: true },
  });
  const workspace = fixture.launches[0]?.cwd;
  expect(workspace).toBeDefined();
  if (workspace === undefined) throw new Error("Expected retained workspace");
  await access(workspace);
  const originalLaunches = [...fixture.launches];
  const next = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(next).toMatchObject({ ok: false, error: { cleanupIncomplete: true } });
  expect(fixture.launches).toEqual(originalLaunches);
  await access(workspace);
  fixture.restoreCleanup();
  const resumed = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  if (!resumed.ok) throw resumed.error;
  expect(resumed.value.subject?.local_path).toBe(fixture.path);
  await assertFirmwareCleanup(fixture.launches);
});

it("accepts another build on the verified release line and reports it", async () => {
  const fixture = await firmwareFixture("normal", "binwalk 3.1.2");
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  if (!result.ok) throw result.error;
  expect(result.value.provider.version).toBe("3.1.2");
  expect(result.value.limitations.join("\n")).toContain(
    "verified against 3.1.0",
  );
  expect(result.value.normalized_result).toMatchObject({
    engine: { version: "3.1.2" },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("names the accepted release line when the banner is another line", async () => {
  const fixture = await firmwareFixture("normal", "binwalk 3.2.0");
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisCapabilityUnavailableError",
      reason: expect.stringContaining("Binwalk 3.1.x"),
    },
  });
  if (result.ok) throw new Error("Unsupported version must be refused");
  expect(result.error.capturedOutput).toMatchObject({
    stdout: "binwalk 3.2.0\n",
    stdout_bytes: Buffer.byteLength("binwalk 3.2.0\n"),
    arguments: ["--version"],
    command: "/usr/bin/true",
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("retains malformed version bytes and command identity when refusing the banner", async () => {
  const fixture = await firmwareFixture("version-invalid-utf8");
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      message: expect.stringContaining("not valid UTF-8"),
      capturedOutput: {
        stdout: "�\n",
        stdout_bytes: 2,
        stdout_utf8_valid: false,
        arguments: ["--version"],
        command: "/usr/bin/true",
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("retains an overlong version banner and command identity when refusing it", async () => {
  const banner = "x".repeat(1025);
  const fixture = await firmwareFixture("normal", banner);
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisCapabilityUnavailableError",
      capturedOutput: {
        stdout: `${banner}\n`,
        stdout_bytes: 1026,
        arguments: ["--version"],
        command: "/usr/bin/true",
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("rejects absent or unsupported engines without installing anything", async () => {
  const missing = await new FirmwareAnalysisService(
    new FirmwareProvider({}),
  ).execute("inspect_firmware_regions", { path: "/tmp/unused" });
  expect(missing).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCapabilityUnavailableError" },
  });
  const fixture = await firmwareFixture("version");
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCapabilityUnavailableError" },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("normalizes selected inspection offsets once and retains the selected snapshot identity", async () => {
  const fixture = await firmwareFixture();
  await writeFile(fixture.path, Buffer.alloc(100, 0x61));
  const outcome = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
    range: { offset: 64, length: 20 },
  });
  if (!outcome.ok) throw outcome.error;
  expect(outcome.value.normalized_result).toMatchObject({
    input_size: 100,
    selection: {
      offset: 64,
      length: 20,
      sha256: createHash("sha256").update(Buffer.alloc(20, 0x61)).digest("hex"),
    },
    regions: [{ offset: 66, local_offset: 2, reported_size: 4 }],
  });
  expect(outcome.value.locations).toEqual([
    { kind: "file-offset-range", start: 64, end: 84 },
  ]);
  expect(await readFile(fixture.path)).toEqual(Buffer.alloc(100, 0x61));
  await assertFirmwareCleanup(fixture.launches);
});

it("rejects native inspection hits outside the selected bytes even when inside the original file", async () => {
  const fixture = await firmwareFixture("outside-selection");
  await writeFile(fixture.path, Buffer.alloc(100, 0x61));
  const outcome = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
    range: { offset: 64, length: 20 },
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      reason: "Reported region lies outside the selected file",
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it.skip("blocked: Unblob skip-extraction inspection", async () => {
  const fixture = await firmwareFixture();
  const unsupported = await fixture.service.execute(
    "inspect_firmware_regions",
    {
      path: fixture.path,
      provider_id: "unblob",
      options: { randomness_depth: 2, workers: 3 },
    },
  );
  expect(unsupported).toMatchObject({
    ok: true,
    value: {
      provider: { id: "unblob" },
      normalized_result: {
        provider_id: "unblob",
        mode: "inspection",
        engine: { worker_count: 3 },
        chunks: [{ handler: "gzip" }],
      },
    },
  });
  expect(fixture.launches[1]?.args).toContain("--skip-extraction");
  const supported = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
    provider_id: "binwalk",
  });
  expect(supported.ok && supported.value.provider.id).toBe("binwalk");
  await assertFirmwareCleanup(fixture.launches);
});

it("keeps framed Unblob guest diagnostics separate from launcher transport capture", async () => {
  const fixture = await firmwareFixture();
  const outcome = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
    provider_id: "unblob",
  });
  if (!outcome.ok) throw outcome.error;
  const raw = jsonObjectSchema.parse(outcome.value.raw_result);
  const execution = jsonObjectSchema.parse(raw.execution);
  const transport = jsonObjectSchema.parse(execution.transport);
  const guestCapture = jsonObjectSchema.parse(execution.captured_output);
  const transportCapture = jsonObjectSchema.parse(transport.captured_output);

  expect(execution).toMatchObject({
    command: expect.stringContaining("unblob-command"),
    stdout: { text: expect.any(String), bytes: expect.any(Number) },
  });
  expect(guestCapture).toMatchObject({
    command: expect.stringContaining("unblob-command"),
    arguments: expect.arrayContaining(["--extract-dir"]),
  });
  expect(transport).toMatchObject({
    command: process.execPath,
    resource_limiter: process.execPath,
    stdout: { text: "" },
  });
  expect(transportCapture).toMatchObject({
    command: process.execPath,
    arguments: expect.arrayContaining([
      expect.stringContaining("/tests/fixtures/firmware/producer.mjs"),
    ]),
  });
  expect(transport.arguments).toEqual(transportCapture.arguments);
  expect(execution).not.toHaveProperty("resource_limiter");
  await assertFirmwareCleanup(fixture.launches);
});

it("retains malformed guest frame bytes and transport capture on UTF-8 rejection", async () => {
  const fixture = await firmwareFixture("frame-invalid-utf8");
  const outcome = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
    provider_id: "unblob",
  });
  expect(outcome).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      message: expect.stringContaining("stdout is not valid UTF-8"),
      capturedOutput: {
        stdout: "�",
        stdout_bytes: 1,
        stdout_utf8_valid: false,
        stdout_sha256: createHash("sha256")
          .update(Buffer.from([0xff]))
          .digest("hex"),
        command: expect.stringContaining("unblob-command"),
        arguments: expect.arrayContaining(["--extract-dir"]),
      },
      diagnostics: {
        output_source: "unblob_guest_frame",
        transport_capture: {
          command: process.execPath,
          arguments: expect.arrayContaining([
            expect.stringContaining("/tests/fixtures/firmware/producer.mjs"),
          ]),
        },
      },
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

/** An already stopped, disjoint root must remain independently cleanable. */
const retainSettledFirmwareWorkspace = async (
  fixture: Awaited<ReturnType<typeof firmwareFixture>>,
  enabled: boolean,
) => {
  let unrelatedStaging: string | undefined;
  let retainUnrelated = true;
  const originalRootClose = PrivateRuntimeRoot.prototype.close;
  const rootClose = enabled
    ? vi
        .spyOn(PrivateRuntimeRoot.prototype, "close")
        .mockImplementation(async function (this: PrivateRuntimeRoot) {
          if (
            retainUnrelated &&
            (unrelatedStaging === undefined || this.path === unrelatedStaging)
          ) {
            unrelatedStaging ??= this.path;
            throw Error("Injected settled disjoint workspace removal failure");
          }
          await originalRootClose.call(this);
        })
    : undefined;
  if (rootClose !== undefined) {
    const prior = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: `${fixture.root}/settled-output`,
    });
    expect(prior).toMatchObject({
      ok: false,
      error: { cleanupIncomplete: true },
    });
    expect(unrelatedStaging).toBeDefined();
    await expect(access(unrelatedStaging!)).resolves.toBeUndefined();
  }
  return {
    staging: unrelatedStaging,
    release: () => {
      retainUnrelated = false;
    },
    restore: () => rootClose?.mockRestore(),
  };
};

/** Inspect the actual original primary/descriptor owner through bounded cause links. */
const expectFirmwareDescriptorPrimary = (
  error: Error,
  primary: AnalysisOutputError,
) => {
  const causeChain: unknown[] = [];
  let cause: unknown = error;
  while (cause instanceof Error && !causeChain.includes(cause)) {
    causeChain.push(cause);
    cause = cause.cause;
  }
  const descriptor = causeChain.find(
    (error): error is FirmwareFileCleanupError =>
      error instanceof FirmwareFileCleanupError,
  );
  expect(descriptor).toBeDefined();
  expect(causeChain).toContain(primary);
  expect(descriptor?.diagnostics?.primary_error).toMatchObject({
    code: "unreadable_output",
    details: { reason: primary.reason },
  });
  expect(descriptor?.resourceScope).toBeDefined();
  return descriptor!;
};

/** The exact staging bytes and live descriptors must survive every failed retry. */
const expectRetainedFirmwareWorkspace = async (
  staging: string,
  bytes: string,
) => {
  await expect(access(staging)).resolves.toBeUndefined();
  expect(fileCloseFailure.handles.every((handle) => handle.fd >= 0)).toBe(true);
  expect(await readFile(`${staging}/extracted/rootfs/config`, "utf8")).toBe(
    bytes,
  );
};

it.skip.each(["none", "caller", "deadline"] as const)(
  "blocked: Unblob publication rollback descriptor ownership: %s",
  async (lateAbort) => {
    const fixture = await firmwareFixture();
    const disjoint = await retainSettledFirmwareWorkspace(
      fixture,
      lateAbort === "none",
    );
    const caller = new AbortController();
    const deadline = new AbortController();
    const timeout =
      lateAbort === "deadline"
        ? vi
            .spyOn(AbortSignal, "timeout")
            .mockImplementationOnce((milliseconds) => {
              expect(milliseconds).toBe(FIRMWARE_LIMITS.timeoutMs);
              return deadline.signal;
            })
        : undefined;
    const bytes = "firmware=true\n";
    const primary = new AnalysisOutputError(
      "extract_firmware",
      "Injected failure after independently verified staged bytes",
      {
        capturedOutput: { stdout: bytes, stderr: "", truncated: false },
      },
    );
    const originalWrite = SafeOutputTree.prototype.write;
    const write = vi
      .spyOn(SafeOutputTree.prototype, "write")
      .mockImplementationOnce(async function (this: SafeOutputTree, ...args) {
        await originalWrite.apply(this, args);
        expect(await readFile(`${this.outputRoot}/${args[0]}`, "utf8")).toBe(
          bytes,
        );
        fileCloseFailure.rejectClose = true;
        throw primary;
      });
    fileCloseFailure.handles.length = 0;
    fileCloseFailure.acquisitions = 0;
    fileCloseFailure.rejectClose = false;
    // Admit the publication handle before its write fails; hash cleanup remains healthy.
    fileCloseFailure.enabled = true;
    const rollback = vi
      .spyOn(SafeOutputTree.prototype, "rollback")
      .mockImplementation(async () => {
        if (lateAbort === "caller") caller.abort();
        if (lateAbort === "deadline") deadline.abort();
        throw new Error("injected publication rollback failure");
      });
    try {
      const outcome = await fixture.service.execute(
        "extract_firmware",
        { path: fixture.path, output_directory: fixture.output },
        { signal: caller.signal },
      );
      expect(outcome).toMatchObject({
        ok: false,
        error: {
          cleanupIncomplete: true,
          capturedOutput: primary.capturedOutput,
          partialObservation: {
            result: {
              publication_state: "not_committed",
              tasks: expect.any(Array),
            },
          },
        },
      });
      if (outcome.ok) throw Error("Expected compound cleanup failure");
      const scope = expectFirmwareDescriptorPrimary(
        outcome.error,
        primary,
      ).resourceScope;
      const staging = fixture.launches.at(-1)?.cwd;
      expect(staging).toBeDefined();
      expect(outcome.error.cleanupResources).toEqual(
        expect.arrayContaining([
          fixture.output,
          staging,
          ...fileCloseFailure.handles.map(
            () => `${staging}/extracted/rootfs/config`,
          ),
        ]),
      );
      await expect(access(staging!)).resolves.toBeUndefined();
      expect(fileCloseFailure.handles.length).toBeGreaterThan(0);
      expect(fileCloseFailure.handles.every((handle) => handle.fd >= 0)).toBe(
        true,
      );
      const launches = fixture.launches.length;
      const acquisitions = fileCloseFailure.acquisitions;
      disjoint.release();
      const blocked = await fixture.service.execute("extract_firmware", {
        path: fixture.path,
        output_directory: fixture.output,
      });
      expect(blocked).toMatchObject({
        ok: false,
        error: { cleanupIncomplete: true },
      });
      expect(fixture.launches).toHaveLength(launches);
      expect(fileCloseFailure.acquisitions).toBe(acquisitions);
      await expectRetainedFirmwareWorkspace(staging!, bytes);

      if (disjoint.staging !== undefined) {
        await expect(access(disjoint.staging)).rejects.toMatchObject({
          code: "ENOENT",
        });
        expect(
          await readFile(
            `${fixture.root}/settled-output/rootfs/config`,
            "utf8",
          ),
        ).toBe(bytes);
      }
      await expect(fixture.close()).rejects.toMatchObject({
        cleanupIncomplete: true,
      });
      await expectRetainedFirmwareWorkspace(staging!, bytes);
      await expect(scope!.retryCleanup()).rejects.toBeDefined();
      await expectRetainedFirmwareWorkspace(staging!, bytes);
      fileCloseFailure.enabled = false;
      write.mockRestore();
      rollback.mockRestore();
      timeout?.mockRestore();
      disjoint.restore();
      await fixture.close();
      expect(fixture.launches).toHaveLength(launches);
      expect(fileCloseFailure.handles.every((handle) => handle.fd === -1)).toBe(
        true,
      );
      for (const handle of fileCloseFailure.handles)
        await expect(handle.stat()).rejects.toMatchObject({ code: "EBADF" });
      await expect(access(fixture.output)).rejects.toMatchObject({
        code: "ENOENT",
      });
      await expect(access(staging!)).rejects.toMatchObject({ code: "ENOENT" });
      expect(await readFile(fixture.path, "utf8")).toBe("fixture-input-data");
    } finally {
      fileCloseFailure.enabled = false;
      write.mockRestore();
      rollback.mockRestore();
      timeout?.mockRestore();
      disjoint.restore();
      await fixture.close();
    }
  },
);
