import { expect, it, vi } from "vitest";
import { FirmwareAnalysisService } from "./FirmwareAnalysisService.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import {
  firmwareInputSchemas,
  firmwareResultSchemas,
} from "../../domain/firmware/firmwareAnalysis.js";
import { ok } from "../../domain/result.js";
import { toolContract } from "../../contracts/toolContracts.js";

it("retains omitted-provider legacy defaults while accepting only explicit ng branches", () => {
  expect(
    firmwareInputSchemas.inspect_firmware_regions.parse({ path: "/tmp/input" }),
  ).toEqual({ path: "/tmp/input" });
  expect(
    firmwareInputSchemas.extract_firmware.parse({
      path: "/tmp/input",
      output_directory: "/tmp/new",
    }),
  ).not.toHaveProperty("provider_id");
  const parsed = firmwareInputSchemas.inspect_firmware_regions.parse({
    path: "/tmp/input",
    provider_id: "binwalk-ng",
    range: { offset: 64, length: 82 },
    options: { include: ["gzip"], workers: 2 },
  });
  expect(parsed).toMatchObject({
    provider_id: "binwalk-ng",
    range: { offset: 64, length: 82 },
    options: { include: ["gzip"], workers: 2 },
  });
  expect(
    firmwareInputSchemas.inspect_firmware_regions.safeParse({
      path: "/tmp/input",
      options: { include: ["gzip"] },
    }).success,
  ).toBe(false);
  expect(
    firmwareInputSchemas.extract_firmware.safeParse({
      path: "/tmp/input",
      provider_id: "binwalk-ng",
      output_directory: "/tmp/new",
      options: { include: ["gzip"], exclude: ["tar"] },
    }).success,
  ).toBe(false);
});
it("inventory has a named corpus contract and preserves null subject and actual runtime facts", async () => {
  const contract = toolContract("inspect_firmware_provider");
  const observed = {
    provider_id: "binwalk-ng",
    version: "4.0.0",
    formats: [{ name: "gzip", description: "gzip compressed data" }],
    source_revision: null,
  };
  const execute = vi.fn(async () =>
    ok(
      createAnalysisExecution(
        observed,
        { id: "binwalk-ng", name: "binwalk-ng", version: "4.0.0" },
        { rawResult: { stdout: "native inventory" } },
      ),
    ),
  );
  const service = new FirmwareAnalysisService({ execute });
  const evidence = await service.execute(contract.name, {
    provider_id: "binwalk-ng",
  });
  expect(evidence.ok).toBe(true);
  if (!evidence.ok) throw evidence.error;
  expect(evidence.value.subject).toBeNull();
  expect(evidence.value.provider.id).toBe("binwalk-ng");
  expect(evidence.value.normalized_result).toEqual(observed);
  expect(evidence.value.raw_result).toEqual({ stdout: "native inventory" });
  expect(execute).toHaveBeenCalledWith(
    {
      operation: "inspect_firmware_provider",
      input: { provider_id: "binwalk-ng" },
    },
    undefined,
  );
});
it("names carving and entropy contracts with exact options and rejects false complete scan coverage", () => {
  const carve = toolContract("carve_firmware"),
    entropy = toolContract("inspect_firmware_entropy");
  expect(
    carve.inputSchema.safeParse({
      path: "/tmp/input",
      provider_id: "binwalk-ng",
      output_directory: "/tmp/new",
    }).success,
  ).toBe(true);
  expect(
    entropy.inputSchema.safeParse({
      path: "/tmp/input",
      provider_id: "binwalk-ng",
      options: { workers: 2 },
    }).success,
  ).toBe(false);
  const engine = {
    name: "binwalk-ng",
    version: "4.0.0",
    executable_path: "/runtime/bin/binwalk",
    executable_sha256: "a".repeat(64),
    source_revision: null,
    worker_count: 1,
  };
  const result = {
    provider_id: "binwalk-ng",
    engine,
    input_size: 178,
    selection: { offset: 64, length: 82, sha256: "b".repeat(64) },
    analyses: [],
    attempted_files: [],
    diagnostics: [],
    coverage: "partial",
  };
  expect(
    firmwareResultSchemas.inspect_firmware_regions.safeParse(result).success,
  ).toBe(true);
  expect(
    firmwareResultSchemas.inspect_firmware_regions.safeParse({
      ...result,
      coverage: "complete",
    }).success,
  ).toBe(false);
});

import { FirmwareAnalysisRouter } from "./FirmwareAnalysisRouter.js";
import { firmwareRequestSchema } from "../../domain/firmware/firmwareAnalysis.js";
it("routes explicit ng to its own provider and never falls back when that provider is absent", async () => {
  const legacy = {
    execute: vi.fn(async () =>
      ok(
        createAnalysisExecution(
          { source: "legacy" },
          { id: "legacy", name: "legacy", version: null },
        ),
      ),
    ),
    close: vi.fn(async () => {}),
  };
  const ng = {
    execute: vi.fn(async () =>
      ok(
        createAnalysisExecution(
          { source: "ng" },
          { id: "binwalk-ng", name: "ng", version: null },
        ),
      ),
    ),
    close: vi.fn(async () => {}),
  };
  const router = new FirmwareAnalysisRouter({
    binwalk: legacy,
    unblob: legacy,
    "binwalk-ng": ng,
  });
  const selected = firmwareRequestSchema.parse({
    operation: "inspect_firmware_regions",
    input: {
      path: "/tmp/input",
      provider_id: "binwalk-ng",
      options: { include: ["gzip"] },
    },
  });
  await router.execute(selected);
  expect(ng.execute).toHaveBeenCalledWith(selected, undefined);
  expect(legacy.execute).not.toHaveBeenCalled();
  const unavailable = await new FirmwareAnalysisRouter({
    binwalk: legacy,
    unblob: legacy,
  }).execute(selected);
  expect(unavailable).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisCapabilityUnavailableError",
      providerId: "binwalk-ng",
    },
  });
  expect(legacy.execute).not.toHaveBeenCalled();
  await router.execute(
    firmwareRequestSchema.parse({
      operation: "inspect_firmware_regions",
      input: { path: "/tmp/input" },
    }),
  );
  await router.execute(
    firmwareRequestSchema.parse({
      operation: "extract_firmware",
      input: { path: "/tmp/input", output_directory: "/tmp/new" },
    }),
  );
  expect(legacy.execute).toHaveBeenCalledTimes(2);
  await router.close();
  expect(legacy.close).toHaveBeenCalledTimes(1);
  expect(ng.close).toHaveBeenCalledTimes(1);
});

import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
it("preserves every producing cleanup owner and primary reason when several selected providers fail close", async () => {
  const first = new ProviderCleanupError(
    "binwalk",
    ["/owned/legacy"],
    { reason: "legacy descriptor" },
    { operation: "close_firmware" },
  );
  const second = new ProviderCleanupError(
    "binwalk-ng",
    ["/owned/ng"],
    { reason: "ng process" },
    { operation: "close_firmware" },
  );
  const router = new FirmwareAnalysisRouter({
    binwalk: {
      execute: vi.fn(),
      close: vi.fn(async () => {
        throw first;
      }),
    },
    "binwalk-ng": {
      execute: vi.fn(),
      close: vi.fn(async () => {
        throw second;
      }),
    },
  });
  try {
    await router.close();
    throw new Error("Expected cleanup failure");
  } catch (cause: unknown) {
    expect(cause).toMatchObject({
      cleanupIncomplete: true,
      cleanupResources: ["/owned/legacy", "/owned/ng"],
      diagnostics: {
        primary_error: {
          details: { diagnostics: { reason: "legacy descriptor" } },
        },
      },
    });
  }
});

it("bounded public result fuzz: seed 0x4e473302, 64 cases refuse invented current ranges and complete scan claims", () => {
  let seed = 0x4e473302;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  for (let index = 0; index < 64; index++) {
    const offset = next() % 100000,
      length = (next() % 2048) + 1;
    const result = {
      provider_id: "binwalk-ng",
      engine: {
        name: "binwalk-ng",
        version: "4.0.0",
        executable_path: "/runtime/bin/binwalk",
        executable_sha256: "a".repeat(64),
        source_revision: null,
        worker_count: 1,
      },
      input_size: offset + length,
      selection: { offset, length, sha256: "b".repeat(64) },
      analyses: [
        {
          file_path: `$child_${index}`,
          analysis_depth: 1,
          expected_input_size: length,
          examination: "unknown",
          diagnostics: null,
          regions: [],
          extractions: [],
          coverage: "none_reported",
        },
      ],
      attempted_files: [],
      diagnostics: [],
      coverage: "partial",
      output_directory: "/tmp/new",
      files: [
        {
          relative_path: `child_${index}`,
          path: `/tmp/new/child_${index}`,
          size: length,
          sha256: "c".repeat(64),
          analysis_depth: 1,
          parent_analysis_file: "$input",
          parent_signature_ids: [],
          runtime_address: null,
          original_file_range: null,
          local_range: null,
          byte_correspondence: "unknown",
          carving_observation: {
            sha256: "d".repeat(64),
            local_range: { offset, length },
            original_file_range: { offset, length },
          },
        },
      ],
      unpublished_entries: [],
      unexamined_files: [],
      published_bytes: length,
    };
    expect(
      firmwareResultSchemas.extract_firmware.safeParse(result).success,
    ).toBe(true);
    expect(
      firmwareResultSchemas.extract_firmware.safeParse({
        ...result,
        files: [
          { ...result.files[0], original_file_range: { offset, length } },
        ],
      }).success,
    ).toBe(false);
    expect(
      firmwareResultSchemas.extract_firmware.safeParse({
        ...result,
        files: [{ ...result.files[0], local_range: { offset, length } }],
      }).success,
    ).toBe(false);
    expect(
      firmwareResultSchemas.extract_firmware.safeParse({
        ...result,
        analyses: [{ ...result.analyses[0], coverage: "complete" }],
      }).success,
    ).toBe(false);
    expect(
      firmwareResultSchemas.extract_firmware.safeParse({
        ...result,
        coverage: "complete",
      }).success,
    ).toBe(false);
  }
});
