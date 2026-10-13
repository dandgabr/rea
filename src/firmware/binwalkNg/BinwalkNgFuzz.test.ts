import { expect, it } from "vitest";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { binwalkNgInputSchemas } from "../../domain/firmware/binwalkNgAnalysis.js";
import {
  parseBinwalkNgAnalyses,
  parseBinwalkNgEntropy,
} from "./BinwalkNgReports.js";
const generator = (seed: number) => () => {
  seed ^= seed << 13;
  seed ^= seed >>> 17;
  seed ^= seed << 5;
  return seed >>> 0;
};
it("bounded JSON boundary fuzz: seed 0x4e473206, 256 analysis cases and 64 entropy cases retain independent facts", () => {
  const next = generator(0x4e473206);
  for (let index = 0; index < 256; index++) {
    const size = 1 + (next() % 128),
      offset = next() % size,
      length = next() % (size - offset + 1),
      rootOffset = next() % 2 === 0 ? null : next() % 8192;
    const hit = {
      id: "id",
      offset,
      size: length,
      name: "gzip",
      description: "fuzz",
      confidence: next() % 256,
      always_display: false,
      extraction_declined: false,
    };
    const good = {
      Analysis: { file_path: "/owned", file_map: [hit], extractions: {} },
    };
    const bad = {
      Analysis: {
        file_path: "/owned",
        file_map: [{ ...hit, offset: size + 1 }],
        extractions: {},
      },
    };
    const raw = JSON.parse(
      JSON.stringify(index % 2 === 0 ? [bad, good] : [good, bad]),
    ) as unknown;
    const files = new Map([["/owned", { size, depth: 0, rootOffset }]]);
    let retained: ReturnType<typeof parseBinwalkNgAnalyses> | undefined;
    try {
      parseBinwalkNgAnalyses(raw, files);
      throw Error("Invalid peer accepted");
    } catch (cause: unknown) {
      expect(cause).toBeInstanceOf(AnalysisOutputError);
      if (
        !(cause instanceof AnalysisOutputError) ||
        cause.partialObservation === undefined ||
        !("kind" in cause.partialObservation) ||
        cause.partialObservation.kind !== "firmware"
      )
        throw cause;
      const partial = cause.partialObservation;
      const result = partial.result as {
        analyses: ReturnType<typeof parseBinwalkNgAnalyses>;
        coverage: string;
      };
      retained = result.analyses;
      expect(result.coverage).toBe("partial");
      expect(partial.provenance).toEqual({ raw_result: raw });
    }
    expect(retained).toHaveLength(1);
    expect(retained?.[0]?.regions[0]).toMatchObject({
      local_range: { offset, length },
      root_file_range:
        rootOffset === null ? null : { offset: rootOffset + offset, length },
      runtime_address: null,
    });
    const empty = parseBinwalkNgAnalyses(
      [{ Analysis: { file_path: "/owned", file_map: [], extractions: {} } }],
      files,
    );
    expect(empty[0]).toMatchObject({
      examination: "unknown",
      coverage: "none_reported",
    });
  }
  for (let index = 0; index < 64; index++) {
    const size = 1 + (next() % 2047),
      value = (next() % 8000) / 1000;
    const raw = [
      {
        Entropy: {
          file: "/owned",
          blocks: [{ start: 0, end: size, entropy: value }],
        },
      },
    ];
    const result = parseBinwalkNgEntropy(raw, {
      path: "/owned",
      size,
      rootOffset: null,
    });
    expect(result.examined_bytes).toBe(size);
    expect(result.blocks[0]).toMatchObject({
      entropy: value,
      root_file_range: null,
    });
    expect(() =>
      parseBinwalkNgEntropy(
        [
          {
            Entropy: {
              file: "/owned",
              blocks: [{ start: 1, end: size, entropy: value }],
            },
          },
        ],
        { path: "/owned", size, rootOffset: null },
      ),
    ).toThrow();
  }
});
it("bounded domain fuzz: seed 0x4e473207, 256 caller option cases enforce named incompatible and ignored combinations", () => {
  const next = generator(0x4e473207);
  for (let index = 0; index < 256; index++) {
    const workers = [0, 1, 2, -1, 1.5][next() % 5] ?? 0;
    const include = next() % 2 === 0 ? ["gzip"] : [],
      exclude = next() % 2 === 0 ? ["zip"] : [];
    const options = {
      workers,
      include,
      exclude,
      search_all: next() % 2 === 0,
      no_mmap: next() % 2 === 0,
    };
    const result = binwalkNgInputSchemas.inspect_firmware_regions.safeParse({
      path: "/selected.bin",
      provider_id: "binwalk-ng",
      options,
    });
    const accepted =
      Number.isSafeInteger(workers) &&
      workers > 0 &&
      (include.length === 0 || exclude.length === 0);
    expect(result.success).toBe(accepted);
    if (result.success) expect(result.data.options).toEqual(options);
    expect(
      binwalkNgInputSchemas.inspect_firmware_entropy.safeParse({
        path: "/selected.bin",
        provider_id: "binwalk-ng",
        options,
      }).success,
    ).toBe(false);
    expect(
      binwalkNgInputSchemas.carve_firmware.safeParse({
        path: "/selected.bin",
        provider_id: "binwalk-ng",
        output_directory: "/out",
        options: { ...options, recursive: true },
      }).success,
    ).toBe(false);
  }
});
