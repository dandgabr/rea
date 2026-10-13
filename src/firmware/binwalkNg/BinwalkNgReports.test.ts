import { describe, expect, it } from "vitest";
import {
  parseBinwalkNgAnalyses,
  parseBinwalkNgEntropy,
} from "./BinwalkNgReports.js";

const hit = (id = "local", offset = 2, size = 4) => ({
  id,
  offset,
  size,
  name: "gzip",
  description: "gzip data",
  confidence: 250,
  always_display: false,
  extraction_declined: false,
});
const record = (path: string, hits = [hit()], extractions = {}) => ({
  Analysis: { file_path: path, file_map: hits, extractions },
});
const context = new Map([
  ["/private/root", { size: 10, depth: 0, rootOffset: 64 }],
  ["/private/child", { size: 10, depth: 1, rootOffset: null }],
]);

describe("binwalk-ng native report boundary", () => {
  it("binds unordered analyses and reused IDs to their owning file and adjusts only known root bytes", () => {
    const parsed = parseBinwalkNgAnalyses(
      [record("/private/child"), record("/private/root")],
      context,
    );
    expect(parsed[0]?.regions[0]).toMatchObject({
      provider_local_id: "local",
      local_range: { offset: 2, length: 4 },
      root_file_range: null,
      runtime_address: null,
      size_basis: "provider_reported_validation_unknown",
    });
    expect(parsed[1]?.regions[0]).toMatchObject({
      root_file_range: { offset: 66, length: 4 },
    });
  });
  it("retains unsuccessful extraction, declined extraction and unknown examination without false completion", () => {
    const extraction = {
      size: null,
      success: false,
      extractor: "gzip",
      do_not_recurse: true,
      output_directory: "/private/out/gzip",
    };
    const parsed = parseBinwalkNgAnalyses(
      [
        record("/private/root", [{ ...hit(), extraction_declined: true }], {
          local: extraction,
        }),
        record("/private/child", []),
      ],
      context,
    );
    expect(parsed[0]).toMatchObject({
      coverage: "partial",
      extractions: [
        {
          provider_local_id: "local",
          success: false,
          consumed_size: null,
          diagnostics: null,
          do_not_recurse: true,
        },
      ],
    });
    expect(parsed[1]).toMatchObject({
      coverage: "none_reported",
      examination: "unknown",
      diagnostics: null,
      regions: [],
    });
  });
  it("cannot distinguish healthy unrecognized bytes from native read failure using identical JSON", () => {
    // Pinned main.rs substitutes b"" on read_or_map_file failure, then logs
    // the same empty Analysis emitted by a successful unrecognized scan.
    const healthyNativeJson = [record("/private/root", [])];
    const readFailureNativeJson = [record("/private/root", [])];
    expect(healthyNativeJson).toEqual(readFailureNativeJson);
    for (const raw of [healthyNativeJson, readFailureNativeJson]) {
      expect(parseBinwalkNgAnalyses(raw, context)[0]).toMatchObject({
        file_path: "/private/root",
        coverage: "none_reported",
        examination: "unknown",
        diagnostics: null,
        regions: [],
      });
    }
    expect(
      parseBinwalkNgAnalyses([record("/private/root")], context)[0]?.coverage,
    ).toBe("signature_scan");
  });
  it("preserves empty expected context as unknown examination and never invents examined coverage", () => {
    expect(
      parseBinwalkNgAnalyses(
        [record("/private/empty", [])],
        new Map([["/private/empty", { size: 0, depth: 1, rootOffset: null }]]),
      )[0],
    ).toMatchObject({
      coverage: "none_reported",
      examination: "unknown",
      expected_input_size: 0,
    });
  });
  it("preserves valid observations beside invalid records regardless of report order", () => {
    const valid = record("/private/root");
    const invalid = record("/private/child", [hit("bad", 9, 2)]);
    for (const raw of [
      [valid, invalid],
      [invalid, valid],
    ]) {
      let observed: unknown;
      try {
        parseBinwalkNgAnalyses(raw, context);
      } catch (cause) {
        observed = cause;
      }
      expect(observed).toMatchObject({
        _tag: "AnalysisOutputError",
        partialObservation: {
          kind: "firmware",
          result: {
            analyses: [
              {
                file_path: "/private/root",
                regions: [{ provider_local_id: "local" }],
              },
            ],
            coverage: "partial",
          },
          provenance: { raw_result: raw },
        },
      });
    }
  });
});

describe("binwalk-ng extraction and identity validation", () => {
  it("marks native failed extraction partial independently of declined signatures", () => {
    const extraction = {
      size: 4,
      success: false,
      extractor: "gzip",
      do_not_recurse: false,
      output_directory: "/private/out/gzip",
    };
    const failed = parseBinwalkNgAnalyses(
      [record("/private/root", [hit()], { local: extraction })],
      context,
    );
    expect(failed[0]?.coverage).toBe("partial");
    const succeeded = parseBinwalkNgAnalyses(
      [
        record("/private/root", [hit()], {
          local: { ...extraction, success: true },
        }),
      ],
      context,
    );
    expect(succeeded[0]?.coverage).toBe("signature_scan");
  });
  it("rejects unowned paths, duplicate file identities, duplicate local IDs and outside-file regions", () => {
    expect(() =>
      parseBinwalkNgAnalyses([record("/host/escape")], context),
    ).toThrow("unowned");
    expect(() =>
      parseBinwalkNgAnalyses(
        [record("/private/root"), record("/private/root")],
        context,
      ),
    ).toThrow("Duplicate analysis");
    expect(() =>
      parseBinwalkNgAnalyses(
        [record("/private/root", [hit(), hit()])],
        context,
      ),
    ).toThrow("Duplicate signature");
    expect(() =>
      parseBinwalkNgAnalyses(
        [record("/private/root", [hit("bad", 9, 2)])],
        context,
      ),
    ).toThrow("outside");
  });
  it("rejects extraction IDs without a signature and consumed ranges outside their owner", () => {
    const extraction = {
      size: 9,
      success: true,
      extractor: "gzip",
      do_not_recurse: false,
      output_directory: "/private/out/gzip",
    };
    expect(() =>
      parseBinwalkNgAnalyses(
        [record("/private/root", [hit()], { missing: extraction })],
        context,
      ),
    ).toThrow("signature");
    expect(() =>
      parseBinwalkNgAnalyses(
        [record("/private/root", [hit()], { local: extraction })],
        context,
      ),
    ).toThrow("outside");
  });
});

describe("binwalk-ng source-native Shannon entropy", () => {
  for (const size of [2047, 2048, 2049]) {
    it(`preserves native block windows and raw bits/byte for ${size} bytes`, () => {
      const window = size < 2048 ? size : Math.floor(size / 2048);
      const blocks = Array.from(
        { length: Math.ceil(size / window) },
        (_, index) => ({
          start: index * window,
          end: Math.min(size, (index + 1) * window),
          entropy: size === 2047 ? 7.875 : 0,
        }),
      );
      const parsed = parseBinwalkNgEntropy(
        [{ Entropy: { file: "/private/root", blocks } }],
        { path: "/private/root", size, rootOffset: 64 },
      );
      expect(parsed).toMatchObject({
        algorithm: "shannon",
        unit: "bits_per_byte",
        nominal_window_bytes: window,
        examined_bytes: size,
        coverage: "complete",
        interpretation: null,
      });
      expect(parsed.blocks).toHaveLength(size === 2047 ? 1 : size);
      expect(parsed.blocks[0]).toMatchObject({
        start: 0,
        end: window,
        entropy: blocks[0]?.entropy,
        root_file_range: { offset: 64, length: window },
      });
    });
  }
  it("retains native windows larger than one and the final partial block without root correspondence", () => {
    const size = 4097;
    const blocks = Array.from({ length: 2049 }, (_, index) => ({
      start: index * 2,
      end: Math.min(size, index * 2 + 2),
      entropy: index === 2048 ? 0 : 1,
    }));
    const parsed = parseBinwalkNgEntropy(
      [{ Entropy: { file: "/private/child", blocks } }],
      { path: "/private/child", size, rootOffset: null },
    );
    expect(parsed.nominal_window_bytes).toBe(2);
    expect(parsed.blocks.at(-1)).toEqual({
      start: 4096,
      end: 4097,
      entropy: 0,
      root_file_range: null,
    });
    expect(parsed.examined_bytes).toBe(4097);
  });
  it("rejects missing/discontinuous coverage, wrong native windows and values beyond native units", () => {
    const parse = (blocks: unknown[]) =>
      parseBinwalkNgEntropy([{ Entropy: { file: "/private/root", blocks } }], {
        path: "/private/root",
        size: 2048,
        rootOffset: null,
      });
    expect(() => parse([])).toThrow("coverage");
    expect(() => parse([{ start: 0, end: 2048, entropy: 0 }])).toThrow(
      "window",
    );
    expect(() => parse([{ start: 1, end: 2, entropy: 0 }])).toThrow("coverage");
    expect(() => parse([{ start: 0, end: 1, entropy: 100 }])).toThrow();
  });
});
