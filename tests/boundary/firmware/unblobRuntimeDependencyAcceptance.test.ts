import { expect, it } from "vitest";
import { assertRequiredDependencies } from "../../../scripts/verify/firmware/dependencyGate.mjs";

const provider = (overrides: Record<string, unknown> = {}) => ({
  provider_id: "unblob",
  dependencies: [
    { command: "7z", reported_installed: true },
    { command: "debugfs", reported_installed: false },
  ],
  dependency_readiness: "reported_missing",
  dependency_inventory_coverage: "native_reported",
  unparsed_dependency_lines: [],
  ...overrides,
});

it("requires the fixture extractor while allowing unrelated reported misses", () => {
  expect(assertRequiredDependencies(provider(), ["7z"])).toEqual(["7z"]);
});

it("fails closed when the required extractor is reported missing", () => {
  expect(() =>
    assertRequiredDependencies(
      provider({
        dependencies: [
          { command: "7z", reported_installed: false },
          { command: "debugfs", reported_installed: false },
        ],
      }),
      ["7z"],
    ),
  ).toThrow(/Required Unblob dependency is missing: 7z/u);
});

it.each([
  ["missing provider id", { provider_id: undefined }],
  ["unknown coverage", { dependency_inventory_coverage: "partial" }],
  ["unparsed inventory", { unparsed_dependency_lines: ["unparsed"] }],
  [
    "malformed row",
    { dependencies: [{ command: "7z", reported_installed: 1 }] },
  ],
  [
    "duplicate row",
    {
      dependencies: [
        { command: "7z", reported_installed: true },
        { command: "7z", reported_installed: true },
      ],
    },
  ],
  ["missing required row", { dependencies: [] }],
])("rejects %s dependency evidence", (_label, overrides) => {
  expect(() =>
    assertRequiredDependencies(provider(overrides), ["7z"]),
  ).toThrow();
});

it("keeps malformed and incomplete evidence fail-closed across 256 deterministic structures", () => {
  // xorshift32 seed 0x554e424c varies row types, values, duplicates and line counts.
  let seed = 0x554e424c;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  for (let index = 0; index < 256; index++) {
    const command = `unknown-${next().toString(16)}`;
    const mode = index % 10;
    const overrides: Record<string, unknown> = {};
    if (mode === 0) overrides.dependencies = [];
    if (mode === 1)
      overrides.dependencies = [{ command: "", reported_installed: true }];
    if (mode === 2)
      overrides.dependencies = [{ command: next(), reported_installed: true }];
    if (mode === 3)
      overrides.dependencies = [{ command: "7z", reported_installed: "true" }];
    if (mode === 4)
      overrides.dependencies = [
        { command: "7z", reported_installed: true },
        { command: "7z", reported_installed: Boolean(next() & 1) },
      ];
    if (mode === 5)
      overrides.dependencies = [
        { command: "7z", reported_installed: true },
        { command, reported_installed: next() % 3 === 0 ? null : "unknown" },
      ];
    if (mode === 6) {
      overrides.dependencies = [{ command: "7z", reported_installed: true }];
      overrides.unparsed_dependency_lines = [command, `${command}-second`];
    }
    if (mode === 7) {
      overrides.dependencies = [{ command: "7z", reported_installed: true }];
      overrides.dependency_inventory_coverage = ["native_reported"];
    }
    if (mode === 8) {
      overrides.dependencies = [{ command: "7z", reported_installed: true }];
      overrides.provider_id = next() % 2 === 0 ? "" : null;
    }
    if (mode === 9)
      overrides.dependencies = [{ command: "7z", reported_installed: false }];
    const malformed = provider(overrides);
    expect(() => assertRequiredDependencies(malformed, ["7z"])).toThrow();
  }
});
