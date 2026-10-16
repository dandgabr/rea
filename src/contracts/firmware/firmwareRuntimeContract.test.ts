import { Ajv } from "ajv";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it } from "vitest";
import { toolInputSchemaWithMetadata } from "../toolSchemaMetadata.js";
import { FIRMWARE_TOOL_CONTRACTS } from "./firmwareToolContracts.js";

const runtime = {
  kind: "container",
  command: "/usr/bin/podman",
  image: `sha256:${"c".repeat(64)}`,
  existing_store_profile: "/tmp/admitted-store.json",
};

it.each(["draft-2020-12", "draft-07"] as const)(
  "preserves runtime and provider correlation in the advertised %s schema",
  (target) => {
    for (const contract of FIRMWARE_TOOL_CONTRACTS) {
      const schema = toolInputSchemaWithMetadata(contract)[
        "~standard"
      ].jsonSchema.input({ target });
      const ajv =
        target === "draft-2020-12"
          ? new Ajv2020({ strict: false, validateFormats: false })
          : new Ajv({ strict: false, validateFormats: false });
      expect(ajv.validateSchema(schema)).toBe(true);
      const validate = ajv.compile(schema);
      const input = {
        provider_id: "unblob",
        ...(contract.name === "inspect_firmware_provider"
          ? {}
          : { path: "/tmp/fw.bin" }),
        ...(contract.name === "extract_firmware"
          ? { output_directory: "/tmp/output" }
          : {}),
        runtime,
      };
      for (const sample of [
        input,
        { ...input, runtime: { kind: "native" } },
        { ...input, runtime: { ...runtime, command: "podman" } },
        {
          ...input,
          runtime: { ...runtime, existing_store_profile: "store.json" },
        },
        { ...input, runtime: { ...runtime, image: "unblob:latest" } },
        { ...input, runtime: { ...runtime, args: ["--privileged"] } },
        { ...input, runtime: { ...runtime, kind: "unrecognized" } },
        { ...input, provider_id: "binwalk" },
        { ...input, provider_id: undefined },
      ]) {
        // JSON omission on the wire preserves defaults only in the owning branch.
        const wire: unknown = JSON.parse(JSON.stringify(sample));
        expect(validate(wire), JSON.stringify(validate.errors)).toBe(
          contract.inputSchema.safeParse(wire).success,
        );
      }
    }
  },
);

it("describes configured native Unblob inventory, inspection, and extraction as supported", () => {
  const descriptions = new Map(
    FIRMWARE_TOOL_CONTRACTS.map(({ name, description }) => [name, description]),
  );
  for (const name of [
    "inspect_firmware_provider",
    "inspect_firmware_regions",
    "extract_firmware",
  ] as const) {
    const description = descriptions.get(name);
    expect(description, name).toBeDefined();
    expect(description, name).not.toMatch(
      /planned capabilities only|unavailable: rea refuses|unavailable pending current-head|remains unavailable/iu,
    );
    expect(description, name).toMatch(/user systemd and cgroup v2/iu);
    expect(description, name).toMatch(/exposed when .*configured/iu);
    expect(description, name).toMatch(/acceptance remains unverified/iu);
    expect(description, name).toMatch(/each request.*admission/iu);
    expect(description, name).toMatch(/caller-container.*unavailable/iu);
  }
  expect(descriptions.get("extract_firmware")).toMatch(/64 MiB\/512-inode/iu);
  expect(descriptions.get("extract_firmware")).toMatch(
    /caller-container.*unavailable/iu,
  );
});

it.each(["draft-2020-12", "draft-07"] as const)(
  "seed0x43545231 checks 288 runtime/provider requests against independent admission oracles in %s",
  (target) => {
    let seed = 0x43545231;
    const next = () => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      return seed >>> 0;
    };
    for (const contract of FIRMWARE_TOOL_CONTRACTS) {
      const schema = toolInputSchemaWithMetadata(contract)[
        "~standard"
      ].jsonSchema.input({ target });
      const ajv =
        target === "draft-2020-12"
          ? new Ajv2020({ strict: false, validateFormats: false })
          : new Ajv({ strict: false, validateFormats: false });
      const validate = ajv.compile(schema);
      for (let index = 0; index < 96; index++) {
        const base = {
          provider_id: "unblob",
          ...(contract.name === "inspect_firmware_provider"
            ? {}
            : { path: `/tmp/fw 雪 ${index}.bin` }),
          ...(contract.name === "extract_firmware"
            ? { output_directory: `/tmp/output ${index}` }
            : {}),
        };
        const selection = {
          ...runtime,
          existing_store_profile: `/tmp/profile 雪 ${next()}.json`,
        };
        const variant = next() % 8;
        const sample =
          variant === 0
            ? { ...base, runtime: selection }
            : variant === 1
              ? { ...base, runtime: { ...selection, args: ["--privileged"] } }
              : variant === 2
                ? {
                    ...base,
                    runtime: { ...selection, image: "mutable:latest" },
                  }
                : variant === 3
                  ? { ...base, provider_id: "binwalk", runtime: selection }
                  : variant === 4
                    ? { ...base, provider_id: undefined, runtime: selection }
                    : variant === 5
                      ? {
                          ...base,
                          runtime: { ...selection, command: "podman" },
                        }
                      : variant === 6
                        ? { ...base, runtime: { kind: "native" } }
                        : {
                            ...base,
                            runtime: {
                              ...selection,
                              existing_store_profile: `relative-${index}.json`,
                            },
                          };
        const expected =
          variant === 0 ||
          variant === 6 ||
          (variant === 4 && contract.name === "extract_firmware");
        const wire: unknown = JSON.parse(JSON.stringify(sample));
        expect(
          validate(wire),
          JSON.stringify({
            target,
            name: contract.name,
            index,
            variant,
            errors: validate.errors,
          }),
        ).toBe(expected);
        expect(contract.inputSchema.safeParse(wire).success).toBe(expected);
      }
    }
  },
);
