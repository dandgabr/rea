import { expect, it } from "vitest";
import { firmwareInputSchemas } from "./firmwareAnalysis.js";

const container = {
  kind: "container",
  command: "/usr/bin/podman",
  image: `sha256:${"a".repeat(64)}`,
  existing_store_profile: "/tmp/operator-initialized-store.json",
};
const inputs = {
  inspect_firmware_regions: { provider_id: "unblob", path: "/tmp/fw.bin" },
  extract_firmware: { path: "/tmp/fw.bin", output_directory: "/tmp/output" },
  inspect_firmware_provider: { provider_id: "unblob" },
} as const;

it.each(Object.keys(inputs) as (keyof typeof inputs)[])(
  "%s preserves explicit runtime choices and native omission",
  (operation) => {
    const schema = firmwareInputSchemas[operation];
    const input = inputs[operation];
    expect(schema.parse(input)).not.toHaveProperty("runtime");
    expect(
      schema.parse({ ...input, runtime: { kind: "native" } }),
    ).toMatchObject({
      runtime: { kind: "native" },
    });
    expect(schema.parse({ ...input, runtime: container })).toMatchObject({
      runtime: container,
    });
  },
);

it("requires a complete immutable container selection without raw runtime authority", () => {
  for (const runtime of [
    { ...container, image: "unblob:latest" },
    { ...container, command: "podman" },
    { ...container, existing_store_profile: "store.json" },
    { ...container, image: "sha256:" + "a".repeat(63) },
    { ...container, image: "repository\0@sha256:" + "a".repeat(64) },
    { ...container, args: ["--privileged"] },
    { ...container, mounts: ["/:/host"] },
    { ...container, environment: { CONTAINERS_CONF: "/human.conf" } },
    { kind: "container", command: container.command, image: container.image },
    { kind: "native", image: container.image },
  ]) {
    expect(
      firmwareInputSchemas.extract_firmware.safeParse({
        ...inputs.extract_firmware,
        runtime,
      }).success,
    ).toBe(false);
  }
  const image = `registry.example.test/tools/unblob@sha256:${"b".repeat(64)}`;
  expect(
    firmwareInputSchemas.inspect_firmware_provider.parse({
      ...inputs.inspect_firmware_provider,
      runtime: { ...container, image },
    }),
  ).toMatchObject({ runtime: { image } });
});

it("keeps container selection correlated to the explicit Unblob inspection branch", () => {
  for (const provider_id of [undefined, "binwalk"])
    expect(
      firmwareInputSchemas.inspect_firmware_regions.safeParse({
        path: "/tmp/fw.bin",
        ...(provider_id === undefined ? {} : { provider_id }),
        runtime: container,
      }).success,
    ).toBe(false);
});
