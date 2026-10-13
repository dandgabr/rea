import { readFile, writeFile } from "node:fs/promises";
import { expect, it as test } from "vitest";
import {
  assertFirmwareCleanup,
  firmwareFixture,
} from "../../fixtures/firmware/provider.js";
const it = test.skipIf(process.platform !== "linux");

it.each([false, true])(
  "retains exact dependency/chunk recovery before and after publication: preexisting=%s",
  async (preexisting) => {
    const fixture = await firmwareFixture("dependency");
    await writeFile(fixture.path, Buffer.alloc(100));
    if (preexisting) await writeFile(fixture.output, "existing caller data");
    const outcome = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      range: { offset: 64, length: 20 },
    });
    const partial = outcome.ok ? undefined : outcome.error.partialObservation;
    const result = outcome.ok
      ? outcome.value.normalized_result
      : partial !== undefined &&
          "kind" in partial &&
          partial.kind === "firmware"
        ? partial.result
        : undefined;
    expect(result).toMatchObject({
      extraction_gaps: [
        {
          kind: "missing-extractor-dependency",
          input_path: "$input",
          handler: "gzip",
          provider_id: "gzip-id",
          range: { offset: 0, length: 20 },
          root_file_range: { offset: 64, length: 20 },
          dependencies: ["sasquatch"],
          continuation: expect.stringContaining("REA installs nothing"),
        },
      ],
    });
    expect(outcome.ok).toBe(!preexisting);
    await assertFirmwareCleanup(fixture.launches);
  },
);

it.each([false, true])(
  "retains distinct repeated dependency, chunk and multifile failures through publication: preexisting=%s",
  async (preexisting) => {
    const fixture = await firmwareFixture("recovery-stage-errors");
    await writeFile(fixture.path, Buffer.alloc(100));
    if (preexisting) await writeFile(fixture.output, "existing caller data");
    const outcome = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      range: { offset: 64, length: 20 },
    });
    const partial = outcome.ok ? undefined : outcome.error.partialObservation;
    const result = outcome.ok
      ? outcome.value.normalized_result
      : partial !== undefined &&
          "kind" in partial &&
          partial.kind === "firmware"
        ? partial.result
        : undefined;
    expect(result).toMatchObject({
      extraction_gaps: [
        {
          kind: "extractor-failure",
          input_path: "$input",
          handler: "gzip",
          provider_id: "gzip-id",
          range: { offset: 0, length: 20 },
          root_file_range: { offset: 64, length: 20 },
          dependencies: [],
        },
        {
          kind: "missing-extractor-dependency",
          input_path: "$input",
          handler: null,
          provider_id: null,
          range: null,
          root_file_range: null,
          dependencies: ["jefferson", "sasquatch"],
        },
        {
          kind: "extractor-failure",
          input_path: "$output/rootfs",
          handler: "multipart",
          provider_id: "parts-stage",
          range: null,
          root_file_range: null,
          dependencies: [],
        },
      ],
    });
    expect(JSON.stringify(result)).toContain(
      "multifile failure without output child",
    );
    expect(outcome.ok).toBe(!preexisting);
    if (preexisting) {
      expect(await readFile(fixture.output, "utf8")).toBe(
        "existing caller data",
      );
      expect(result).toMatchObject({ publication_state: "not_committed" });
      expect(result).not.toHaveProperty("files");
    }
    expect(fixture.launches).toHaveLength(2);
    await assertFirmwareCleanup(fixture.launches);
  },
);
