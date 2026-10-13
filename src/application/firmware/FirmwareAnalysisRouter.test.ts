import { expect, it } from "vitest";
import { FirmwareAnalysisRouter } from "./FirmwareAnalysisRouter.js";
import { firmwareRequestSchema } from "../../domain/firmware/firmwareAnalysis.js";
import { createAnalysisExecution } from "../AnalysisProvider.js";
import { ok } from "../../domain/result.js";

it("routes the validated provider choice and refuses absent registrations", async () => {
  const router = new FirmwareAnalysisRouter({
    unblob: {
      execute: async () =>
        ok(
          createAnalysisExecution(
            { selected: "unblob" },
            { id: "unblob", name: "Unblob", version: "26.6.4" },
          ),
        ),
    },
  });
  const selected = await router.execute(
    firmwareRequestSchema.parse({
      operation: "inspect_firmware_regions",
      input: { provider_id: "unblob", path: "/tmp/fw.bin" },
    }),
  );
  expect(selected.ok && selected.value.result).toEqual({ selected: "unblob" });
  const missing = await router.execute(
    firmwareRequestSchema.parse({
      operation: "inspect_firmware_regions",
      input: { path: "/tmp/fw.bin" },
    }),
  );
  expect(missing.ok).toBe(false);
  if (!missing.ok)
    expect(missing.error).toMatchObject({
      operation: "inspect_firmware_regions",
      providerId: "binwalk",
    });
});
