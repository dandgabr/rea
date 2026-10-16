import {
  firmwareInputSchemas,
  firmwareResultSchemas,
} from "../../domain/firmware/firmwareAnalysis.js";
import type { ToolContract } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";

/** Explicit local firmware observations and extraction, backed by caller-supplied tools. */
export const FIRMWARE_TOOL_CONTRACTS = [
  {
    name: "inspect_firmware_provider",
    ...toolContractMetadata("inspect_firmware_provider"),
    kind: "firmware-provider",
    description:
      "Inspect a caller-supplied Unblob installation for its observed version, external dependency readiness and public handler documentation. Native Unblob inventory is exposed when its absolute command and runtime paths are configured; current-head live CLI/MCP/systemd acceptance remains unverified. Each request performs runtime admission and requires a protected runtime, user systemd and cgroup v2; caller-container execution is unavailable. Startup hooks and installed unblob_v1 entrypoints are audited before Unblob imports, and Pluggy entrypoint loading is disabled. No firmware input or fabricated artifact subject.",
    inputSchema: firmwareInputSchemas.inspect_firmware_provider,
    outputSchema: evidenceResultOf(
      firmwareResultSchemas.inspect_firmware_provider,
    ),
    examples: [
      {
        title: "Inspect the selected Unblob installation",
        input: { provider_id: "unblob" },
      },
    ],
  },
  {
    name: "inspect_firmware_regions",
    ...toolContractMetadata("inspect_firmware_regions"),
    kind: "firmware-provider",
    description:
      "Inspect firmware bytes with caller-supplied Binwalk 3.1.x for signature candidates and reported confidence, or explicitly selected native Unblob for chunks, stat/hash/magic, randomness and processing diagnostics. Native Unblob is exposed when its absolute command and runtime paths are configured; current-head live CLI/MCP/systemd acceptance remains unverified. Each request performs runtime admission and requires a protected runtime, user systemd and cgroup v2; caller-container execution is unavailable. Startup hooks and installed unblob_v1 entrypoints are audited before Unblob imports, and Pluggy entrypoint loading is disabled. The caller runtime source revision remains unverified, so Unblob processing and overall coverage remain unknown/partial. This operation does not publish extracted files or execute target code.",
    inputSchema: firmwareInputSchemas.inspect_firmware_regions,
    outputSchema: evidenceResultOf(
      firmwareResultSchemas.inspect_firmware_regions,
    ),
    examples: [
      {
        title: "Inspect firmware regions",
        input: { path: "/tmp/firmware.bin" },
      },
    ],
  },
  {
    name: "extract_firmware",
    ...toolContractMetadata("extract_firmware"),
    kind: "firmware-provider",
    description:
      "Native Unblob extraction is exposed when absolute REA_UNBLOB_RUNTIME_ROOT and REA_UNBLOB_COMMAND paths are configured; current-head live CLI/MCP/systemd acceptance remains unverified. Each request performs runtime admission and requires a protected runtime, user systemd and cgroup v2; caller-container execution is unavailable. Named options preserve workers, skip policies, randomness, native carvings, intermediate deletion and suffix layout. The producer uses a private 64 MiB/512-inode tmpfs; hash-checked regular files stream into SafeOutputTree before publication, within caller byte/entry ceilings. Startup hooks and installed unblob_v1 entrypoints are audited before imports; Pluggy entrypoint loading is disabled. Processing remains unknown and coverage partial. Returned task facts, derivations, diagnostics and extraction gaps retain their provenance; extracted code is never automatically executed, and decompressed offsets remain unknown and are not original-file addresses.",
    inputSchema: firmwareInputSchemas.extract_firmware,
    outputSchema: evidenceResultOf(firmwareResultSchemas.extract_firmware),
    examples: [
      {
        title: "Extract selected firmware with Unblob",
        input: {
          path: "/tmp/firmware.bin",
          output_directory: "/tmp/firmware-output",
          range: { offset: 64, length: 4096 },
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
