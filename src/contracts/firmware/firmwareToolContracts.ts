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
      "Inspect a caller-supplied Unblob installation for its observed version, external dependency readiness and public handler documentation. Native execution requires an absolute REA_UNBLOB_RUNTIME_ROOT and REA_UNBLOB_COMMAND inside it, user systemd and cgroup v2; installed unblob_v1 entrypoints run only after the service boundary is verified. The installed plugin set remains unknown. Caller-container execution is unavailable. No firmware input or fabricated artifact subject.",
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
      "Inspect firmware bytes with caller-supplied Binwalk 3.1.x for signature candidates and reported confidence, or explicitly selected native Unblob for chunks, stat/hash/magic, randomness and processing diagnostics. Unblob requires an absolute REA_UNBLOB_RUNTIME_ROOT with REA_UNBLOB_COMMAND inside it, user systemd and cgroup v2; installed unblob_v1 entrypoints run only after the service boundary is verified. REA cannot attest the installed plugin set, so Unblob processing and overall coverage remain unknown/partial. Caller-container Unblob is unavailable. This operation does not publish extracted files or execute target code.",
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
      "Extract caller-selected firmware bytes with Unblob 26.6.x (verified with 26.6.4) into an absent output directory using an admitted user systemd and cgroup v2 service. Named options preserve workers, skip policies, randomness, native carvings, intermediate deletion and suffix layout. The producer uses a private 64 MiB/512-inode tmpfs; hash-checked regular files stream into SafeOutputTree before publication, within caller-selected byte/entry ceilings. Returns native task facts, derivations, extraction diagnostics, explicit extraction gaps and continuation references. Configure an absolute REA_UNBLOB_RUNTIME_ROOT and REA_UNBLOB_COMMAND inside it. Caller-container execution is unavailable; installed entrypoints are caller-provided and not attested, so per-task processing and coverage remain partial. Extracted code is never automatically executed; decompressed offsets remain unknown and are not original-file addresses.",
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
