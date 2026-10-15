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
    name: "inspect_firmware_regions",
    ...toolContractMetadata("inspect_firmware_regions"),
    kind: "firmware-provider",
    description:
      "Inspect signature candidates with default Binwalk 3.1.x (verified with 3.1.0), or explicit provider_id binwalk-ng 4.0.0 with selected byte range and scan options. Returns offsets, reported lengths, descriptions and raw confidence values. Length validation and runtime addresses remain unknown. No extraction or target execution. Linux, caller-supplied tool and util-linux prlimit required; 128 MiB input limit, default one worker and 120-second deadline; ng requires the explicit minimal bubblewrap runtime manifest.",
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
      "Extract caller-selected firmware bytes with default Unblob 26.6.x (verified with 26.6.4) into an absent output directory. Binwalk-NG extraction is unavailable until its signature-selected external helpers and exact helper-path identities are admitted; REA refuses that provider before reading the target or launching upstream code. Returns verified child paths/digests, task derivations, unknown chunks, extraction diagnostics and explicit Unblob extraction_gaps naming unextracted regions, missing extractor dependencies and continuation IDs for shared recovery. Preserves the default sandbox; publishes regular files only. Linux, caller-supplied default tool, format-specific extractors and util-linux prlimit required. No device acquisition or extracted-code execution. Select a returned native file with open_binary for Ghidra analysis; decompressed offsets are not original-file addresses.",
    inputSchema: firmwareInputSchemas.extract_firmware,
    outputSchema: evidenceResultOf(firmwareResultSchemas.extract_firmware),
    examples: [
      {
        title: "Extract selected firmware",
        input: {
          path: "/tmp/firmware.bin",
          output_directory: "/tmp/firmware-output",
          range: { offset: 64, length: 4096 },
        },
      },
    ],
  },
  {
    name: "carve_firmware",
    ...toolContractMetadata("carve_firmware"),
    kind: "firmware-provider",
    description:
      "Carve known and unknown native regions with explicitly selected binwalk-ng 4.0.0 into a fresh directory. Return independently verified bytes/digests and current byte correspondence; unknown original ranges stay null. Linux, caller-supplied minimal bubblewrap runtime and prlimit required. Extracted code is never executed.",
    inputSchema: firmwareInputSchemas.carve_firmware,
    outputSchema: evidenceResultOf(firmwareResultSchemas.carve_firmware),
    examples: [
      {
        title: "Carve firmware bytes",
        input: {
          provider_id: "binwalk-ng",
          path: "/tmp/firmware.bin",
          output_directory: "/tmp/carvings",
        },
      },
    ],
  },
  {
    name: "inspect_firmware_entropy",
    ...toolContractMetadata("inspect_firmware_entropy"),
    kind: "firmware-provider",
    description:
      "Measure native binwalk-ng Shannon entropy in bits per byte with exact byte windows. Always create a private native PNG; optionally publish it into a fresh output directory. Header dimensions and digest are verified; no encryption or compression interpretation. Requires an entropy-plot build and the same minimal bubblewrap runtime policy.",
    inputSchema: firmwareInputSchemas.inspect_firmware_entropy,
    outputSchema: evidenceResultOf(
      firmwareResultSchemas.inspect_firmware_entropy,
    ),
    examples: [
      {
        title: "Measure selected firmware entropy",
        input: {
          provider_id: "binwalk-ng",
          path: "/tmp/firmware.bin",
          range: { offset: 64, length: 4096 },
        },
      },
    ],
  },
  {
    name: "inspect_firmware_provider",
    ...toolContractMetadata("inspect_firmware_provider"),
    kind: "firmware-provider",
    description:
      "Inspect the explicitly selected binwalk-ng native format/extractor inventory and runtime fingerprints under its actual bubblewrap policy. Returns corpus Evidence with no firmware subject. Reported extractors do not establish dependency availability, and format inventory does not probe entropy-plot readiness or attest source revision.",
    inputSchema: firmwareInputSchemas.inspect_firmware_provider,
    outputSchema: evidenceResultOf(
      firmwareResultSchemas.inspect_firmware_provider,
    ),
    examples: [
      {
        title: "Inspect binwalk-ng formats",
        input: { provider_id: "binwalk-ng" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
