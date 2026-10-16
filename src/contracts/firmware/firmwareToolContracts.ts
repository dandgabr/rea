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
      "Inspect signature candidates with default Binwalk 3.1.x (verified with 3.1.0), or explicitly select Binwalk-NG 4.0.0 with provider_id binwalk-ng and the pinned runtime manifest. On Linux, NG requires bubblewrap, prlimit and systemd-run with verified user-systemd cgroup v2 limits; it fails closed when those boundaries are unavailable. Returns offsets, reported lengths, descriptions and raw confidence values. Length validation and runtime addresses remain unknown. No extracted-code or target execution.",
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
      "Extract caller-selected firmware bytes with default Unblob 26.6.x (verified with 26.6.4) or explicitly select Binwalk-NG 4.0.0 with provider_id binwalk-ng. NG external-helper extraction requires a pinned helper manifest binding exact helper names, paths, SHA-256 values, version identities and supported signatures; bounded recursion runs under the same verified systemd, bubblewrap and workspace limits as scanning. Unconfigured helpers have no host PATH fallback. Returns verified child paths/digests, task derivations, unknown chunks and extraction diagnostics; Unblob also reports extraction_gaps for unextracted regions, missing dependencies and continuation IDs. Preserves the default sandbox and publishes regular files only. No device acquisition or extracted-code execution. Select a returned native file with open_binary for Ghidra analysis; decompressed offsets are not original-file addresses.",
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
      "Carve known and unknown native regions with explicitly selected Binwalk-NG 4.0.0 (provider_id binwalk-ng) into a fresh directory using internal carving. Return independently verified bytes/digests and current byte correspondence; unknown original ranges stay null. Linux, a pinned runtime manifest, bubblewrap, prlimit and verified user-systemd cgroup v2 limits are required. Extracted code is never executed.",
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
      "Measure Binwalk-NG 4.0.0 Shannon entropy in bits per byte with exact byte windows using provider_id binwalk-ng. Always create a private native PNG; optionally publish it into a fresh output directory. Header dimensions and digest are verified; no encryption or compression interpretation. Requires an entropy-plot build and the same pinned runtime, bubblewrap, prlimit and verified systemd limits as other NG operations.",
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
      "Inspect the explicitly selected Binwalk-NG 4.0.0 native format/extractor inventory (provider_id binwalk-ng) and runtime fingerprints under its actual bubblewrap policy. Returns corpus Evidence with no firmware subject. Reported extractors do not establish dependency availability, and format inventory does not probe entropy-plot readiness or attest source revision.",
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
