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
      "Inspect caller-selected firmware bytes with default Binwalk 3.1.x or explicit Unblob 26.6.x (verified with 3.1.0 and 26.6.4). Binwalk returns signature candidates and reported confidence; Unblob skip-extraction returns chunks, stat/hash/magic, scoped native randomness when measured, and processing diagnostics. No published extraction or automatic target execution. Linux, caller-supplied tool and util-linux prlimit required; 128 MiB input, one outstanding operation per provider and 120-second deadline. Unblob installed trusted plugin entrypoints may execute code and access the network before sandbox setup; native Landlock fallback means isolation is not attested.",
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
      "Extract caller-selected firmware bytes with Unblob 26.6.x (verified with 26.6.4) into an absent output directory. Named options preserve workers, skip policies, randomness, native carvings, intermediate deletion and suffix layout. Returns verified regular-file paths/digests, native task facts, derivations, unknown chunks, extraction diagnostics, explicit extraction_gaps and a continuation_id referencing shared extraction_continuations recovery instructions. Linux, caller-supplied tool, format-specific extractors and util-linux prlimit required. One outstanding operation per provider; extracted code is never automatically executed. Installed trusted plugin entrypoints may execute code and access the network before sandbox setup; native Landlock fallback means isolation is not attested. Select a returned native file with open_binary for Ghidra analysis; decompressed offsets remain unknown and are not original-file addresses.",
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
] as const satisfies readonly ToolContract[];
