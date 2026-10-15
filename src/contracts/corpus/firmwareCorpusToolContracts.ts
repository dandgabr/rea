import {
  firmwareCorpusInputs,
  firmwareCorpusResultSchema,
  type FirmwareCorpusOperation,
} from "../../domain/corpus/firmwareCorpus.js";
import type { ToolContract, ToolExample } from "../toolContractTypes.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
const connection = {
  endpoint: "http://127.0.0.1:5000",
  profile: "source-54aed90b",
};
const uid = "a".repeat(64) + "_3",
  other = "b".repeat(64) + "_4";
const native = {
  interpreter: "/opt/fact/venv/bin/python",
  checkout: "/opt/FACT_core",
  profile: "source-54aed90b",
};
const contract = <Name extends FirmwareCorpusOperation>(
  name: Name,
  description: string,
  input: ToolExample["input"],
) => ({
  name,
  ...toolContractMetadata(name),
  kind: "corpus-provider" as const,
  description,
  inputSchema: firmwareCorpusInputs[name],
  outputSchema: evidenceResultOf(firmwareCorpusResultSchema),
  examples: [{ title: name.replaceAll("_", " "), input }],
});
/** Named corpus questions; catalog order never selects operation or schema. */
export const FIRMWARE_CORPUS_TOOL_CONTRACTS = [
  contract(
    "inspect_firmware_corpus",
    "Inspect caller-selected literal-loopback FACT REST status and dynamic plugin inventory. Explicit source/release profile is a caller declaration; status does not attest installed version or readiness. External-service Evidence has no local artifact subject.",
    { connection },
  ),
  contract(
    "search_corpus_objects",
    "Search FACT firmware or files with the exact Mongo query, offset and limit; zero limit is unbounded at the producer. Firmware recursive/inverted search is explicit. Returns the requested page, never an exhaustive corpus claim.",
    {
      connection,
      kind: "firmware",
      query: { vendor: "example" },
      offset: 0,
      limit: 10,
    },
  ),
  contract(
    "inspect_corpus_object",
    "Inspect a FACT UID with firmware/file metadata and available analyses. Firmware summaries are explicit; file summaries are unsupported. Corpus virtual paths remain provider-local, never host files or runtime addresses.",
    { connection, kind: "firmware", uid, summary: false },
  ),
  contract(
    "inspect_corpus_analysis",
    "Inspect one explicitly selected dynamic FACT analysis plugin for a UID, preserving the native analysis result and producer metadata. No implicit all-plugin selection.",
    { connection, uid, plugin: "file_type" },
  ),
  contract(
    "inspect_corpus_parent_analysis",
    "Inspect the parent-context included_files resources of FACT file_system_metadata or qemu_exec. Availability depends on the caller's selected plugin installation; virtual paths remain corpus-local.",
    { connection, uid, plugin: "file_system_metadata" },
  ),
  contract(
    "inspect_corpus_comparison",
    "Inspect the native comparison for selected distinct FACT UIDs. Native HTTP202 may contain a completed comparison; status codes alone never establish completion.",
    { connection, uids: [uid, other] },
  ),
  contract(
    "collect_corpus_yara",
    "Explicitly collect a one-shot FACT YARA result (rule names to UIDs). Producer GET consumes it. Identical authority/search reads share first Evidence within this REA process/session; ambiguous delivered reads stay retained, with no automatic second consumption.",
    { connection, search_id: "selected-search-id" },
  ),
  contract(
    "inspect_corpus_statistics",
    "Inspect raw FACT statistics, optionally one supported category. Native dictionaries are source evidence, not response envelopes or proof of complete analysis.",
    { connection, category: "general" },
  ),
  contract(
    "inspect_corpus_gaps",
    "Inspect FACT missing/failed analyses. This non-destructive GET requires the producer's delete privilege; permission failure remains explicit. Empty results do not prove exhaustive analysis.",
    { connection },
  ),
  contract(
    "download_corpus_binary",
    "Download original or explicitly repacked FACT bytes to a fresh absent local output. Original UID/SHA/size must match actual bytes; repacked archives have independent digests, never the root firmware UID. Preserve cleanup/publication uncertainty.",
    { connection, uid, repacked: false, output_path: "/tmp/download.bin" },
  ),
  contract(
    "export_corpus_firmware",
    "This planned FACT native export request is currently unavailable for omitted, native and podman-existing runtimes. REA has no enforceable filesystem, network and device isolation boundary before producer identity or process launch. The schema remains for planning and the provider returns capability-unavailable until that boundary exists.",
    { ...native, uids: [uid], output_directory: "/tmp/fact-export" },
  ),
] as const satisfies readonly ToolContract[];
