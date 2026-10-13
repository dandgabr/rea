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
    "upload_corpus_firmware",
    "Upload immutable local firmware bytes and required metadata to FACT with exact plugin selection. Accepted means externally queued, not analyzed. Selected trusted plugins can execute code and permit egress; unpacker is a producer dependency. No automatic retry or external cancellation.",
    {
      connection,
      path: "/tmp/firmware.bin",
      metadata: {
        device_name: "device",
        device_part: "part",
        device_class: "class",
        file_name: "firmware.bin",
        version: "1",
        vendor: "vendor",
      },
      plugins: ["file_type"],
    },
  ),
  contract(
    "reanalyze_corpus_firmware",
    "Queue FACT firmware analysis with exact plugins and separate re_unpack choice. Trusted plugins may execute and permit egress; prior analyses may be replaced. Accepted is external-job delivery, not completion; canceling REA does not cancel that job.",
    { connection, uid, plugins: ["file_type"], re_unpack: false },
  ),
  contract(
    "enqueue_corpus_analysis",
    "Queue one FACT file/plugin analysis with explicit force. Supported by source-54aed90b; release-4.4.1 refuses this route before HTTP. Trusted plugins may execute/egress and force may replace analysis. No retry or job cancellation.",
    { connection, uid, plugin: "file_type", force: false },
  ),
  contract(
    "start_corpus_comparison",
    "Queue comparison of distinct FACT firmware UIDs with explicit redo. External comparison plugins can execute/egress and redo can replace prior comparison data. Acknowledged delivery is distinct from completed comparison.",
    { connection, uids: [uid, other], redo: false },
  ),
  contract(
    "inspect_corpus_comparison",
    "Inspect the native comparison for selected distinct FACT UIDs. Native HTTP202 may contain a completed comparison; status codes alone never establish completion.",
    { connection, uids: [uid, other] },
  ),
  contract(
    "start_corpus_yara",
    "Queue an asynchronous FACT YARA search from raw YARA source text in rule_file and optional UID. Preserve the returned search ID; no automatic polling, retry or server cancellation.",
    { connection, rule_file: "rule test { condition: true }" },
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
    "delete_corpus_firmware",
    "Delete selected FACT firmware through explicit producer delete authority. Shared child UIDs may remain; retain the actual deleted-files report and ambiguous delivery. No compensating deletion or retry.",
    { connection, uid },
  ),
  contract(
    "export_corpus_firmware",
    "Export selected FACT UIDs through the official native CLI/default checkout config into fresh verified ZIP outputs. Interpreter/critical sources/config are fingerprinted; native DB authority is independent of REST. Existing local DB/admin/storage prerequisites are caller-provided; no config rewrite or role setup.",
    { ...native, uids: [uid], output_directory: "/tmp/fact-export" },
  ),
  contract(
    "import_corpus_firmware",
    "Import selected FACT ZIPs through official native CLI/default config after all-input CRC/header/member/UID/graph/resource preflight. Preserve caller order, strict revision, skips and partial writes; DB objects precede files. Exit0 alone is not import, and no force, rollback or retry is performed.",
    { ...native, archives: ["/tmp/FACT_export.zip"] },
  ),
] as const satisfies readonly ToolContract[];
