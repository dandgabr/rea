import { firmwareResultSchemas } from "../domain/firmware/firmwareAnalysis.js";
import type { FirmwareFileAccess } from "./FirmwareFiles.js";
import type { runFirmwareCommand } from "./FirmwareCommand.js";
import { FIRMWARE_LIMITS } from "./FirmwareRelease.js";

/** Read only the native public documentation emitted into this invocation's staging. */
export const readUnblobDocumentation = (
  files: FirmwareFileAccess,
  path: string,
  signal: AbortSignal,
): Promise<string> => files.readText(path, "inspect_firmware_provider", signal);

/** Native dependency marks are PATH availability observations, not extractor execution tests. */
export const normalizeUnblobInventory = (
  execution: Awaited<ReturnType<typeof runFirmwareCommand>>,
  documentation: string,
  engine: unknown,
) => {
  const lines = execution.stdout.text.split(/\r?\n/u);
  const dependencies: { command: string; reported_installed: boolean }[] = [];
  const unparsed: string[] = [];
  const seen = new Set<string>();
  const header =
    "The following executables found installed, which are needed by unblob:";
  const headerValid = lines.shift() === header;
  for (const line of lines) {
    if (line === "") continue;
    const parsed = /^ {4}(.+?) {4,}([✓✗])$/u.exec(line);
    if (parsed?.[1] === undefined || seen.has(parsed[1])) {
      unparsed.push(line);
      continue;
    }
    seen.add(parsed[1]);
    dependencies.push({
      command: parsed[1],
      reported_installed: parsed[2] === "✓",
    });
  }
  const agrees = dependencies.some((row) => !row.reported_installed)
    ? execution.exit_code === 1
    : execution.exit_code === 0;
  const complete =
    headerValid && dependencies.length > 0 && unparsed.length === 0 && agrees;
  const formats: { name: string; type: string; fully_supported: boolean }[] =
    [];
  const unparsedFormats: string[] = [];
  const formatSeen = new Set<string>();
  const documentationLines = documentation.split(/\r?\n/u);
  const tableHeaderValid =
    documentationLines[0] === '??? example "All supported formats"' &&
    /^    \| Format\s*\| Type\s*\| Fully supported\?\s*\|$/u.test(
      documentationLines[1] ?? "",
    ) &&
    /^    \| :[-]+\s*\| :[-]+\s*\| :[-]+:\s*\|$/u.test(
      documentationLines[2] ?? "",
    );
  for (const line of documentationLines.slice(3)) {
    if (line === "") break;
    const parsed =
      /^    \| \[\x60(.+?)\x60\]\(#[^)]*\) \| ([A-Z_]+) \| :(octicons-check-16|octicons-alert-fill-12): \|$/u.exec(
        line,
      );
    if (
      parsed?.[1] === undefined ||
      parsed[2] === undefined ||
      formatSeen.has(parsed[1])
    ) {
      unparsedFormats.push(line);
      continue;
    }
    formatSeen.add(parsed[1]);
    formats.push({
      name: parsed[1],
      type: parsed[2],
      fully_supported: parsed[3] === "octicons-check-16",
    });
  }
  return firmwareResultSchemas.inspect_firmware_provider.parse({
    provider_id: "unblob",
    engine,
    dependencies,
    dependency_readiness: complete
      ? dependencies.some((row) => !row.reported_installed)
        ? "reported_missing"
        : "reported_installed"
      : "unknown",
    dependency_inventory_coverage: complete ? "native_reported" : "partial",
    unparsed_dependency_lines: [
      ...(headerValid ? [] : [execution.stdout.text.split(/\r?\n/u)[0] ?? ""]),
      ...unparsed,
    ],
    formats,
    format_inventory_coverage:
      tableHeaderValid && formats.length > 0 && unparsedFormats.length === 0
        ? "documented_public_handlers"
        : "partial",
    unparsed_format_lines: [
      ...(tableHeaderValid || documentation === ""
        ? []
        : documentationLines.slice(0, 3)),
      ...unparsedFormats,
    ],
    installed_plugin_inventory: "unknown",
    runtime: {
      mode: "native",
      platform: process.platform,
      per_process_address_space_bytes: FIRMWARE_LIMITS.addressSpaceBytes,
      per_process_cpu_seconds: 120,
      core_bytes: 0,
      deadline_ms: FIRMWARE_LIMITS.timeoutMs,
      sandbox_isolation: "not_attested",
      dependency_probe: "native_shutil_which",
      format_scope:
        "Only handler DOC entries that the native CLI marks public; this is not a complete installed-handler inventory",
    },
  });
};
