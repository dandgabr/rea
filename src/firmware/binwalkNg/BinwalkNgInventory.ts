import { mkdir, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { FirmwareLauncher } from "../FirmwareCommand.js";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { firmwareToolUnavailable } from "../FirmwareCommand.js";
import { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";
import {
  probeBinwalkNgSandbox,
  runBinwalkNgCommand,
} from "./BinwalkNgCommand.js";
import type { FirmwareFileAccess } from "../FirmwareFiles.js";

/** Parse the pinned --list presentation without inventing fields hidden by pipe/color output. */
export const parseBinwalkNgInventory = (text: string) => {
  const formats: {
    name: string;
    description: string;
    extractor: string | null;
    requires_search_all: boolean | null;
  }[] = [];
  const unparsed: string[] = [];
  let signatures: number | undefined, extractable: number | undefined;
  let rows = false;
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.replace(/\u001b\[(?:[0-9]+;)*[0-9]+m/gu, "");
    if (line.trim() === "") continue;
    if (/^Total signatures: [0-9]+$/u.test(line)) {
      signatures = Number(line.slice("Total signatures: ".length));
      rows = false;
      continue;
    }
    if (/^Extractable signatures: [0-9]+$/u.test(line)) {
      extractable = Number(line.slice("Extractable signatures: ".length));
      continue;
    }
    if (/^-+$/u.test(line)) continue;
    if (line.startsWith("Signature Description")) {
      rows = true;
      continue;
    }
    if (!rows) {
      unparsed.push(rawLine);
      continue;
    }
    // Upstream display.rs pads two minimum-width columns to 35 Unicode scalars.
    // A long description overflows before the padded name column. Recover only
    // that source-defined layout and keep any remaining ambiguity unparsed.
    const characters = Array.from(line),
      first = characters.slice(0, 35).join(""),
      second = characters.slice(35, 70).join("");
    let description = first.trimEnd(),
      name = second.trimEnd(),
      extractor = characters.slice(70).join("").trim();
    const fixedWidthValid =
      first.endsWith("  ") &&
      second.endsWith("  ") &&
      description.length > 0 &&
      /^\S+$/u.test(name) &&
      extractor.length > 0;
    if (!fixedWidthValid && !line.includes("\u001b")) {
      const utility = /([^\s]+)$/u.exec(line),
        utilityOffset = utility?.index;
      if (utility !== null && utilityOffset !== undefined) {
        const prefix = Array.from(line.slice(0, utilityOffset)),
          nameField = prefix.slice(-35),
          descriptionField = prefix.slice(0, -35),
          overflowDescription = descriptionField.join("").trimEnd(),
          overflowName = nameField.join("").trim();
        if (
          overflowDescription.length > 35 &&
          nameField.length === 35 &&
          nameField.at(-1)?.trim() === "" &&
          /^\S+$/u.test(overflowName)
        ) {
          description = overflowDescription;
          name = overflowName;
          extractor = utility[1] ?? "";
        }
      }
    }
    if (
      description.length === 0 ||
      !/^\S+$/u.test(name) ||
      extractor.length === 0 ||
      line.includes("\u001b")
    ) {
      unparsed.push(rawLine);
      continue;
    }
    formats.push({
      name,
      description,
      extractor: extractor === "None" ? null : extractor,
      requires_search_all: rawLine.includes("\u001b[33m")
        ? true
        : rawLine.includes("\u001b[32m")
          ? false
          : null,
    });
  }
  if (
    signatures === undefined ||
    extractable === undefined ||
    !Number.isSafeInteger(signatures) ||
    !Number.isSafeInteger(extractable) ||
    extractable > signatures
  )
    throw new AnalysisOutputError(
      "inspect_firmware_provider",
      "Native format inventory has no valid reported totals",
    );
  return {
    formats,
    reported_signature_count: signatures,
    reported_extractable_count: extractable,
    unparsed_lines: unparsed,
    inventory_coverage:
      formats.length === signatures && unparsed.length === 0
        ? ("native_reported" as const)
        : ("partial" as const),
  };
};

interface BinwalkNgHelperCapability {
  readonly name: string;
  readonly expected_version: string;
  readonly supported_signatures: readonly string[];
}

// Pinned Binwalk-NG 4.0.0 has data-dependent preferred extractors that are not
// represented by `--list`. Keep this source-backed exception table explicit.
const dynamicBinwalkNgExtractorSignatures: Readonly<
  Record<string, readonly string[]>
> = {
  "7z": ["xz"],
  sasquatch: ["squashfs"],
  "sasquatch-v4be": ["squashfs"],
  "sasquatch-be": ["squashfs"],
};

/** Require complete source-backed helper dispatch mappings before admission. */
export const validateBinwalkNgHelperBindings = <
  T extends BinwalkNgHelperCapability,
>(
  inventory: ReturnType<typeof parseBinwalkNgInventory>,
  helpers: readonly T[],
): T[] => {
  if (helpers.length > 0 && inventory.inventory_coverage !== "native_reported")
    throw firmwareToolUnavailable(
      "binwalk-ng",
      "extract_firmware",
      "External helpers require a complete native format inventory to prove the full signature dispatch mapping",
    );
  const available = new Map<string, Set<string>>();
  for (const format of inventory.formats) {
    if (format.extractor === null || format.extractor === "Built-in") continue;
    const signatures = available.get(format.extractor) ?? new Set<string>();
    signatures.add(format.name);
    available.set(format.extractor, signatures);
  }
  const configured = new Map<string, T>();
  for (const helper of helpers) {
    if (configured.has(helper.name))
      throw firmwareToolUnavailable(
        "binwalk-ng",
        "extract_firmware",
        `Duplicate admitted helper mapping: ${helper.name}`,
      );
    configured.set(helper.name, helper);
  }
  for (const helper of helpers) {
    const declared = [...helper.supported_signatures].sort();
    const permitted = new Set([
      ...(available.get(helper.name) ?? []),
      ...(dynamicBinwalkNgExtractorSignatures[helper.name] ?? []),
    ]);
    if (
      declared.length === 0 ||
      new Set(declared).size !== declared.length ||
      [...permitted].sort().join("\0") !== declared.join("\0")
    )
      throw firmwareToolUnavailable(
        "binwalk-ng",
        "extract_firmware",
        `Helper ${helper.name} capability list must exactly match the complete native and source-backed signature mapping`,
      );
  }
  return [...helpers];
};

/** Actual version/list invocation under the identical selected producer policy, without a file subject. */
export const inspectBinwalkNgRuntime = async (context: {
  root: string;
  runtime: {
    command: string;
    bubblewrap: string;
    limiter: string;
    systemdRun: string;
    manifest: string;
  };
  signal: AbortSignal;
  scope: ArtifactResourceScope;
  files: FirmwareFileAccess;
  launcher?: FirmwareLauncher;
  retainCleanup(supervisor: ProviderProcessSupervisor): void;
}) => {
  const workRoot = join(context.root, "work"),
    inputPath = join(context.root, "readiness-input");
  await mkdir(workRoot, { mode: 0o700 });
  await writeFile(inputPath, "REA runtime inspection\n", {
    mode: 0o400,
    flag: "wx",
  });
  await chmod(inputPath, 0o400);
  const sandbox = await prepareBinwalkNgSandbox({
    ...context.runtime,
    inputPath,
    workRoot,
    signal: context.signal,
    scope: context.scope,
    files: context.files,
    operation: "inspect_firmware_provider",
  });
  const commandContext = {
    sandbox,
    operation: "inspect_firmware_provider",
    signal: context.signal,
    maxOutputBytes: 256 * 1024 * 1024,
    maxOutputFiles: 10000,
    retainCleanup: context.retainCleanup,
    ...(context.launcher === undefined ? {} : { launcher: context.launcher }),
  };
  const version = await probeBinwalkNgSandbox(commandContext);
  let observed: Awaited<ReturnType<typeof runBinwalkNgCommand>> | undefined;
  let inventory: ReturnType<typeof parseBinwalkNgInventory> | undefined;
  let identity: "unknown" | "changed" = "unknown";
  try {
    observed = await runBinwalkNgCommand(commandContext, ["--list"]);
    if (observed.stdout.invalidUtf8 === true)
      throw new AnalysisOutputError(
        "inspect_firmware_provider",
        "Native format inventory contains invalid UTF-8; retained source bytes cannot be normalized",
      );
    inventory = parseBinwalkNgInventory(observed.stdout.text);
    for (const file of [
      sandbox.command,
      sandbox.bubblewrap,
      sandbox.limiter,
      sandbox.systemdRun,
      sandbox.manifest,
      ...sandbox.runtime_mounts.map((mount) => ({
        path: mount.source,
        sha256: mount.sha256,
      })),
    ])
      if (
        (await context.files.hash(file.path, context.signal)) !== file.sha256
      ) {
        identity = "changed";
        throw new AnalysisOutputError(
          "inspect_firmware_provider",
          "Selected runtime identity changed during native inventory",
        );
      }
    return {
      result: {
        provider_id: "binwalk-ng",
        engine: {
          name: "binwalk-ng",
          version: "4.0.0",
          executable_path: sandbox.command.path,
          executable_sha256: sandbox.command.sha256,
          source_revision: null,
          worker_count: 1,
        },
        ...inventory,
        dependency_readiness: "unknown",
        entropy_readiness: "not_probed",
        runtime: sandbox,
      },
      raw: {
        version_execution: version,
        inventory_execution: observed,
        runtime: sandbox,
      },
    };
  } catch (cause: unknown) {
    const partial = {
      kind: "firmware" as const,
      result: jsonValueSchema.parse({
        provider_id: "binwalk-ng",
        ...inventory,
        inventory_coverage: "partial",
        runtime_identity: identity,
      }),
      provenance: jsonValueSchema.parse({
        raw_result: {
          version_execution: version,
          ...(observed === undefined ? {} : { inventory_execution: observed }),
          runtime: sandbox,
        },
        subject: null,
      }),
    };
    if (cause instanceof AnalysisError) {
      cause.retainPartialObservation(partial);
      throw cause;
    }
    throw new ProviderAdapterError("binwalk-ng", "inspect_firmware_provider", {
      cause,
      partialObservation: partial,
      diagnostics: {
        reason: cause instanceof Error ? cause.message : String(cause),
      },
    });
  }
};
