import { mkdir, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { FirmwareLauncher } from "../FirmwareCommand.js";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";
import {
  probeBinwalkNgSandbox,
  runBinwalkNgCommand,
} from "./BinwalkNgCommand.js";
import { hashFirmwareFile } from "../FirmwareFiles.js";

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
    // Without visible padding a longer column is ambiguous; retain it raw.
    const characters = Array.from(line),
      first = characters.slice(0, 35).join(""),
      second = characters.slice(35, 70).join("");
    const description = first.trimEnd(),
      name = second.trimEnd(),
      extractor = characters.slice(70).join("").trim();
    if (
      !first.endsWith("  ") ||
      !second.endsWith("  ") ||
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

/** Actual version/list invocation under the identical selected producer policy, without a file subject. */
export const inspectBinwalkNgRuntime = async (context: {
  root: string;
  runtime: {
    command: string;
    bubblewrap: string;
    limiter: string;
    manifest: string;
  };
  signal: AbortSignal;
  scope: ArtifactResourceScope;
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
    inventory = parseBinwalkNgInventory(observed.stdout.text);
    for (const file of [
      sandbox.command,
      sandbox.bubblewrap,
      sandbox.limiter,
      sandbox.manifest,
      ...sandbox.runtime_mounts.map((mount) => ({
        path: mount.source,
        sha256: mount.sha256,
      })),
    ])
      if (
        (await hashFirmwareFile(
          file.path,
          context.signal,
          context.scope,
          "inspect_firmware_provider",
        )) !== file.sha256
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
