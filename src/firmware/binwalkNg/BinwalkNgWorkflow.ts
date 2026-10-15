import { lstat, mkdir } from "node:fs/promises";
import { basename, join, posix } from "node:path";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { AnalysisOutputError } from "../../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";
import type { BinwalkNgFileRequest } from "../../domain/firmware/binwalkNgAnalysis.js";
import { jsonValueSchema, type JsonValue } from "../../domain/jsonValue.js";
import type { ProviderProcessSupervisor } from "../../process/ProviderProcess.js";
import {
  hashFirmwareFile,
  inventoryFirmwareOutput,
  snapshotFirmware,
  type FirmwareEntry,
} from "../FirmwareFiles.js";
import {
  readFirmwareCommandReport,
  type FirmwareLauncher,
} from "../FirmwareCommand.js";
import { FIRMWARE_LIMITS } from "../FirmwareRelease.js";
import {
  inspectBinwalkNgPng,
  publishBinwalkNgFiles,
  verifyBinwalkNgCarving,
  type BinwalkNgCarvingObservation,
  type BinwalkNgPublication,
} from "./BinwalkNgArtifacts.js";
import {
  probeBinwalkNgSandbox,
  runBinwalkNgCommand,
} from "./BinwalkNgCommand.js";
import { BINWALK_NG_CGROUP_LIMITS } from "./BinwalkNgSystemdBoundary.js";
import {
  parseBinwalkNgAnalyses,
  parseBinwalkNgEntropy,
} from "./BinwalkNgReports.js";
import { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";

export interface BinwalkNgWorkflowContext {
  readonly request: BinwalkNgFileRequest;
  readonly root: string;
  readonly target: Awaited<ReturnType<typeof snapshotFirmware>>;
  readonly runtime: {
    command: string;
    bubblewrap: string;
    limiter: string;
    systemdRun: string;
    manifest: string;
  };
  readonly signal: AbortSignal;
  readonly scope: ArtifactResourceScope;
  readonly launcher?: FirmwareLauncher;
  retainCleanup(supervisor: ProviderProcessSupervisor): void;
  ownTree(tree: SafeOutputTree): void;
  releaseTree(): void;
}

type Analysis = ReturnType<typeof parseBinwalkNgAnalyses>[number];
interface QueuedFile {
  inputPath: string;
  size: number;
  rootOffset: number | null;
  depth: number;
  parentPath: string | null;
  sha256: string;
}
interface FileLineage {
  analysis_depth: number | null;
  parent_analysis_file: string | null;
  parent_signature_ids: string[];
  runtime_address: null;
  original_file_range: { offset: number; length: number } | null;
  local_range: { offset: number; length: number } | null;
  byte_correspondence: "verified" | "unknown";
  carving_observation: Awaited<ReturnType<typeof verifyBinwalkNgCarving>>;
}

const nativeScanOptions = (options: {
  workers: number;
  search_all: boolean;
  include: string[];
  exclude: string[];
  no_mmap: boolean;
}) => [
  "--threads",
  String(options.workers),
  ...(options.search_all ? ["--search-all"] : []),
  ...(options.include.length > 0
    ? [`--include=${options.include.join(",")}`]
    : []),
  ...(options.exclude.length > 0
    ? [`--exclude=${options.exclude.join(",")}`]
    : []),
  ...(options.no_mmap ? ["--no-mmap"] : []),
];

const extractionOwners = (
  entry: FirmwareEntry,
  analysis: Analysis | undefined,
  nativeOutput: string,
  workRoot: string,
) => {
  if (analysis === undefined) return [];
  return analysis.extractions.filter((extraction) => {
    const directory = extraction.output_directory;
    if (
      posix.normalize(directory) !== directory ||
      !directory.startsWith(`${nativeOutput}/`)
    )
      throw new AnalysisOutputError(
        "extract_firmware",
        `Extraction directory is outside its admitted pass: ${directory}`,
      );
    const host = join(workRoot, directory.slice("/work/".length));
    return entry.path.startsWith(`${host}/`);
  });
};

/** One global deadline and an explicit per-file queue replace unrestricted native matryoshka. */
export const runBinwalkNgWorkflow = async (
  context: BinwalkNgWorkflowContext,
) => {
  const { request, target, signal } = context;
  const workRoot = join(context.root, "work");
  await mkdir(workRoot, { mode: 0o700 });
  await mkdir(join(workRoot, "reports"), { mode: 0o700 });
  const transferRoot = join(workRoot, "transfer");
  await mkdir(transferRoot, { mode: 0o700 });
  const producesArtifacts =
    request.operation === "carve_firmware" ||
    request.operation === "extract_firmware";
  // Scan outputs are report-sized. Producer artifacts use caller limits under
  // independent absolute 512 MiB/10,000-file ceilings and private tmpfs quotas.
  const maxBytes = producesArtifacts
    ? Math.min(
        request.input.max_output_bytes,
        BINWALK_NG_CGROUP_LIMITS.outputBytes - FIRMWARE_LIMITS.reportBytes,
      )
    : Math.min(
        "max_output_bytes" in request.input
          ? request.input.max_output_bytes
          : FIRMWARE_LIMITS.reportBytes,
        FIRMWARE_LIMITS.reportBytes,
      );
  const maxFiles = Math.min(
    producesArtifacts && "max_output_files" in request.input
      ? request.input.max_output_files
      : 2,
    producesArtifacts ? 10_000 : 2,
  );
  // runFirmwareCommand inventories the entire private work root, including
  // reports/artifacts directories, while maxFiles describes producer files.
  // Leave bounded slots for those fixed workspace entries and the entropy PNG.
  const maxStagingEntries = maxFiles + 8;
  const transferFiles = maxStagingEntries + 2;
  const transferEntries = transferFiles + 32;
  const transferBytes = maxBytes + FIRMWARE_LIMITS.reportBytes;
  const analyses: Analysis[] = [];
  const runs: JsonValue[] = [];
  let reportBytes = 0;
  const attempted: {
    file_path: string;
    depth: number;
    sha256: string;
    parent_file: string | null;
    returned: boolean;
  }[] = [];
  const unexamined: { path: string; reason: string; depth: number | null }[] =
    [];
  const lineages = new Map<string, FileLineage>();
  const diagnostics: string[] = [];
  const allArtifactEntries: FirmwareEntry[] = [];
  let totalArtifactBytes = 0;
  let pngObservation:
    | Awaited<ReturnType<typeof inspectBinwalkNgPng>>
    | undefined;
  let entropyObservation: ReturnType<typeof parseBinwalkNgEntropy> | undefined;
  const queue: QueuedFile[] = [
    {
      inputPath: target.inputPath,
      size: target.selection.length,
      rootOffset: target.selection.offset,
      depth: 0,
      parentPath: null,
      sha256: target.selection.sha256,
    },
  ];
  let activeTransferTree: SafeOutputTree | undefined;
  const publication = (
    entries: readonly FirmwareEntry[],
    outputDirectory: string,
    expectedIdentities?: ReadonlyMap<string, string>,
    observePublished?: (publication: BinwalkNgPublication) => void,
  ) =>
    publishBinwalkNgFiles({
      entries,
      outputDirectory,
      signal,
      operation: request.operation,
      scope: context.scope,
      expectedIdentities,
      observePublished,
      ownTree: context.ownTree,
      releaseTree: context.releaseTree,
    });
  const partial = () => ({
    kind: "firmware" as const,
    result: jsonValueSchema.parse({
      provider_id: "binwalk-ng",
      selection: target.selection,
      analyses,
      attempted_files: attempted,
      unexamined_files: unexamined,
      diagnostics,
      coverage: "partial",
      artifact_observations: [...lineages].map(([relative_path, lineage]) => ({
        relative_path,
        ...lineage,
      })),
      ...(pngObservation === undefined ? {} : { png: pngObservation }),
      ...(entropyObservation === undefined
        ? {}
        : { entropy: entropyObservation }),
    }),
    provenance: jsonValueSchema.parse({
      raw_result: runs,
      subject: target.subject,
    }),
  });
  try {
    while (queue.length > 0) {
      signal.throwIfAborted();
      const file = queue.shift();
      if (file === undefined) break;
      const pass = String(runs.length).padStart(4, "0");
      const transferPassRoot = join(transferRoot, pass);
      const transferTree = await SafeOutputTree.create(transferPassRoot);
      activeTransferTree = transferTree;
      const sandbox = await prepareBinwalkNgSandbox({
        ...context.runtime,
        inputPath: file.inputPath,
        workRoot,
        signal,
        scope: context.scope,
        operation: request.operation,
      });
      const reportPath = join(transferPassRoot, "reports", `${pass}.json`);
      const pngPath = join(transferPassRoot, "entropy.png");
      const baseCommandContext = {
        sandbox,
        operation: request.operation,
        signal,
        maxOutputBytes: maxBytes,
        maxOutputFiles: maxStagingEntries,
        retainCleanup: context.retainCleanup,
        ...(context.launcher === undefined
          ? {}
          : { launcher: context.launcher }),
      };
      const versionExecution = await probeBinwalkNgSandbox(baseCommandContext);
      const commandContext = {
        ...baseCommandContext,
        transfer: {
          tree: transferTree,
          paths: [
            `reports/${pass}.json`,
            ...(request.operation === "inspect_firmware_entropy"
              ? ["entropy.png"]
              : []),
            ...(request.operation === "extract_firmware" ||
            request.operation === "carve_firmware"
              ? [`artifacts/${pass}`]
              : []),
          ],
          maxBytes: transferBytes,
          maxFiles: transferFiles,
          maxEntries: transferEntries,
          workspaceBytes: transferBytes,
          workspaceInodes: transferEntries + 4,
        },
      };
      const nativeOutput = `/work/artifacts/${pass}`;
      const producingArtifacts =
        request.operation === "extract_firmware" ||
        request.operation === "carve_firmware";
      const reportedPath = producingArtifacts
        ? `${nativeOutput}/${basename(file.inputPath)}`
        : sandbox.input_path;
      const attempt = {
        file_path: reportedPath,
        depth: file.depth,
        sha256: file.sha256,
        parent_file: file.parentPath,
        returned: false,
      };
      attempted.push(attempt);
      const args = ["--quiet", "--log", `/work/reports/${pass}.json`];
      if (request.operation === "inspect_firmware_entropy")
        args.push("--entropy", "--png", "/work/entropy.png");
      else args.push(...nativeScanOptions(request.input.options));
      if (request.operation === "extract_firmware")
        args.push(
          "--extract",
          ...(request.input.options.carve ? ["--carve"] : []),
        );
      if (request.operation === "carve_firmware") args.push("--carve");
      if (producingArtifacts) args.push("--directory", nativeOutput);
      args.push(sandbox.input_path);
      const execution = await runBinwalkNgCommand(
        {
          ...commandContext,
          reportPath,
          ...(request.operation === "inspect_firmware_entropy"
            ? { pngPath }
            : {}),
        },
        args,
      );
      await transferTree.commit();
      activeTransferTree = undefined;
      const reportStat = await lstat(reportPath).catch((cause: unknown) => {
        if (
          cause instanceof Error &&
          "code" in cause &&
          cause.code === "ENOENT"
        )
          return undefined;
        throw cause;
      });
      if (reportStat !== undefined) {
        if (reportStat.size > FIRMWARE_LIMITS.reportBytes - reportBytes)
          throw new AnalysisOutputError(
            request.operation,
            "Combined native reports exceed the 8 MiB operation report budget",
          );
        reportBytes += reportStat.size;
      }
      const raw = await readFirmwareCommandReport({
        path: reportPath,
        engine: "binwalk-ng",
        operation: request.operation,
        execution,
        signal,
        scope: context.scope,
      });
      runs.push(
        jsonValueSchema.parse({
          report: raw,
          execution,
          version_execution: versionExecution,
          sandbox,
          input: { sha256: file.sha256, size: file.size, depth: file.depth },
        }),
      );
      const engine = {
        name: "binwalk-ng",
        version: "4.0.0",
        executable_path: sandbox.command.path,
        executable_sha256: sandbox.command.sha256,
        source_revision: null,
        worker_count:
          request.operation === "inspect_firmware_entropy"
            ? 1
            : request.input.options.workers,
      };
      if (request.operation === "inspect_firmware_entropy") {
        const entropy = parseBinwalkNgEntropy(raw, {
          path: reportedPath,
          size: file.size,
          rootOffset: file.rootOffset,
        });
        entropyObservation = entropy;
        attempt.returned = true;
        const png = await inspectBinwalkNgPng(
          pngPath,
          context.scope,
          signal,
          request.operation,
          (png) => {
            pngObservation = png;
          },
        );
        pngObservation = png;
        await recheckRuntime(sandbox, signal, request.operation, context.scope);
        if (request.input.output_directory !== undefined) {
          await publication(
            [
              {
                path: pngPath,
                relativePath: "entropy.png",
                size: png.size,
                kind: "file",
                linkTarget: null,
              },
            ],
            request.input.output_directory,
            new Map([["entropy.png", png.sha256]]),
            (output) => {
              const publishedPng = output.files.find(
                (file) =>
                  file.relative_path === "entropy.png" &&
                  file.sha256 === png.sha256 &&
                  file.size === png.size,
              );
              if (publishedPng !== undefined) {
                png.path = publishedPng.path;
                png.publication_state = "published";
              }
            },
          );
        }
        return {
          result: {
            provider_id: "binwalk-ng",
            engine,
            input_size: target.size,
            selection: target.selection,
            entropy,
            png,
            attempted_files: attempted,
          },
          raw: runs,
        };
      }
      let parsed: Analysis[];
      try {
        parsed = parseBinwalkNgAnalyses(
          raw,
          new Map([
            [
              reportedPath,
              {
                size: file.size,
                depth: file.depth,
                rootOffset: file.rootOffset,
              },
            ],
          ]),
        );
      } catch (cause: unknown) {
        if (
          cause instanceof AnalysisError &&
          cause.partialObservation !== undefined
        ) {
          throw new AnalysisOutputError(
            request.operation,
            "Native analysis contains invalid or conflicting records",
            {
              cause,
              partialObservation: {
                ...partial(),
                result: jsonValueSchema.parse({
                  ...(partial().result as Record<string, JsonValue>),
                  failed_pass: cause.partialObservation,
                }),
              },
            },
          );
        }
        throw cause;
      }
      analyses.push(...parsed);
      attempt.returned = parsed.length > 0;
      if (!attempt.returned)
        diagnostics.push(
          `Native report omitted admitted file ${reportedPath}; examination remains unknown`,
        );
      await recheckRuntime(sandbox, signal, request.operation, context.scope);
      if (!producingArtifacts)
        return {
          result: {
            provider_id: "binwalk-ng",
            engine,
            input_size: target.size,
            selection: target.selection,
            analyses,
            attempted_files: attempted,
            diagnostics,
            coverage: attempt.returned
              ? (parsed[0]?.coverage ?? "partial")
              : "partial",
          },
          raw: runs,
        };
      const passArtifactRoot = join(transferPassRoot, "artifacts");
      const entries = await inventoryFirmwareOutput(
        passArtifactRoot,
        maxBytes,
        maxFiles,
        request.operation,
        signal,
      );
      totalArtifactBytes += entries.reduce((sum, entry) => sum + entry.size, 0);
      if (
        totalArtifactBytes > maxBytes ||
        allArtifactEntries.length + entries.length > maxFiles
      )
        throw new AnalysisOutputError(
          request.operation,
          "Combined Binwalk-NG artifacts exceed the requested aggregate byte or file budget",
        );
      allArtifactEntries.push(...entries);
      const passEntries = entries.filter((entry) =>
        entry.relativePath.startsWith(`${pass}/`),
      );
      for (const entry of passEntries) {
        const owners = extractionOwners(
          entry,
          parsed[0],
          nativeOutput,
          transferPassRoot,
        );
        const retainCarving = (carving: BinwalkNgCarvingObservation | null) =>
          lineages.set(entry.relativePath, {
            analysis_depth: file.depth + 1,
            parent_analysis_file: reportedPath,
            parent_signature_ids: owners.map(
              (owner) => owner.provider_local_id,
            ),
            runtime_address: null,
            original_file_range: carving?.original_file_range ?? null,
            local_range: carving?.local_range ?? null,
            byte_correspondence: carving === null ? "unknown" : "verified",
            carving_observation: carving,
          });
        const carving =
          request.operation === "carve_firmware" || request.input.options.carve
            ? await verifyBinwalkNgCarving({
                entry,
                inputPath: file.inputPath,
                inputSize: file.size,
                rootOffset: file.rootOffset,
                scope: context.scope,
                signal,
                operation: request.operation,
                observe: retainCarving,
              })
            : null;
        retainCarving(carving);
        if (
          request.operation !== "extract_firmware" ||
          !request.input.options.recursive
        )
          continue;
        const nextDepth = file.depth + 1;
        const reason =
          entry.kind !== "file"
            ? "nonregular_entry"
            : entry.size === 0
              ? "empty_file"
              : owners.length === 0
                ? "unattributed_output"
                : owners.some((owner) => owner.do_not_recurse)
                  ? "provider_do_not_recurse"
                  : nextDepth >= request.input.max_depth
                    ? "depth_limit"
                    : entry.size > FIRMWARE_LIMITS.inputBytes
                      ? "input_byte_limit"
                      : null;
        if (reason !== null) {
          unexamined.push({
            path: entry.relativePath,
            reason,
            depth: nextDepth,
          });
          continue;
        }
        const childRoot = join(
          context.root,
          "children",
          String(attempted.length + queue.length),
        );
        await mkdir(childRoot, { recursive: true, mode: 0o700 });
        const child = await snapshotFirmware(
          { operation: request.operation, input: { path: entry.path } },
          childRoot,
          signal,
          context.scope,
        );
        queue.push({
          inputPath: child.inputPath,
          size: child.selection.length,
          rootOffset:
            child.selection.sha256 === carving?.sha256
              ? (carving.original_file_range?.offset ?? null)
              : null,
          depth: nextDepth,
          parentPath: reportedPath,
          sha256: child.selection.sha256,
        });
      }
      if (queue.length === 0) {
        for (const entry of allArtifactEntries)
          if (!lineages.has(entry.relativePath)) {
            lineages.set(entry.relativePath, {
              analysis_depth: null,
              parent_analysis_file: null,
              parent_signature_ids: [],
              runtime_address: null,
              original_file_range: null,
              local_range: null,
              byte_correspondence: "unknown",
              carving_observation: null,
            });
            unexamined.push({
              path: entry.relativePath,
              reason: "unattributed_output",
              depth: null,
            });
            diagnostics.push(
              `Final inventory contains unattributed output ${entry.relativePath}; parent and examination remain unknown`,
            );
          }
        const published = await publication(
          allArtifactEntries,
          request.input.output_directory,
        );
        const finalLineage = (entry: {
          relative_path: string;
          sha256?: string;
        }) => {
          const lineage = lineages.get(entry.relative_path);
          if (
            lineage?.byte_correspondence === "verified" &&
            lineage.carving_observation?.sha256 !== entry.sha256
          ) {
            diagnostics.push(
              `Artifact bytes changed after carving comparison: ${entry.relative_path}; prior observation retained, current correspondence unknown`,
            );
            return {
              ...lineage,
              byte_correspondence: "unknown",
              original_file_range: null,
              local_range: null,
            };
          }
          return lineage;
        };
        const finalFiles = published.files.map((entry) => ({
          ...entry,
          ...finalLineage(entry),
        }));
        return {
          result: {
            provider_id: "binwalk-ng",
            engine,
            input_size: target.size,
            selection: target.selection,
            ...published,
            files: finalFiles,
            unpublished_entries: published.unpublished_entries.map((entry) => ({
              ...entry,
              ...finalLineage(entry),
            })),
            analyses,
            attempted_files: attempted,
            unexamined_files: unexamined,
            diagnostics,
            coverage:
              diagnostics.length > 0 ||
              unexamined.length > 0 ||
              analyses.some(
                (analysis) => analysis.coverage !== "signature_scan",
              )
                ? "partial"
                : "signature_scan",
          },
          raw: runs,
        };
      }
    }
    throw new AnalysisOutputError(
      request.operation,
      "No admitted file was analyzed",
    );
  } catch (cause: unknown) {
    if (activeTransferTree !== undefined) {
      const transferTree = activeTransferTree;
      activeTransferTree = undefined;
      try {
        const cleanup = await transferTree.rollback();
        if (cleanup.status === "incomplete")
          throw new Error(
            `Private transfer rollback retained ${cleanup.residualPaths.join(", ")}`,
          );
      } catch (cleanupCause: unknown) {
        throw new ProviderCleanupError(
          "binwalk-ng",
          [transferTree.outputRoot],
          {
            reason: "Private framed-transfer staging could not be rolled back",
            previous_error:
              cause instanceof Error ? cause.message : String(cause),
          },
          { operation: request.operation, cause: cleanupCause },
        );
      }
    }
    if (runs.length > 0) {
      if (
        cause instanceof ProviderCleanupError &&
        cause.partialObservation !== undefined
      ) {
        const retained = cause.partialObservation;
        cause.partialObservation = {
          ...partial(),
          result: jsonValueSchema.parse({
            ...(partial().result as Record<string, JsonValue>),
            retained_observation: retained,
          }),
        };
      } else if (cause instanceof AnalysisError)
        cause.retainPartialObservation(partial());
      else
        throw new ProviderAdapterError("binwalk-ng", request.operation, {
          cause,
          diagnostics: {
            reason: cause instanceof Error ? cause.message : String(cause),
          },
          partialObservation: partial(),
        });
    }
    throw cause;
  }
};

const recheckRuntime = async (
  sandbox: Awaited<ReturnType<typeof prepareBinwalkNgSandbox>>,
  signal: AbortSignal,
  operation: string,
  scope: ArtifactResourceScope,
) => {
  const identities = [
    sandbox.command,
    sandbox.bubblewrap,
    sandbox.limiter,
    sandbox.systemdRun,
    sandbox.manifest,
    ...sandbox.runtime_mounts.map((mount) => ({
      path: mount.source,
      sha256: mount.sha256,
    })),
  ];
  for (const identity of identities)
    if (
      (await hashFirmwareFile(identity.path, signal, scope, operation)) !==
      identity.sha256
    )
      throw new AnalysisOutputError(
        operation,
        `Selected runtime identity changed; producing attribution is unknown: ${identity.path}`,
      );
};
