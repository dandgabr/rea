import { FACT_NATIVE_PROVIDER_IDENTITY } from "./FactRelease.js";
import { createReadStream } from "node:fs";
import { mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { setImmediate as yieldTurn } from "node:timers/promises";
import type { FirmwareCorpusPort } from "../../application/corpus/FirmwareCorpusPort.js";
import {
  createAnalysisExecution,
  type ExecutionOptions,
} from "../../application/AnalysisProvider.js";
import {
  firmwareCorpusInputs,
  type FirmwareCorpusOperation,
  type FirmwareCorpusInput,
} from "../../domain/corpus/firmwareCorpus.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  freezeJsonSnapshot,
  freezeOwnedJsonSnapshotSteps,
} from "../../domain/immutableJson.js";
import { ok, err } from "../../domain/result.js";
import { ArtifactAnalysisResources } from "../../process/ArtifactAnalysisResources.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { readLinuxResourceLimits } from "../../process/LinuxResourceLimits.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../../artifacts/SafeOutputTreeCreationFailure.js";
import { runFirmwareCommand } from "../FirmwareCommand.js";
import { inventoryFirmwareOutput } from "../FirmwareFiles.js";
import {
  FactFileResources,
  snapshotFactFile,
  requireFreshFactOutput,
} from "./FactFiles.js";
import { FactJsonParser } from "./FactJsonParser.js";
import {
  observeFactNativeIdentity,
  readFactNativeFile,
  type FactNativeIdentity,
  FactNativeFileCleanupFailure,
} from "./FactNativeIdentity.js";
import { preflightFactArchive, FactArchiveFailure } from "./FactArchive.js";
import { interpretFactImport } from "./FactNativeInterpretation.js";
import {
  FACT_LIMITS,
  factHash,
  factResult,
  factRedactor,
} from "./FactProtocol.js";

type Runtime = Awaited<ReturnType<FactFileResources["runtime"]>>;
type NativeInput =
  | FirmwareCorpusInput<"import_corpus_firmware">
  | FirmwareCorpusInput<"export_corpus_firmware">;

/** Independent local DB/storage authority: no HTTP binding, setup, force, retry or compensation. */
export class FactNativeProvider implements FirmwareCorpusPort {
  readonly files: FactFileResources;
  readonly parser: FactJsonParser;
  private readonly admission = new ArtifactAnalysisResources(
    "fact-core-native",
    "firmware-corpus-native",
    readStableArtifact,
    readLinuxResourceLimits,
    {
      message: "FACT permits one outstanding heavy operation per provider",
      details: { outstanding_operations: 1 },
    },
  );
  constructor(
    readonly dependencies: {
      observeIdentity?: typeof observeFactNativeIdentity;
      command?: typeof runFirmwareCommand;
      files?: FactFileResources;
      parser?: FactJsonParser;
      limiter?: string;
      createOutput?: typeof SafeOutputTree.create;
    } = {},
  ) {
    this.files = dependencies.files ?? new FactFileResources();
    this.parser = dependencies.parser ?? new FactJsonParser();
  }
  async close(): Promise<void> {
    // Never remove staging while its retained producer lifetime is unresolved.
    await this.admission.close();
    const failures: unknown[] = [];
    for (const close of [() => this.parser.close(), () => this.files.close()]) {
      try {
        await close();
      } catch (cause) {
        failures.push(cause);
      }
    }
    if (failures.length)
      throw new AggregateError(
        failures,
        "FACT native cleanup remains unresolved",
      );
  }
  execute<Name extends FirmwareCorpusOperation>(
    operation: Name,
    input: FirmwareCorpusInput<Name>,
    options?: ExecutionOptions,
  ) {
    if (
      operation !== "import_corpus_firmware" &&
      operation !== "export_corpus_firmware"
    )
      return Promise.resolve(
        err(
          new AnalysisCapabilityUnavailableError(
            "fact-core-native",
            operation,
            "This operation requires the independent FACT REST authority",
          ),
        ),
      );
    const selected =
      operation === "import_corpus_firmware"
        ? firmwareCorpusInputs.import_corpus_firmware.parse(input)
        : firmwareCorpusInputs.export_corpus_firmware.parse(input);
    return this.admission.run(
      () => this.executeOwned(operation, selected, options),
      options?.signal,
    );
  }
  private async executeOwned(
    operation: "import_corpus_firmware" | "export_corpus_firmware",
    input: NativeInput,
    options?: ExecutionOptions,
  ) {
    if (
      this.admission.pendingPaths.length ||
      this.files.pendingResources.length ||
      this.parser.pendingResources.length
    )
      return err(
        new AnalysisResourceConstraintError(
          operation,
          "capacity",
          this.admission.pendingPaths.length
            ? "Unverified FACT producer cleanup must be resolved before another heavy operation"
            : this.parser.pendingResources.length
              ? "Retained FACT parser worker cleanup must be resolved before another heavy operation"
              : "Retained FACT file/publication cleanup must be resolved before another heavy operation",
          {
            outstanding_operations: 1,
            producer_ownership_roots: this.admission.pendingPaths.length,
            parser_workers: this.parser.pendingResources.length,
            file_or_publication_resources: this.files.pendingResources.length,
          },
        ),
      );
    const signal = AbortSignal.any([
      options?.signal ?? new AbortController().signal,
      AbortSignal.timeout(FACT_LIMITS.deadlineMs),
    ]);
    const roots: Runtime[] = [];
    const diagnostics: string[] = [];
    const archives: JsonValue[] = [];
    const executions: JsonValue[] = [];
    const data: Record<string, JsonValue> = {
      selected_interpreter: input.interpreter,
      selected_checkout: input.checkout,
      binding_declaration: input.binding_declaration ?? null,
      identity: null,
      archives,
      executions,
      native_invocations: 0,
      database_effects: "not_started",
      publication: null,
      preflight_selection: null,
    };
    let identity: FactNativeIdentity | undefined;
    let launched = false;
    let activeImport: number | undefined;
    let diagnosticBytes = 0;
    let state: "not-delivered" | "completed" | "failed" | "unknown" =
      "not-delivered";
    const secrets = new Set<string>();
    const observe = async () => {
      const observed = await (
        this.dependencies.observeIdentity ?? observeFactNativeIdentity
      )(
        input,
        this.dependencies.limiter ?? "/usr/bin/prlimit",
        signal,
        this.files,
      );
      for (const secret of observed.credentials) secrets.add(secret);
      return observed;
    };
    const assertIdentity = async () => {
      const current = await observe();
      if (
        identity !== undefined &&
        JSON.stringify(current.public) !== JSON.stringify(identity.public)
      ) {
        data.identity_after = current.public;
        throw Error(
          "FACT native selected interpreter/source/default configuration identity changed; attribution is unknown",
        );
      }
    };
    const invoke = async (
      runtime: Runtime,
      args: string[],
      exportRoot?: string,
      importIndex?: number,
    ) => {
      signal.throwIfAborted();
      if (identity === undefined)
        throw Error("FACT native identity is unavailable");
      // Only this admitted invocation may establish possible delivery for its selection.
      activeImport = importIndex;
      launched = true;
      data.native_invocations = Number(data.native_invocations) + 1;
      const result = await (this.dependencies.command ?? runFirmwareCommand)({
        engine: "fact-core-native",
        operation,
        command: identity.command,
        limiter: identity.limiter,
        args,
        cwd: runtime.path,
        environment: {
          PATH: "/usr/bin:/bin",
          LANG: "C.UTF-8",
          TERM: "dumb",
          COLUMNS: "8192",
          NO_COLOR: "1",
          HOME: runtime.path,
          XDG_CONFIG_HOME: join(runtime.path, "config"),
          XDG_CACHE_HOME: join(runtime.path, "cache"),
          PYTHONNOUSERSITE: "1",
          PYTHONDONTWRITEBYTECODE: "1",
          PGPASSFILE: join(runtime.path, "no-pgpass"),
          PGSERVICEFILE: join(runtime.path, "no-pg-service.conf"),
          PGSYSCONFDIR: runtime.path,
        },
        signal,
        ...(exportRoot === undefined
          ? {}
          : {
              outputBudget: {
                root: exportRoot,
                bytes: input.max_output_bytes,
                entries: input.max_output_files,
              },
            }),
        acceptReportedExtractionFailure: true,
        retainCleanup: (supervisor) => {
          // Inputs and output staging remain owned until this exact process has stopped.
          for (const root of roots) {
            this.files.forget(root);
            this.admission.retain(root, supervisor);
          }
        },
      });
      diagnosticBytes += result.stdout.bytes + result.stderr.bytes;
      const execution = {
        command: result.command,
        arguments: [...args],
        resource_limiter: result.resource_limiter,
        exit_code: result.exit_code ?? null,
        signal: result.signal,
        stdout:
          diagnosticBytes > FACT_LIMITS.jsonBytes ? null : result.stdout.text,
        stderr:
          diagnosticBytes > FACT_LIMITS.jsonBytes ? null : result.stderr.text,
        stdout_bytes: result.stdout.bytes,
        stderr_bytes: result.stderr.bytes,
        stdout_observed_bytes: result.stdout.observedBytes,
        stderr_observed_bytes: result.stderr.observedBytes,
        stdout_sha256: result.stdout.sha256 ?? null,
        stderr_sha256: result.stderr.sha256 ?? null,
        stdout_utf8_valid: result.stdout.utf8Valid ?? null,
        stderr_utf8_valid: result.stderr.utf8Valid ?? null,
        aggregate_diagnostic_budget_exceeded:
          diagnosticBytes > FACT_LIMITS.jsonBytes,
      };
      executions.push(execution);
      if (diagnosticBytes > FACT_LIMITS.jsonBytes)
        throw Error(
          "FACT native aggregate retained diagnostics exceed the 8MiB budget; current text omitted and remaining imports not started",
        );
      return result;
    };
    let outputTree: SafeOutputTree | undefined;
    let outputOwner: { path: string; close(): Promise<void> } | undefined;
    const verified: {
      path: string;
      name: string;
      sha256: string;
      size: number;
    }[] = [];
    let durablePublication:
      | {
          output_directory: string;
          files: { path: string; sha256: string; size: number }[];
        }
      | undefined;
    const observePublished = (cleanupUncertain: boolean) => {
      if (outputTree === undefined || !outputTree.published) return;
      // Durability is observed from the actual fsynced tree, never prepared metadata.
      durablePublication ??= {
        output_directory: outputTree.outputRoot,
        files: verified.map((file) => ({
          path: join(outputTree!.outputRoot, file.name),
          sha256: file.sha256,
          size: file.size,
        })),
      };
      data.publication = {
        ...durablePublication,
        state: cleanupUncertain ? "committed-cleanup-uncertain" : "committed",
      };
      for (const item of archives) {
        if (item === null || typeof item !== "object" || Array.isArray(item))
          continue;
        if (
          durablePublication.files.some(
            (file) =>
              file.path === item.output_path &&
              file.sha256 === item.archive_sha256 &&
              file.size === item.archive_bytes,
          )
        )
          item.publication = "committed";
      }
    };

    try {
      signal.throwIfAborted();
      if (process.platform !== "linux")
        throw Error(
          "FACT native interchange requires Linux process/resource ownership primitives",
        );
      if ("output_directory" in input)
        await requireFreshFactOutput(input.output_directory);
      identity = await observe();
      data.identity = identity.public;
      const runtime = await this.files.runtime();
      roots.push(runtime);
      if ("archives" in input) {
        let staged = 0,
          expanded = 0,
          entries = 0,
          metadata = 0;
        const prepared: {
          snapshot: Awaited<ReturnType<typeof snapshotFactFile>>;
          index: number;
          archive: Awaited<ReturnType<typeof preflightFactArchive>>;
        }[] = [];
        for (const [index, path] of input.archives.entries()) {
          const snapshot = await snapshotFactFile(
            path,
            signal,
            this.files,
            Math.min(FACT_LIMITS.rawBytes, input.max_output_bytes - staged),
          );
          roots.push(snapshot.runtime);
          staged += snapshot.bytes.length;
          data.preflight_selection = {
            original_path: path,
            snapshot_path: snapshot.path,
            archive_sha256: snapshot.sha256,
            archive_bytes: snapshot.bytes.length,
          };
          const archive = await preflightFactArchive(
            snapshot.bytes,
            this.parser,
            signal,
            {
              bytes: input.max_output_bytes - expanded,
              entries: input.max_output_files - entries,
              metadataBytes: FACT_LIMITS.jsonBytes - metadata,
              retainCleanup: (owner) => this.files.retain(owner),
            },
          );
          expanded += archive.expanded_bytes;
          entries += archive.members.length + 1;
          metadata += archive.expanded_bytes - archive.binary_bytes;
          archives.push({
            ...archive,
            original_path: path,
            snapshot_path: snapshot.path,
            archive_sha256: snapshot.sha256,
            archive_bytes: snapshot.bytes.length,
            disposition: "not_started",
            database_effects: "not_started",
          });
          prepared.push({ snapshot, index, archive });
          data.preflight_selection = null;
          // Binary bytes remain in the immutable private file; release the readback buffer.
          snapshot.bytes = Buffer.alloc(0);
        }
        data.input_staging_bytes = staged;
        data.preflight_expanded_bytes = expanded;
        await assertIdentity();
        state = "completed";
        for (const { snapshot, index, archive } of prepared) {
          const result = await invoke(
            runtime,
            [identity.script, "import", snapshot.path],
            undefined,
            index,
          );
          const disposition = interpretFactImport(
            {
              ...archive,
              binary_count: archive.members.length,
              path: snapshot.path,
            },
            result.stdout.text + "\n" + result.stderr.text,
            result.stdout.utf8Valid === false ||
              result.stderr.utf8Valid === false
              ? null
              : result.exit_code,
          );
          const item = archives[index];
          if (item !== null && typeof item === "object" && !Array.isArray(item))
            Object.assign(item, disposition);
          if (
            disposition.database_effects !== "none-reported" ||
            data.database_effects === "not_started"
          )
            data.database_effects = disposition.database_effects;
          if (disposition.disposition === "unknown") {
            state = "unknown";
            break;
          }
          if (disposition.disposition === "revision-refused") state = "failed";
          activeImport = undefined;
          await assertIdentity();
        }
      } else {
        const exportRoot = join(runtime.path, "export");
        await mkdir(exportRoot, { mode: 0o700 });
        await assertIdentity();
        const result = await invoke(
          runtime,
          [identity.script, "export", ...input.uids, "-o", exportRoot],
          exportRoot,
        );
        state =
          result.exit_code === 0 &&
          result.stdout.utf8Valid !== false &&
          result.stderr.utf8Valid !== false
            ? "completed"
            : "unknown";
        const selected = new Set(input.uids);
        const expectedNames = new Set(
          [...selected].map((uid) => `FACT_export_${uid}.zip`),
        );
        const inventory = await inventoryFirmwareOutput(
          exportRoot,
          input.max_output_bytes,
          input.max_output_files,
          operation,
          signal,
        );
        if (
          inventory.some(
            (item) =>
              item.kind !== "file" || !expectedNames.has(item.relativePath),
          )
        )
          throw Error(
            "FACT native export emitted an undeclared or nonregular archive",
          );
        // Directory listing and verified descriptors establish actual archive presence.
        const names = await readdir(exportRoot);
        let expanded = 0,
          entries = 0,
          metadata = 0;

        for (const name of names) {
          const path = join(exportRoot, name);
          const file = await readFactNativeFile(
            path,
            input.max_output_bytes,
            signal,
            this.files,
          );
          data.preflight_selection = {
            native_output_path: path,
            selected_uids: [...input.uids],
            archive_sha256: file.identity.sha256,
            archive_bytes: file.bytes.length,
          };
          const archive = await preflightFactArchive(
            file.bytes,
            this.parser,
            signal,
            {
              bytes: input.max_output_bytes - expanded,
              entries: input.max_output_files - entries,
              metadataBytes: FACT_LIMITS.jsonBytes - metadata,
              archiveBytes: input.max_output_bytes,
              retainCleanup: (owner) => this.files.retain(owner),
            },
          );
          if (
            name !== `FACT_export_${archive.uid}.zip` ||
            !selected.has(archive.uid)
          )
            throw Error(
              "FACT native exported archive UID contradicts the selected resource",
            );
          expanded += archive.expanded_bytes;
          entries += archive.members.length + 1;
          metadata += archive.expanded_bytes - archive.binary_bytes;
          archives.push({
            ...archive,
            archive_sha256: file.identity.sha256,
            archive_bytes: file.bytes.length,
            output_path: join(input.output_directory, name),
            publication: "verified-unpublished",
          });
          verified.push({
            path,
            name,
            sha256: file.identity.sha256,
            size: file.bytes.length,
          });
          data.preflight_selection = null;
        }
        if (verified.length !== selected.size) {
          state = "unknown";
          diagnostics.push(
            "Selected native export archives are missing; present verified archives are partial evidence",
          );
        }
        data.selected_uids = [...input.uids];
        data.preflight_expanded_bytes = expanded;
        await assertIdentity();
        if (verified.length) {
          try {
            outputTree = await (
              this.dependencies.createOutput ?? SafeOutputTree.create
            )(input.output_directory);
          } catch (cause) {
            if (cause instanceof SafeOutputTreeCreationFailure)
              outputTree = cause.tree;
            throw cause;
          }
          outputOwner = {
            path: outputTree.outputRoot,
            close: async () => {
              const cleanup = await outputTree!.rollback();
              if (cleanup.status === "incomplete")
                throw Error("FACT native output cleanup remains incomplete");
            },
          };
          this.files.retain(outputOwner);
          for (const file of verified)
            await outputTree.write(
              file.name,
              createReadStream(file.path),
              { sha256: file.sha256, bytes: file.size },
              signal,
            );
          signal.throwIfAborted();
          await outputTree.commit();
          observePublished(false);
          this.files.forget(outputOwner);
          outputOwner = undefined;
        }
      }
    } catch (cause) {
      state = launched ? "unknown" : "not-delivered";
      if (launched && activeImport !== undefined) {
        const active = archives[activeImport];
        if (
          active !== null &&
          typeof active === "object" &&
          !Array.isArray(active) &&
          active.disposition === "not_started"
        ) {
          Object.assign(active, {
            disposition: "unknown",
            database_effects: "possibly-partial",
          });
          data.database_effects = "possibly-partial";
        }
      }
      diagnostics.push(cause instanceof Error ? cause.message : String(cause));
      if (cause instanceof FactArchiveFailure)
        data.archive_preflight_failure = {
          selection: data.preflight_selection ?? null,
          ...cause.partial,
        };
      if (cause instanceof FactNativeFileCleanupFailure)
        data.native_file_cleanup_failure = {
          path: cause.path,
          observed_identity: cause.identity ?? null,
          primary_reason:
            cause.primary instanceof Error ? cause.primary.message : null,
        };
      if (cause instanceof AnalysisError)
        data.failure = {
          tag: cause._tag,
          diagnostics:
            cause.diagnostics === undefined ? null : { ...cause.diagnostics },
          captured_output:
            cause.capturedOutput === undefined
              ? null
              : { ...cause.capturedOutput },
        };
      if (outputTree !== undefined) {
        observePublished(true);
        if (outputOwner === undefined) {
          outputOwner = {
            path: outputTree.outputRoot,
            close: async () => {
              await outputTree!.rollback();
            },
          };
          this.files.retain(outputOwner);
        }
        const cleaned = await this.files.release(outputOwner);
        data.publication ??= {
          output_directory: outputTree.outputRoot,
          state: cleaned.ok ? "rolled-back" : "uncommitted-cleanup-retained",
        };
      }
    }
    for (const root of roots) {
      if (this.admission.pendingPaths.includes(root.path)) continue;
      const cleaned = await this.files.release(root);
      if (!cleaned.ok)
        diagnostics.push(
          "FACT native staging cleanup failed; ownership retained for explicit close",
        );
    }
    const pending = [
      ...this.admission.pendingPaths,
      ...this.files.pendingResources,
      ...this.parser.pendingResources,
    ];
    if (pending.length)
      diagnostics.push(
        `Cleanup remains uncertain for owned resources: ${pending.join(", ")}`,
      );
    data.capture_representation_sha256 = executions.length
      ? factHash(executions.map((item) => JSON.stringify(item)).join("\n"))
      : null;
    // Redact actual private transport secrets once at their owning output boundary.
    for (const secret of secrets) factRedactor(secret).value(data);
    const redactText = (value: string) => {
      for (const secret of secrets) value = factRedactor(secret).text(value);
      return value;
    };
    for (const step of freezeOwnedJsonSnapshotSteps(data)) {
      void step;
      await yieldTurn();
    }
    return ok(
      createAnalysisExecution(
        freezeJsonSnapshot(
          factResult({
            state,
            endpoint: null,
            profile: input.profile,
            http_status: null,
            observed_at: new Date().toISOString(),
            raw_sha256: null,
            coverage: launched ? "producer-response" : "archive-preflight",
            data,
            diagnostics: diagnostics.map(redactText),
          }),
        ),
        FACT_NATIVE_PROVIDER_IDENTITY,
        {
          limitations: [
            "Native authority is independently declared; default configuration identity is not proof of HTTP binding.",
            "Critical native source/config/interpreter identities are observed before and after work; remaining installed dependencies are caller-trusted. Identity checks detect drift and do not prevent races.",
            "Native imports require existing namespace-local admin DB/storage authority and may create configured storage directories. REA never creates DB roles, rewrites config, uses --force, retries or compensates native mutations.",
            "Per-archive import calls preserve caller order under one 120s operation deadline. Exact skips/revision refusals continue; unknown delivery/producer failure stops remaining not_started. Exit 0 does not mean imported, and reported counts do not independently verify DB/storage writes.",
            "Producer address space is limited to 1GiB; native export uses BytesIO. Expanded archive and staging bytes are bounded separately; aggregate retained command diagnostics are capped at 8MiB with at most one additional bounded command capture before rejection. No process-wide OOM prevention claim.",
            "Command stream digests describe actual retained bytes and validity explicitly; capture_representation_sha256 describes serialized command observations before redaction, not a raw protocol byte stream.",
          ],
        },
      ),
    );
  }
}
