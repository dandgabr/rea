import {
  mkdtemp,
  writeFile,
  rm,
  readFile,
  lstat,
  open,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ZipWriter, Uint8ArrayWriter, Uint8ArrayReader } from "@zip.js/zip.js";
import { readlinkSync } from "node:fs";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { expect, it, vi } from "vitest";
import { FactNativeProvider } from "./FactNativeProvider.js";
import type { FactNativeIdentity } from "./FactNativeIdentity.js";
import { factHash, factUid } from "./FactProtocol.js";
import {
  firmwareCorpusInputs,
  firmwareCorpusResultSchema,
} from "../../domain/corpus/firmwareCorpus.js";
import { runFirmwareCommand } from "../FirmwareCommand.js";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../../artifacts/SafeOutputTreeCreationFailure.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";

const bytes = Buffer.from("native-boundary-fixture");
const uid = factUid(bytes);
async function archive() {
  const writer = new ZipWriter(new Uint8ArrayWriter(), {
    useWebWorkers: false,
  });
  await writer.add(
    "data.json",
    new Uint8ArrayReader(
      Buffer.from(
        JSON.stringify({
          uid,
          db_revision: "fixture-rev",
          files: [],
          firmware: {
            uid,
            sha256: factHash(bytes),
            size: bytes.length,
            file_name: "fixture.bin",
            files_included: [],
            virtual_file_path: {},
            processed_analysis: {},
            comments: [],
            depth: 0,
          },
        }),
      ),
    ),
  );
  await writer.add(`files/${uid}`, new Uint8ArrayReader(bytes));
  return Buffer.from(await writer.close());
}
const fileIdentity = {
  path: "/fixture",
  sha256: "a".repeat(64),
  size: 1,
  device: "1",
  inode: "1",
  mtime_ns: "1",
  ctime_ns: "1",
};
const identity: FactNativeIdentity = {
  public: {
    namespace: "host",
    interpreter: { selected_path: "/fixture/python", ...fileIdentity },
    checkout: {
      selected_path: "/fixture/checkout",
      resolved_path: "/fixture/checkout",
    },
    sources: {},
    configuration: {
      ...fileIdentity,
      projection: {
        postgres: {
          source: "/fixture/socket",
          effective: "/fixture/socket",
          port: 5432,
          database: "fixture",
          transport: "unix-socket",
        },
        storage_root: "/fixture/storage",
      },
    },
    resource_limiter: { selected_path: "/usr/bin/prlimit", ...fileIdentity },
    critical_source_profile_verified: true,
    remaining_imported_dependencies:
      "caller-trusted; not independently attested",
  },
  credentials: ["private-transport-password"],
  command: "/fixture/python",
  script: "/fixture/checkout/src/firmware_import_export.py",
  limiter: "/usr/bin/prlimit",
};
const execution = (
  stderr: string,
  exit_code = 0,
): Awaited<ReturnType<typeof runFirmwareCommand>> => ({
  stdout: { text: "", bytes: 0, observedBytes: 0 },
  stderr: {
    text: stderr,
    bytes: Buffer.byteLength(stderr),
    observedBytes: Buffer.byteLength(stderr),
  },
  exit_code,
  signal: null,
  command: identity.command,
  args: [],
  resource_limiter: identity.limiter,
});
const observed = (
  result: Awaited<ReturnType<FactNativeProvider["execute"]>>,
) => {
  if (!result.ok) throw result.error;
  expect(result.ok).toBe(true);
  const value = firmwareCorpusResultSchema.parse(result.value.result);
  const data = value.data;
  if (data === null || typeof data !== "object" || Array.isArray(data))
    throw Error("Expected native observation dictionary");
  return { ...value, data };
};
async function fixture(work: (root: string, path: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), "rea-fact-native-test-"));
  const path = join(root, "input.zip");
  await writeFile(path, await archive());
  try {
    await work(root, path);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
const native = {
  interpreter: identity.command,
  checkout: "/fixture/checkout",
  profile: "source-54aed90b" as const,
};

it("preflights every selected archive before any native DB operation", async () =>
  fixture(async (root, path) => {
    const bad = join(root, "bad.zip");
    await writeFile(bad, "malformed");
    const command = vi.fn<typeof runFirmwareCommand>();
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
    });
    try {
      const result = observed(
        await provider.execute(
          "import_corpus_firmware",
          firmwareCorpusInputs.import_corpus_firmware.parse({
            ...native,
            archives: [path, bad],
          }),
        ),
      );
      expect(result.state).toBe("not-delivered");
      expect(command).not.toHaveBeenCalled();
      expect(JSON.stringify(result.data)).toContain(uid);
    } finally {
      await provider.close();
    }
  }));
it("keeps ordered native skips and stops remaining imports after a partial producer exception", async () =>
  fixture(async (_root, path) => {
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockResolvedValueOnce(
        execution(
          `[12:34:56] WARNING Skipping firmware ${uid}. Reason: is already in the DB firmware_import_export.py:129\n`,
        ),
      )
      .mockResolvedValueOnce(
        execution(
          "storage.db_interface_base.DbInterfaceError private-transport-password postgres /var/run/postgresql",
          1,
        ),
      );
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
    });
    try {
      const result = observed(
        await provider.execute(
          "import_corpus_firmware",
          firmwareCorpusInputs.import_corpus_firmware.parse({
            ...native,
            archives: [path, path, path],
          }),
        ),
      );
      expect(result.state).toBe("unknown");
      expect(command).toHaveBeenCalledTimes(2);
      expect(command.mock.calls.map(([call]) => call.args[1])).toEqual([
        "import",
        "import",
      ]);
      for (const [call] of command.mock.calls)
        expect(call.environment).toMatchObject({
          HOME: call.cwd,
          PYTHONNOUSERSITE: "1",
          PYTHONDONTWRITEBYTECODE: "1",
          PGPASSFILE: join(call.cwd, "no-pgpass"),
          PGSERVICEFILE: join(call.cwd, "no-pg-service.conf"),
          PGSYSCONFDIR: call.cwd,
        });
      const raw = JSON.stringify(result.data);
      expect(raw).toContain("skipped-existing");
      expect(raw).toContain("possibly-partial");
      expect(raw).toContain("not_started");
      expect(raw).not.toContain("private-transport-password");
      expect(raw).toContain("postgres /var/run/postgresql");
    } finally {
      await provider.close();
    }
  }));
it("verifies selected exported archive identities and publishes exact ZIP bytes to a fresh output", async () =>
  fixture(async (root) => {
    const zip = await archive();
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockImplementation(async (call) => {
        const output = call.args[call.args.indexOf("-o") + 1]!;
        await writeFile(join(output, `FACT_export_${uid}.zip`), zip);
        return execution("");
      });
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
    });
    try {
      const output = join(root, "published");
      const result = observed(
        await provider.execute(
          "export_corpus_firmware",
          firmwareCorpusInputs.export_corpus_firmware.parse({
            ...native,
            uids: [uid],
            output_directory: output,
          }),
        ),
      );
      expect(result.state).toBe("completed");
      expect(await readFile(join(output, `FACT_export_${uid}.zip`))).toEqual(
        zip,
      );
      const exists = observed(
        await provider.execute(
          "export_corpus_firmware",
          firmwareCorpusInputs.export_corpus_firmware.parse({
            ...native,
            uids: [uid],
            output_directory: output,
          }),
        ),
      );
      expect(exists.state).toBe("not-delivered");
      expect(command).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(result.data)).toContain(factHash(zip));
    } finally {
      await provider.close();
    }
  }));
it("keeps verified facts unknown when the selected default configuration drifts after native execution", async () =>
  fixture(async (root) => {
    const observeIdentity = vi
      .fn()
      .mockResolvedValueOnce(structuredClone(identity))
      .mockResolvedValueOnce(structuredClone(identity))
      .mockResolvedValueOnce({
        ...identity,
        public: {
          ...identity.public,
          configuration: {
            ...identity.public.configuration,
            sha256: "b".repeat(64),
          },
        },
      });
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockImplementation(async (call) => {
        await writeFile(
          join(
            call.args[call.args.indexOf("-o") + 1]!,
            `FACT_export_${uid}.zip`,
          ),
          await archive(),
        );
        return execution("");
      });
    const provider = new FactNativeProvider({ observeIdentity, command });
    try {
      const result = observed(
        await provider.execute(
          "export_corpus_firmware",
          firmwareCorpusInputs.export_corpus_firmware.parse({
            ...native,
            uids: [uid],
            output_directory: join(root, "drift"),
          }),
        ),
      );
      expect(result.state).toBe("unknown");
      expect(JSON.stringify(result.data)).toContain(uid);
      expect(result.diagnostics.join(" ")).toMatch(/identity.*changed|drift/iu);
    } finally {
      await provider.close();
    }
  }));
it("retains the bounded partial command and never interprets repaired UTF-8 as an import acknowledgement", async () =>
  fixture(async (_root, path) => {
    const acknowledgement = `[12:34:56] INFO Successfully imported 1 files and 1 DB entries from `;
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockImplementation(async (call) => {
        const result = execution(
          acknowledgement + call.args[2] + " firmware_import_export.py:129\n",
        );
        return {
          ...result,
          stderr: {
            ...result.stderr,
            utf8Valid: false,
            sha256: "b".repeat(64),
          },
        };
      });
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
    });
    try {
      const result = observed(
        await provider.execute(
          "import_corpus_firmware",
          firmwareCorpusInputs.import_corpus_firmware.parse({
            ...native,
            archives: [path, path],
          }),
        ),
      );
      expect(result.state).toBe("unknown");
      expect(command).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(result.data)).toContain(
        '"stderr_utf8_valid":false',
      );
      expect(JSON.stringify(result.data)).toContain("not_started");
    } finally {
      await provider.close();
    }
  }));
it("redacts actual secrets in failed command observations while preserving cancellation and role/path facts", async () =>
  fixture(async (_root, path) => {
    const command = vi.fn<typeof runFirmwareCommand>().mockRejectedValue(
      new AnalysisCancelledError("import_corpus_firmware", {
        capturedOutput: {
          stdout: "partial-native-ack",
          stderr:
            "role postgres /var/run/postgresql private-transport-password",
          truncated: false,
        },
      }),
    );
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
    });
    try {
      const result = observed(
        await provider.execute(
          "import_corpus_firmware",
          firmwareCorpusInputs.import_corpus_firmware.parse({
            ...native,
            archives: [path, path],
          }),
        ),
      );
      expect(result.state).toBe("unknown");
      expect(command).toHaveBeenCalledTimes(1);
      const retained = JSON.stringify(result);
      expect(retained).toContain("AnalysisCancelledError");
      expect(retained).toContain("partial-native-ack");
      expect(retained).toContain("possibly-partial");
      expect(retained).toContain("role postgres /var/run/postgresql");
      expect(retained).not.toContain("private-transport-password");
    } finally {
      await provider.close();
    }
  }));
it("retains verified exports and an explicit output cleanup owner across publication failure", async () =>
  fixture(async (root) => {
    const output = join(root, "failed-output");
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockImplementation(async (call) => {
        if (call.args[1] === "import")
          return execution(
            `[12:34:56] WARNING Skipping firmware ${uid}. Reason: is already in the DB firmware_import_export.py:129\n`,
          );
        await writeFile(
          join(
            call.args[call.args.indexOf("-o") + 1]!,
            `FACT_export_${uid}.zip`,
          ),
          await archive(),
        );
        return execution("");
      });
    let tree: SafeOutputTree | undefined;
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
      createOutput: async (path) => {
        tree = await SafeOutputTree.create(path);
        vi.spyOn(tree, "commit").mockRejectedValue(
          Error("publication interrupted private-transport-password"),
        );
        vi.spyOn(tree, "rollback").mockRejectedValueOnce(
          Error("bounded cleanup fault"),
        );
        return tree;
      },
    });
    try {
      const result = observed(
        await provider.execute(
          "export_corpus_firmware",
          firmwareCorpusInputs.export_corpus_firmware.parse({
            ...native,
            uids: [uid],
            output_directory: output,
          }),
        ),
      );
      expect(result.state).toBe("unknown");
      expect(JSON.stringify(result.data)).toContain(uid);
      expect(JSON.stringify(result.data)).toContain(
        "uncommitted-cleanup-retained",
      );
      expect(provider.files.pendingResources).toContain(output);
      const next = await provider.execute(
        "import_corpus_firmware",
        firmwareCorpusInputs.import_corpus_firmware.parse({
          ...native,
          archives: [join(root, "input.zip")],
        }),
      );
      expect(next).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisResourceConstraintError",
          resource: "capacity",
        },
      });
      expect(command).toHaveBeenCalledTimes(1);
      expect(
        (await readFile(join(output, `FACT_export_${uid}.zip`))).length,
      ).toBeGreaterThan(0);
      await provider.files.close();
      await expect(lstat(output)).rejects.toMatchObject({ code: "ENOENT" });
      expect(provider.files.pendingResources).toEqual([]);
      const afterCleanup = observed(
        await provider.execute(
          "import_corpus_firmware",
          firmwareCorpusInputs.import_corpus_firmware.parse({
            ...native,
            archives: [join(root, "input.zip")],
          }),
        ),
      );
      expect(afterCleanup.state).toBe("completed");
      expect(command).toHaveBeenCalledTimes(2);
      expect(command.mock.calls.map(([call]) => call.args[1])).toEqual([
        "export",
        "import",
      ]);
      expect(JSON.stringify(result)).not.toContain(
        "private-transport-password",
      );
    } finally {
      await provider.close();
    }
  }));
it("owns an output tree even when publication acquisition fails after creating it", async () =>
  fixture(async (root) => {
    const output = join(root, "failed-acquisition");
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockImplementation(async (call) => {
        await writeFile(
          join(
            call.args[call.args.indexOf("-o") + 1]!,
            `FACT_export_${uid}.zip`,
          ),
          await archive(),
        );
        return execution("");
      });
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
      createOutput: async (path) => {
        const tree = await SafeOutputTree.create(path);
        throw new SafeOutputTreeCreationFailure(
          Error("acquisition fault"),
          tree,
        );
      },
    });
    try {
      const result = observed(
        await provider.execute(
          "export_corpus_firmware",
          firmwareCorpusInputs.export_corpus_firmware.parse({
            ...native,
            uids: [uid],
            output_directory: output,
          }),
        ),
      );
      expect(result.state).toBe("unknown");
      expect(JSON.stringify(result.data)).toContain(uid);
      await expect(lstat(output)).rejects.toMatchObject({ code: "ENOENT" });
      expect(provider.files.pendingResources).toEqual([]);
    } finally {
      await provider.close();
    }
  }));
it("admits only one heavy operation and preserves the first exact native observation", async () =>
  fixture(async (_root, path) => {
    let unblock: (() => void) | undefined;
    const blocked = new Promise<void>((resolve) => {
      unblock = resolve;
    });
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockImplementation(async () => {
        await blocked;
        return execution(
          `[12:34:56] WARNING Skipping firmware ${uid}. Reason: is already in the DB firmware_import_export.py:129\n`,
        );
      });
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
    });
    const input = firmwareCorpusInputs.import_corpus_firmware.parse({
      ...native,
      archives: [path],
    });
    try {
      const first = provider.execute("import_corpus_firmware", input);
      const second = await provider.execute("import_corpus_firmware", input);
      expect(second).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisResourceConstraintError",
          resource: "capacity",
        },
      });
      unblock!();
      expect(observed(await first).state).toBe("completed");
      expect(command).toHaveBeenCalledTimes(1);
    } finally {
      unblock?.();
      await provider.close();
    }
  }));

it("refuses a native-rejected local binary filename before issuing any selected import", async () =>
  fixture(async (root, path) => {
    const forged = await readFile(path);
    const at = forged.indexOf(Buffer.from(`files/${uid}`));
    expect(forged.readUInt32LE(at - 30)).toBe(0x04034b50);
    forged[at + 6] = forged[at + 6] === 48 ? 49 : 48;
    const bad = join(root, "header-contradiction.zip");
    await writeFile(bad, forged);
    const command = vi.fn<typeof runFirmwareCommand>();
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
    });
    try {
      const result = observed(
        await provider.execute(
          "import_corpus_firmware",
          firmwareCorpusInputs.import_corpus_firmware.parse({
            ...native,
            archives: [path, bad],
          }),
        ),
      );
      expect(result.state).toBe("not-delivered");
      expect(command).not.toHaveBeenCalled();
      expect(result.data.native_invocations).toBe(0);
      expect(result.data.database_effects).toBe("not_started");
      expect(result.data.archive_preflight_failure).toMatchObject({
        producer_metadata: { uid },
      });
    } finally {
      await provider.close();
    }
  }));

it("attributes cancellation only to the current delivered import and preserves earlier effects", async () =>
  fixture(async (_root, path) => {
    for (const earlier of ["skip", "write"] as const)
      for (const delivered of [false, true]) {
        const controller = new AbortController();
        let observations = 0;
        const command = vi
          .fn<typeof runFirmwareCommand>()
          .mockImplementation(async (call) => {
            if (command.mock.calls.length === 2) {
              controller.abort();
              throw new AnalysisCancelledError("import_corpus_firmware");
            }
            return execution(
              earlier === "skip"
                ? `WARNING Skipping firmware ${uid}. Reason: is already in the DB firmware_import_export.py:129\n`
                : `INFO Successfully imported 1 files and 1 DB entries from ${call.args[2]} firmware_import_export.py:129\n`,
            );
          });
        const provider = new FactNativeProvider({
          observeIdentity: async () => {
            observations++;
            if (!delivered && observations === 3) controller.abort();
            return structuredClone(identity);
          },
          command,
        });
        try {
          const result = observed(
            await provider.execute(
              "import_corpus_firmware",
              firmwareCorpusInputs.import_corpus_firmware.parse({
                ...native,
                archives: [path, path, path],
              }),
              { signal: controller.signal },
            ),
          );
          expect(command).toHaveBeenCalledTimes(delivered ? 2 : 1);
          expect(result.data.native_invocations).toBe(delivered ? 2 : 1);
          expect(result.data.archives).toMatchObject([
            {
              disposition:
                earlier === "skip"
                  ? "skipped-existing"
                  : "producer-reported-import",
              database_effects:
                earlier === "skip"
                  ? "none-reported"
                  : "producer-reported-write",
            },
            {
              disposition: delivered ? "unknown" : "not_started",
              database_effects: delivered ? "possibly-partial" : "not_started",
            },
            { disposition: "not_started", database_effects: "not_started" },
          ]);
          expect(result.data.database_effects).toBe(
            delivered
              ? "possibly-partial"
              : earlier === "skip"
                ? "none-reported"
                : "producer-reported-write",
          );
        } finally {
          await provider.close();
        }
      }
  }));

it("projects actual durable publication before repeated directory close faults and retains exact caller bytes", async () =>
  fixture(async (root) => {
    const output = join(root, "durable-output"),
      zip = await archive();
    let inCommit = false,
      failedOwner: OwnedFileHandle | undefined,
      faults = 0;
    const originalClose = OwnedFileHandle.prototype.close;
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockImplementation(async (call) => {
        await writeFile(
          join(
            call.args[call.args.indexOf("-o") + 1]!,
            `FACT_export_${uid}.zip`,
          ),
          zip,
        );
        return execution("");
      });
    const close = vi
      .spyOn(OwnedFileHandle.prototype, "close")
      .mockImplementation(async function (this: OwnedFileHandle) {
        if (
          this === failedOwner ||
          (inCommit &&
            this.handle.fd >= 0 &&
            readlinkSync(`/proc/self/fd/${this.handle.fd}`) === output)
        ) {
          failedOwner = this;
          faults++;
          if (faults <= 2) throw Error("postcommit directory close fault");
        }
        return originalClose.call(this);
      });
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
      createOutput: async (path) => {
        const tree = await SafeOutputTree.create(path),
          commit = tree.commit.bind(tree);
        vi.spyOn(tree, "commit").mockImplementation(async () => {
          inCommit = true;
          try {
            await commit();
          } finally {
            inCommit = false;
          }
        });
        return tree;
      },
    });
    try {
      const result = observed(
        await provider.execute(
          "export_corpus_firmware",
          firmwareCorpusInputs.export_corpus_firmware.parse({
            ...native,
            uids: [uid],
            output_directory: output,
          }),
        ),
      );
      expect(faults).toBe(2);
      expect(command).toHaveBeenCalledTimes(1);
      expect(await readFile(join(output, `FACT_export_${uid}.zip`))).toEqual(
        zip,
      );
      expect(result.data.publication).toMatchObject({
        state: "committed-cleanup-uncertain",
        files: [
          {
            path: join(output, `FACT_export_${uid}.zip`),
            sha256: factHash(zip),
            size: zip.length,
          },
        ],
      });
      expect(result.data.archives).toMatchObject([
        {
          publication: "committed",
          archive_sha256: factHash(zip),
          archive_bytes: zip.length,
        },
      ]);
      expect(provider.files.pendingResources).toContain(output);
      await provider.files.close();
      expect(faults).toBe(3);
      expect(provider.files.pendingResources).toEqual([]);
      expect(await readFile(join(output, `FACT_export_${uid}.zip`))).toEqual(
        zip,
      );
      expect(command).toHaveBeenCalledTimes(1);
    } finally {
      close.mockRestore();
      await provider.close();
    }
  }));

it("keeps real precommit fsync refusal unpublished despite prepared verified metadata", async () =>
  fixture(async (root, path) => {
    const output = join(root, "unsynced-output"),
      zip = await archive();
    const handle = await open(path, "r"),
      prototype = Object.getPrototypeOf(handle) as typeof handle;
    await handle.close();
    const originalSync = prototype.sync;
    let syncFaults = 0;
    const sync = vi.spyOn(prototype, "sync").mockImplementation(async function (
      this: typeof handle,
    ) {
      if (this.fd >= 0 && readlinkSync(`/proc/self/fd/${this.fd}`) === output) {
        syncFaults++;
        throw Error("precommit output fsync refusal");
      }
      await originalSync.call(this);
    });
    const command = vi
      .fn<typeof runFirmwareCommand>()
      .mockImplementation(async (call) => {
        await writeFile(
          join(
            call.args[call.args.indexOf("-o") + 1]!,
            `FACT_export_${uid}.zip`,
          ),
          zip,
        );
        return execution("");
      });
    const provider = new FactNativeProvider({
      observeIdentity: async () => structuredClone(identity),
      command,
    });
    try {
      const result = observed(
        await provider.execute(
          "export_corpus_firmware",
          firmwareCorpusInputs.export_corpus_firmware.parse({
            ...native,
            uids: [uid],
            output_directory: output,
          }),
        ),
      );
      expect(syncFaults).toBe(1);
      expect(command).toHaveBeenCalledTimes(1);
      expect(result.data.publication).toMatchObject({ state: "rolled-back" });
      expect(result.data.archives).toMatchObject([
        { publication: "verified-unpublished", archive_sha256: factHash(zip) },
      ]);
      await expect(lstat(output)).rejects.toMatchObject({ code: "ENOENT" });
      expect(provider.files.pendingResources).toEqual([]);
    } finally {
      sync.mockRestore();
      await provider.close();
    }
  }));
