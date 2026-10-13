import { mkdtemp, writeFile, rm, readFile, lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ZipWriter, Uint8ArrayWriter, Uint8ArrayReader } from "@zip.js/zip.js";
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
  return firmwareCorpusResultSchema.parse(result.value.result);
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
