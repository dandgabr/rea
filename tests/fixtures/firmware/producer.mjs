import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  chmod,
  mkdir,
  readFile,
  readdir,
  readlink,
  truncate,
  writeFile,
  symlink,
} from "node:fs/promises";
import { join } from "node:path";
const args = process.argv.slice(2);
const mode = process.env.REA_FIRMWARE_FIXTURE_MODE;
const engine = process.env.REA_FIRMWARE_FIXTURE_ENGINE;
const banner = process.env.REA_FIRMWARE_FIXTURE_VERSION;
const serializeUnblobReport = (report, input, output) =>
  JSON.stringify(report)
    .replaceAll(input, "/tmp/rea-input")
    .replaceAll(output, "/tmp/rea-extracted");
const emitExtractionFrame = async (reportPath, root) => {
  const entries = [];
  const walk = async (directory, prefix = "") => {
    for (const item of await readdir(directory, { withFileTypes: true })) {
      const relative = prefix === "" ? item.name : `${prefix}/${item.name}`;
      const path = join(directory, item.name);
      if (item.isDirectory()) {
        entries.push({ kind: 0, relative, bytes: Buffer.alloc(0) });
        await walk(path, relative);
      } else if (item.isSymbolicLink()) {
        entries.push({
          kind: 2,
          relative,
          bytes: Buffer.alloc(0),
          target: await readlink(path),
        });
      } else if (item.isFile()) {
        entries.push({ kind: 1, relative, bytes: await readFile(path) });
      } else {
        entries.push({ kind: 3, relative, bytes: Buffer.alloc(0) });
      }
    }
  };
  await walk(root);
  const report = await readFile(reportPath);
  const stdout =
    mode === "frame-invalid-utf8" ? Buffer.from([0xff]) : Buffer.alloc(0);
  const stderr = Buffer.alloc(0);
  const auxiliary = Buffer.from(
    JSON.stringify({
      stdout_observed_bytes: 0,
      stderr_observed_bytes: 0,
      stdout_truncated: false,
      stderr_truncated: false,
    }),
  );
  const totalBytes = entries.reduce(
    (sum, entry) => sum + entry.bytes.length,
    0,
  );
  const header = Buffer.alloc(40);
  Buffer.from("REAUB1\0\0", "ascii").copy(header);
  header.writeInt32BE(process.exitCode ?? 0, 8);
  header.writeUInt32BE(stdout.length, 12);
  header.writeUInt32BE(stderr.length, 16);
  header.writeUInt32BE(report.length, 20);
  header.writeUInt32BE(auxiliary.length, 24);
  header.writeUInt32BE(entries.length, 28);
  header.writeBigUInt64BE(BigInt(totalBytes), 32);
  const frames = entries.map((entry) => {
    const path = Buffer.from(entry.relative, "utf8");
    const target = Buffer.from(entry.target ?? "", "utf8");
    const frame = Buffer.alloc(45);
    frame.writeUInt8(entry.kind, 0);
    frame.writeUInt16BE(path.length, 1);
    frame.writeUInt16BE(target.length, 3);
    frame.writeBigUInt64BE(BigInt(entry.bytes.length), 5);
    createHash("sha256").update(entry.bytes).digest().copy(frame, 13);
    return Buffer.concat([frame, path, target, entry.bytes]);
  });
  process.stdout.write(
    Buffer.concat([header, stdout, stderr, report, auxiliary, ...frames]),
  );
};
const selectedPlugin = args
  .find((arg) => arg.startsWith("--plugins-path="))
  ?.slice("--plugins-path=".length);
if (
  mode === "plugin-bytecode" &&
  selectedPlugin !== undefined &&
  process.env.PYTHONDONTWRITEBYTECODE !== "1"
) {
  await mkdir(join(selectedPlugin, "__pycache__"), { recursive: true });
  await writeFile(
    join(selectedPlugin, "__pycache__", "trusted.pyc"),
    "native import cache",
  );
}
if (args.includes("--version")) {
  if (mode === "version-invalid-utf8") {
    process.stdout.write(Buffer.from([0xff, 0x0a]));
    process.exit(0);
  }
  console.log(
    mode === "version"
      ? "unsupported"
      : banner !== undefined && banner.length > 0
        ? banner
        : engine === "binwalk"
          ? "binwalk 3.1.0"
          : "26.6.4",
  );
} else if (args.includes("--show-external-dependencies")) {
  if (mode === "inventory-plugin-dependency-invalid")
    await writeFile(selectedPlugin, "# changed before invalid dependencies\n");
  if (
    mode === "inventory-invalid-utf8" ||
    mode === "inventory-plugin-dependency-invalid"
  )
    process.stdout.write(Buffer.from([0xff]));
  console.log(
    "The following executables found installed, which are needed by unblob:",
  );
  console.log("    gzip    ✓");
  console.log(
    mode === "inventory-malformed"
      ? "unrecognized dependency row"
      : `    sasquatch    ${mode === "inventory-missing" ? "✗" : "✓"}`,
  );
  if (mode === "inventory-missing") process.exitCode = 1;
} else if (args.includes("--build-handlers-doc")) {
  if (
    mode?.startsWith("inventory-plugin-doc-") === true &&
    mode !== "inventory-plugin-doc-failure"
  ) {
    await writeFile(
      selectedPlugin,
      "# changed before documentation admission\n",
    );
    if (mode === "inventory-plugin-doc-missing") process.exit(0);
    await writeFile(
      args[args.indexOf("--build-handlers-doc") + 1],
      mode === "inventory-plugin-doc-invalid"
        ? Buffer.from([0xff])
        : Buffer.alloc(8 * 1024 * 1024 + 1, 0x61),
    );
    process.exit(0);
  }
  if (
    mode === "inventory-doc-failure" ||
    mode === "inventory-plugin-doc-failure"
  ) {
    if (mode === "inventory-plugin-doc-failure")
      await writeFile(
        selectedPlugin,
        "# changed before failed documentation\n",
      );
    console.error(
      "Documentation generation failed after dependency inspection",
    );
    process.exit(2);
  }
  if (mode === "inventory-plugin-drift")
    await writeFile(
      args
        .find((arg) => arg.startsWith("--plugins-path="))
        ?.slice("--plugins-path=".length),
      "# changed by trusted inventory plugin\n",
    );
  await writeFile(
    args[args.indexOf("--build-handlers-doc") + 1],
    '??? example "All supported formats"\n    | Format | Type | Fully supported? |\n    | :--- | :--- | :---: |\n    | [`GZIP`](#gzip) | COMPRESSION | :octicons-check-16: |\n\n## GZIP\n',
  );
} else if (mode === "stall") {
  console.log("native output before cancellation");
  await writeFile(join(process.cwd(), "ready"), "ready");
  setInterval(() => {}, 1000);
} else if (mode === "startup") {
  console.error("Landlock sandbox is not available on this fixture host");
  process.exitCode = 1;
} else if (mode === "missing-report") {
  console.error("Producer forgot its report");
} else {
  const input = args.at(-1);
  const bytes = await readFile(input);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const reportPath =
    args[args.indexOf(engine === "binwalk" ? "--log" : "--report") + 1];
  if (engine === "binwalk") {
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          Analysis: {
            file_path: mode === "wrong-input" ? "/tmp/another.bin" : input,
            file_map: [
              {
                id: "hit",
                offset: mode === "outside-selection" ? 25 : 2,
                size: mode === "bounds" ? bytes.length : 4,
                name: "gzip",
                confidence: 250,
                description: "fixture signature",
                always_display: false,
                extraction_declined: false,
              },
            ],
            extractions: {},
          },
        },
      ]),
    );
  } else if (args.includes("--skip-extraction")) {
    const recognized = mode !== "unrecognized";
    await mkdir(args[args.indexOf("--extract-dir") + 1], { recursive: true });
    const reports = [
      {
        __typename__: "StatReport",
        path: input,
        size: bytes.length,
        is_file: true,
        is_dir: false,
        is_link: false,
        link_target: null,
      },
      {
        __typename__: "FileMagicReport",
        magic: "data",
        mime_type: "application/octet-stream",
      },
      {
        __typename__: "HashReport",
        sha256: mode === "wrong-hash" ? "a".repeat(64) : sha256,
      },
    ];
    if (recognized)
      reports.push({
        __typename__: "ChunkReport",
        id: "gzip-id",
        start_offset: 0,
        end_offset: bytes.length,
        size: bytes.length,
        handler_name: "gzip",
        is_encrypted: false,
        extraction_reports: [],
      });
    if (!recognized && Number(args[args.indexOf("--randomness-depth") + 1]) > 0)
      reports.push({
        __typename__: "RandomnessReport",
        shannon: { block_size: 1024, percentages: [0], mean: 0 },
        chi_square: { block_size: 1024, percentages: [0], mean: 0 },
      });
    if (mode === "custom-report")
      reports.push({
        __typename__: "TrustedFirmwareReport",
        sensitive_password: "firmware-password-observation",
      });
    if (mode === "plugin-drift")
      await writeFile(
        args
          .find((arg) => arg.startsWith("--plugins-path="))
          ?.slice("--plugins-path=".length),
        "# changed after import\n",
      );
    await writeFile(
      reportPath,
      serializeUnblobReport(
        [
          {
            task: { path: input, depth: 0, blob_id: "", is_multi_file: false },
            reports,
            subtasks: [],
          },
        ],
        input,
        args[args.indexOf("--extract-dir") + 1],
      ),
    );
  } else {
    const deleted = mode === "deleted" || mode === "deleted-and-missing";
    const observationFacts = mode?.startsWith("observation-facts") === true;
    const output = args[args.indexOf("--extract-dir") + 1];
    await mkdir(output, { recursive: true });
    const child =
      mode === "reserved-name"
        ? join(output, "$input")
        : join(output, "rootfs", "config");
    await mkdir(join(output, "rootfs"));
    const content = Buffer.from("firmware=true\n");
    if (
      mode !== "missing-file" &&
      mode !== "depth-reentry" &&
      mode !== "depth-orphan" &&
      mode !== "observation-facts-missing" &&
      !deleted
    )
      await writeFile(child, mode === "budget" ? Buffer.alloc(10000) : content);
    if (mode === "link") await symlink("/etc/passwd", join(output, "escape"));
    const childHash = createHash("sha256").update(content).digest("hex");
    const depth =
      mode === "depth" || mode === "depth-reentry" || mode === "depth-orphan"
        ? Number(args[args.indexOf("--depth") + 1])
        : 1;
    const stat = (path, size, isDir = false) => ({
      __typename__: "StatReport",
      path,
      size,
      is_file: !isDir,
      is_dir: isDir,
      is_link: false,
      link_target: null,
    });
    const task = (path, level, id) => ({
      path,
      depth: level,
      blob_id: id,
      is_multi_file: false,
    });
    const hash = (value) => ({ __typename__: "HashReport", sha256: value });
    const childTask = task(child, depth, "gzip-id");
    if (mode === "nested-unknown") {
      const nestedUnknownRecords = [
        {
          task: childTask,
          reports: [
            stat(child, content.length),
            hash(childHash),
            {
              __typename__: "UnknownChunkReport",
              id: "unknown-id",
              start_offset: 0,
              end_offset: content.length,
              size: content.length,
              randomness: null,
            },
          ],
          subtasks: [],
        },
        {
          task: task(input, 0, ""),
          reports: [
            stat(input, bytes.length),
            hash(sha256),
            {
              __typename__: "ChunkReport",
              id: "gzip-id",
              start_offset: 0,
              end_offset: bytes.length,
              size: bytes.length,
              handler_name: "gzip",
              is_encrypted: false,
              extraction_reports: [],
            },
          ],
          subtasks: [childTask],
        },
      ];
      await writeFile(
        reportPath,
        serializeUnblobReport(nestedUnknownRecords, input, output),
      );
    }
    if (mode === "nested-unknown-oversized") {
      // The child exceeds the firmware input limit, so a fresh run cannot
      // accept it even though the unknown chunk's range is small.
      // The test lowers the input ceiling to keep this case below the
      // isolation stream's independent 64 MiB output ceiling.
      const oversized = 32;
      await truncate(child, oversized);
      const oversizedDigest = createHash("sha256");
      for await (const chunk of createReadStream(child))
        oversizedDigest.update(chunk);
      const oversizedHash = oversizedDigest.digest("hex");
      const nestedUnknownRecords = [
        {
          task: childTask,
          reports: [
            stat(child, oversized),
            hash(oversizedHash),
            {
              __typename__: "UnknownChunkReport",
              id: "unknown-id",
              start_offset: 0,
              end_offset: content.length,
              size: content.length,
              randomness: null,
            },
          ],
          subtasks: [],
        },
        {
          task: task(input, 0, ""),
          reports: [
            stat(input, bytes.length),
            hash(sha256),
            {
              __typename__: "ChunkReport",
              id: "gzip-id",
              start_offset: 0,
              end_offset: bytes.length,
              size: bytes.length,
              handler_name: "gzip",
              is_encrypted: false,
              extraction_reports: [],
            },
          ],
          subtasks: [childTask],
        },
      ];
      await writeFile(
        reportPath,
        serializeUnblobReport(nestedUnknownRecords, input, output),
      );
    }
    if (mode === "depth-orphan") {
      // A depth-limited directory with nothing published under it cannot
      // re-root a fresh run.
      const mid = join(output, "rootfs", "config");
      await mkdir(mid, { recursive: true });
      const midTask = task(mid, depth, "gzip-id");
      const orphanRecords = [
        {
          task: midTask,
          reports: [stat(mid, 0, true)],
          subtasks: [],
        },
        {
          task: task(input, 0, ""),
          reports: [
            stat(input, bytes.length),
            hash(sha256),
            {
              __typename__: "ChunkReport",
              id: "gzip-id",
              start_offset: 0,
              end_offset: bytes.length,
              size: bytes.length,
              handler_name: "gzip",
              is_encrypted: false,
              extraction_reports: [],
            },
          ],
          subtasks: [midTask],
        },
      ];
      await writeFile(
        reportPath,
        serializeUnblobReport(orphanRecords, input, output),
      );
    }
    if (mode === "depth-reentry") {
      // A depth-limited directory with two published children that can each
      // re-root a fresh run, proving neither target is lost during indexing.
      const mid = join(output, "rootfs", "config");
      const innerPath = join(mid, "inner.gz");
      const secondPath = join(mid, "second.gz");
      await mkdir(mid, { recursive: true });
      await writeFile(innerPath, content);
      await writeFile(secondPath, content);
      const innerTask = task(innerPath, depth + 1, "inner-id");
      const secondTask = task(secondPath, depth + 1, "second-id");
      const midTask = {
        ...task(mid, depth, "gzip-id"),
        is_multi_file: true,
      };
      const depthReentryRecords = [
        {
          task: innerTask,
          reports: [stat(innerPath, content.length), hash(childHash)],
          subtasks: [],
        },
        {
          task: secondTask,
          reports: [stat(secondPath, content.length), hash(childHash)],
          subtasks: [],
        },
        {
          task: midTask,
          reports: [
            stat(mid, 0, true),
            {
              __typename__: "MultiFileReport",
              id: "gzip-id",
              handler_name: "gzip",
              name: "config",
              paths: [innerPath, secondPath],
              extraction_reports: [],
            },
          ],
          subtasks: [innerTask, secondTask],
        },
        {
          task: task(input, 0, ""),
          reports: [
            stat(input, bytes.length),
            hash(sha256),
            {
              __typename__: "ChunkReport",
              id: "gzip-id",
              start_offset: 0,
              end_offset: bytes.length,
              size: bytes.length,
              handler_name: "gzip",
              is_encrypted: false,
              extraction_reports: [],
            },
          ],
          subtasks: [midTask],
        },
      ];
      await writeFile(
        reportPath,
        serializeUnblobReport(depthReentryRecords, input, output),
      );
      process.exitCode = 0;
    }
    const records = [
      {
        task: childTask,
        reports: [
          stat(child, content.length),
          ...(mode === "depth"
            ? []
            : [hash(mode === "hash" ? "a".repeat(64) : childHash)]),
          ...(deleted
            ? [
                {
                  __typename__: "ExtractedFileDeletedReport",
                  path: child,
                  handler_name: "gzip",
                },
              ]
            : []),
        ],
        subtasks: [],
      },
      {
        task: task(input, 0, ""),
        reports: [
          stat(input, bytes.length),
          hash(sha256),
          ...(mode === "multi-file-failure" || mode === "multi-file-dependency"
            ? [
                {
                  __typename__: "MultiFileReport",
                  id: mode === "multi-file-dependency" ? "sq-id" : "mf-id",
                  handler_name:
                    mode === "multi-file-dependency" ? "squashfs" : "tar",
                  name:
                    mode === "multi-file-dependency"
                      ? "rootfs.squashfs"
                      : "rootfs.tar",
                  paths: [
                    join(
                      output,
                      mode === "multi-file-dependency"
                        ? "rootfs.squashfs"
                        : "rootfs.tar",
                    ),
                  ],
                  extraction_reports: [
                    mode === "multi-file-dependency"
                      ? {
                          __typename__: "ExtractorDependencyNotFoundReport",
                          severity: "ERROR",
                          dependencies: ["sasquatch"],
                        }
                      : {
                          __typename__: "ExtractorExecutionErrorReport",
                          severity: "ERROR",
                          handler: "tar",
                        },
                  ],
                },
              ]
            : []),
          {
            __typename__: "ChunkReport",
            id: "gzip-id",
            start_offset: 0,
            end_offset: bytes.length,
            size: bytes.length,
            handler_name: "gzip",
            is_encrypted: false,
            extraction_reports:
              mode === "dependency" || mode === "unnamed-chunk-dependency"
                ? [
                    {
                      __typename__: "ExtractorDependencyNotFoundReport",
                      severity: "ERROR",
                      dependencies:
                        mode === "unnamed-chunk-dependency"
                          ? []
                          : ["sasquatch"],
                    },
                  ]
                : [],
          },
        ],
        subtasks: [childTask],
      },
    ];
    if (mode === "many-unknown") {
      records[1].reports = [
        ...records[1].reports,
        ...Array.from({ length: 1000 }, (_, index) => ({
          __typename__: "UnknownChunkReport",
          id: `unknown-${index}`,
          start_offset: 0,
          end_offset: 1,
          size: 1,
          randomness: null,
        })),
      ];
    }
    if (mode === "unnamed-dependency") {
      records[1].reports = [
        ...records[1].reports,
        {
          __typename__: "ExtractorDependencyNotFoundReport",
          severity: "ERROR",
          dependencies: [],
        },
      ];
    }
    if (observationFacts) {
      const fullHash = (data) => ({
        __typename__: "HashReport",
        md5: createHash("md5").update(data).digest("hex"),
        sha1: createHash("sha1").update(data).digest("hex"),
        sha256: createHash("sha256").update(data).digest("hex"),
      });
      const magic = {
        __typename__: "FileMagicReport",
        magic: "ASCII text",
        mime_type: "text/plain",
      };
      const measurements = {
        __typename__: "RandomnessReport",
        shannon: { percentages: [40], block_size: 1024, mean: 40.000000001 },
        chi_square: { percentages: [0], block_size: 1024, mean: 0 },
      };
      records[0].reports = [
        stat(child, content.length),
        magic,
        fullHash(content),
        measurements,
      ];
      records[1].reports[1] = fullHash(bytes);
      records[1].reports.push(magic);
      const directory = task(join(output, "rootfs"), 1, "gzip-id");
      const partPath = join(output, "rootfs", "part");
      const partBytes = Buffer.from("part=true\n");
      await writeFile(partPath, partBytes);
      const partTask = { ...task(partPath, 1, "gzip-id"), is_multi_file: true };
      const deletedPath = join(output, "rootfs", "intermediate.gz");
      const deletedTask = task(deletedPath, 1, "gzip-id");
      records[1].subtasks = [directory];
      records.push(
        {
          task: directory,
          reports: [
            { ...stat(directory.path, 4096), is_file: false, is_dir: true },
            {
              __typename__: "MultiFileReport",
              id: "multifile-id",
              handler_name: "multipart",
              name: "volume",
              paths: [partPath],
              extraction_reports: [],
            },
          ],
          subtasks: [childTask, partTask, deletedTask],
        },
        {
          task: partTask,
          reports: [
            stat(partPath, partBytes.length),
            magic,
            fullHash(partBytes),
          ],
          subtasks: [],
        },
        {
          task: deletedTask,
          reports: [
            stat(deletedPath, content.length),
            magic,
            fullHash(content),
            {
              __typename__: "ExtractedFileDeletedReport",
              path: deletedPath,
              handler_name: "gzip",
            },
          ],
          subtasks: [],
        },
      );
    }
    if (mode === "recovery-stage-errors") {
      const dependency = (dependencies) => ({
        __typename__: "ExtractorDependencyNotFoundReport",
        severity: "ERROR",
        dependencies,
      });
      records[1].reports[2].extraction_reports = [
        {
          __typename__: "TrustedExtractionError",
          severity: "ERROR",
          note: "chunk failure",
        },
      ];
      records[1].reports.push(
        dependency(["sasquatch", "sasquatch"]),
        dependency(["jefferson", "sasquatch"]),
      );
      const directory = task(join(output, "rootfs"), 1, "gzip-id");
      childTask.is_multi_file = true;
      records[1].subtasks = [directory];
      records.push({
        task: directory,
        reports: [
          { ...stat(directory.path, 4096), is_file: false, is_dir: true },
          {
            __typename__: "MultiFileReport",
            id: "parts-stage",
            handler_name: "multipart",
            name: "volume",
            paths: [child],
            extraction_reports: [
              {
                __typename__: "TrustedExtractionError",
                severity: "ERROR",
                note: "multifile failure without output child",
              },
            ],
          },
        ],
        subtasks: [childTask],
      });
    }
    if (mode === "deleted-and-missing") {
      const ghost = join(output, "unreported-deletion");
      const ghostTask = task(ghost, 1, "gzip-id");
      records[1].subtasks.push(ghostTask);
      records.push({
        task: ghostTask,
        reports: [stat(ghost, content.length), hash(childHash)],
        subtasks: [],
      });
    }
    if (
      mode !== "depth-reentry" &&
      mode !== "depth-orphan" &&
      mode !== "nested-unknown" &&
      mode !== "nested-unknown-oversized"
    )
      await writeFile(
        reportPath,
        mode === "malformed" || mode === "workspace-cleanup-failure-malformed"
          ? "["
          : serializeUnblobReport(records, input, output),
      );
    if (mode === "dependency" || mode === "multi-file-dependency")
      process.exitCode = 1;
    if (
      mode === "workspace-cleanup-failure" ||
      mode === "workspace-cleanup-failure-malformed"
    ) {
      const blocked = join(process.cwd(), "cleanup-blocked");
      await mkdir(blocked);
      await writeFile(join(blocked, "retained"), "owned workspace bytes");
      await chmod(blocked, 0);
    }
    if (!args.includes("--skip-extraction"))
      await emitExtractionFrame(reportPath, output);
  }
}
