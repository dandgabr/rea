// Controlled native-protocol producer; not native format or containment evidence.
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  symlink,
  writeFile,
} from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
const [mode, work, pass, name] = process.argv.slice(2);
if (mode === "list") {
  process.stdout.write(
    "-".repeat(90) +
      "\nSignature Description".padEnd(35) +
      "Signature Name".padEnd(35) +
      "Extraction Utility\n" +
      "-".repeat(90) +
      "\n" +
      "gzip compressed data".padEnd(35) +
      "gzip".padEnd(35) +
      "gzip\n" +
      "-".repeat(90) +
      "\nTotal signatures: 1\nExtractable signatures: 1\n",
  );
  process.exit(0);
}
if (mode === "version") {
  console.log("binwalk-ng 4.0.0");
} else {
  await Promise.all([
    mkdir(join(work, "reports"), { recursive: true }),
    mkdir(join(work, "artifacts", pass), { recursive: true }),
  ]);
  const path = `/work/artifacts/${pass}/${name}`;
  const hit = {
    id: "hit",
    offset: 2,
    size: 2,
    name: "gzip",
    description: "fixture",
    confidence: 250,
    always_display: false,
    extraction_declined: false,
  };
  let report;
  if (mode === "png") {
    const png = Buffer.alloc(24);
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(png);
    png.writeUInt32BE(13, 8);
    png.write("IHDR", 12);
    png.writeUInt32BE(2048, 16);
    png.writeUInt32BE(1024, 20);
    await writeFile(join(work, "entropy.png"), png);
    report = [
      {
        Entropy: {
          file: `/input/${name}`,
          blocks: [{ start: 0, end: 6, entropy: 2.5849625 }],
        },
      },
    ];
  } else if (mode === "stable" || mode === "mutate") {
    const dir = join(work, "artifacts", "0000", "input.bin.extracted", "2");
    await mkdir(dir, { recursive: true });
    const candidate = join(dir, "input.bin_2_gzip.raw");
    if (pass === "0000") {
      await writeFile(candidate, "cd");
      report = [
        {
          Analysis: {
            file_path: path,
            file_map: [hit],
            extractions: {
              hit: {
                size: 2,
                success: true,
                extractor: "gzip",
                do_not_recurse: false,
                output_directory: "/work/artifacts/0000/input.bin.extracted/2",
              },
            },
          },
        },
      ];
      if (mode === "mutate") await writeFile(candidate, "ZZ");
    } else {
      report = [
        { Analysis: { file_path: path, file_map: [], extractions: {} } },
      ];
    }
  } else {
    const dir =
      mode === "outside"
        ? join(work, "artifacts")
        : join(work, "artifacts", pass);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "orphan.bin"), "unattributed bytes");
    if (mode === "inside" || mode === "outside")
      await writeFile(
        join(dir, "orphan-second.bin"),
        "more unattributed bytes",
      );
    else if (mode === "symlink")
      await symlink("orphan.bin", join(dir, "orphan.link"));
    else if (mode === "special")
      execFileSync("/usr/bin/mkfifo", [join(dir, "orphan.pipe")], {
        env: { PATH: "/usr/bin:/bin" },
      });
    report = [
      { Analysis: { file_path: path, file_map: [hit], extractions: {} } },
    ];
  }
  await writeFile(
    join(work, "reports", `${pass}.json`),
    JSON.stringify(report),
  );
  const transferPaths = [
    `reports/${pass}.json`,
    ...(mode === "png" ? ["entropy.png"] : []),
    ...(mode === "outside"
      ? ["artifacts"]
      : mode === "stable" ||
          mode === "mutate" ||
          mode === "inside" ||
          mode === "symlink" ||
          mode === "special"
        ? [`artifacts/${pass}`]
        : []),
  ];
  const write = (bytes) =>
    new Promise((resolve, reject) => {
      process.stdout.write(bytes, (error) =>
        error ? reject(error) : resolve(),
      );
    });
  const frame = (value) => {
    const body = Buffer.from(JSON.stringify(value));
    const length = Buffer.alloc(4);
    length.writeUInt32BE(body.length);
    return Buffer.concat([length, body]);
  };
  let files = 0;
  let bytes = 0;
  await write(Buffer.from("REABWNG1"));
  const emitFile = async (relativePath) => {
    const content = await readFile(join(work, ...relativePath.split("/")));
    await write(
      frame({
        type: "file",
        path: relativePath,
        bytes: content.length,
        sha256: createHash("sha256").update(content).digest("hex"),
      }),
    );
    await write(content);
    files += 1;
    bytes += content.length;
  };
  const walk = async (relativePath) => {
    const absolute = join(work, ...relativePath.split("/"));
    const metadata = await lstat(absolute);
    if (
      metadata.isSymbolicLink() ||
      (!metadata.isDirectory() && !metadata.isFile())
    )
      throw new Error("Synthetic transfer tree contains a non-regular entry");
    if (metadata.isFile()) {
      await emitFile(relativePath);
      return;
    }
    for (const child of (await readdir(absolute)).sort())
      await walk(`${relativePath}/${child}`);
  };
  for (const path of transferPaths) await walk(path);
  await write(frame({ type: "end", files, bytes }));
}
