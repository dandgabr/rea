// Controlled native-protocol producer; not native format or containment evidence.
import { mkdir, writeFile, symlink } from "node:fs/promises";
import { join } from "node:path";
const [mode, work, pass, name] = process.argv.slice(2);
if (mode === "version") {
  console.log("binwalk-ng 4.0.0");
} else {
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
    } else {
      if (mode === "mutate") await writeFile(candidate, "ZZ");
      report = [
        { Analysis: { file_path: path, file_map: [], extractions: {} } },
      ];
    }
  } else {
    const dir =
      mode === "inside"
        ? join(work, "artifacts", pass)
        : join(work, "artifacts");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "orphan.bin"), "unattributed bytes");
    await symlink("orphan.bin", join(dir, "orphan.link"));
    report = [
      { Analysis: { file_path: path, file_map: [hit], extractions: {} } },
    ];
  }
  await writeFile(
    join(work, "reports", `${pass}.json`),
    JSON.stringify(report),
  );
}
