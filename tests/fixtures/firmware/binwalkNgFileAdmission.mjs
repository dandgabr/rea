// A bounded child prevents a blocking FIFO admission regression from hanging the test host.
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createJiti } from "jiti";
const jiti = createJiti(import.meta.url, { fsCache: false });
const { FirmwareFileAccess } = await jiti.import(
  "../../../src/firmware/FirmwareFiles.ts",
);
const { inspectBinwalkNgPng, verifyBinwalkNgCarving } = await jiti.import(
  "../../../src/firmware/binwalkNg/BinwalkNgArtifacts.ts",
);
const { ArtifactResourceScope } = await jiti.import(
  "../../../src/artifacts/ArtifactResourceScope.ts",
);
const [mode, path, root] = process.argv.slice(2);
const files = new FirmwareFileAccess();
const scope = new ArtifactResourceScope();
const signal = AbortSignal.timeout(100);
console.log("entered");
try {
  if (mode === "hash") await files.hash(path, signal);
  if (mode === "snapshot")
    await files.snapshot(
      { operation: "inspect_firmware_regions", input: { path } },
      root,
      signal,
    );
  if (mode === "report") await files.report(path, "inspect_firmware_regions");
  if (mode === "png")
    await inspectBinwalkNgPng(path, scope, signal, "inspect_firmware_entropy");
  if (mode === "carving") {
    const inputPath = join(root, "input.bin");
    await writeFile(inputPath, "abcdef");
    await verifyBinwalkNgCarving({
      inputPath,
      entry: {
        path,
        relativePath: "input.bin_0_gzip.raw",
        kind: "file",
        size: 2,
        linkTarget: null,
      },
      inputSize: 6,
      rootOffset: 0,
      scope,
      signal,
      operation: "carve_firmware",
    });
  }
  throw Error("unexpected success");
} catch (error) {
  if (
    !error.message.includes("regular file") &&
    !error.cause?.message?.includes("regular file") &&
    !error.issues?.some((issue) => issue.message.includes("regular file"))
  )
    throw error;
  console.log("regular-file rejection");
} finally {
  await files.close();
  await scope.close();
}
