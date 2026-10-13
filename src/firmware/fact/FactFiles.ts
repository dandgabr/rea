import { constants, createWriteStream } from "node:fs";
import { open, chmod, mkdtemp, lstat, realpath, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { readBoundedFileBytes } from "../../process/BoundedFileBytes.js";
import { FACT_LIMITS, factHash } from "./FactProtocol.js";

/** Owned immutable snapshot with original basename and SHA-256 readback. */
export async function snapshotFactFile(
  path: string,
  signal: AbortSignal,
  maxBytes: number = FACT_LIMITS.rawBytes,
) {
  const root = await mkdtemp(join(tmpdir(), "rea-fact-"));
  const selected = join(root, basename(path));
  try {
    const source = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    let size = 0;
    try {
      const info = await source.stat();
      if (!info.isFile() || info.size === 0 || info.size > maxBytes)
        throw Error(
          "FACT input must be a nonempty regular file within the byte budget",
        );
      await pipeline(
        source.createReadStream({ autoClose: false }),
        new Transform({
          transform(chunk: Buffer, _enc, cb) {
            size += chunk.length;
            cb(
              size > maxBytes
                ? Error("FACT input grew beyond the byte budget")
                : null,
              chunk,
            );
          },
        }),
        createWriteStream(selected, { flags: "wx", mode: 0o600 }),
        { signal },
      );
    } finally {
      await source.close();
    }
    await chmod(selected, 0o400);
    const handle = await open(
      selected,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    let bytes: Buffer;
    try {
      const data = await readBoundedFileBytes(handle, maxBytes, signal);
      if (data === undefined || data.length !== size)
        throw Error("Snapshot readback mismatch");
      bytes = data;
    } finally {
      await handle.close();
    }
    return {
      root,
      path: selected,
      bytes,
      sha256: factHash(bytes),
      original_path: path,
    };
  } catch (cause) {
    try {
      await rm(root, { recursive: true });
    } catch (cleanup) {
      throw new AggregateError(
        [cause, cleanup],
        `FACT snapshot cleanup failed; ownership retained at ${root}`,
      );
    }
    throw cause;
  }
}
export async function requireFreshFactOutput(path: string): Promise<void> {
  if (!(await lstat(dirname(path))).isDirectory())
    throw Error("Output parent must be an existing directory");
  if ((await realpath(dirname(path))) !== dirname(path))
    throw Error("Output parent must not traverse symlinks");
  try {
    await lstat(path);
  } catch (cause) {
    if (
      cause !== null &&
      typeof cause === "object" &&
      "code" in cause &&
      cause.code === "ENOENT"
    )
      return;
    throw cause;
  }
  throw Error("FACT output must be absent; overwriting is unsupported");
}
export async function publishFactFile(
  path: string,
  bytes: Buffer,
): Promise<void> {
  await requireFreshFactOutput(path);
  const handle = await open(
    path,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await handle.writeFile(bytes);
  } finally {
    await handle.close();
  }
}
