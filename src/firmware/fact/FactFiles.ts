import { constants, createWriteStream } from "node:fs";
import { open, chmod, lstat, realpath, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import type { FileHandle } from "node:fs/promises";
import { PrivateRuntimeRoot } from "../../process/PrivateRuntimeRoot.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { ok, err } from "../../domain/result.js";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { readBoundedFileBytes } from "../../process/BoundedFileBytes.js";
import { FACT_LIMITS, factHash } from "./FactProtocol.js";

interface FactOwnedResource {
  readonly path: string;
  close(): Promise<void>;
}
/** Lifetime owner exists before any fallible acquisition or publication step. */
export class FactFileResources {
  private readonly pending = new Set<FactOwnedResource>();
  readonly createRuntime: () => Promise<
    Pick<PrivateRuntimeRoot, "path" | "close">
  >;
  readonly writeBytes: (handle: FileHandle, bytes: Buffer) => Promise<void>;
  readonly removeFile: (path: string) => Promise<void>;
  constructor(
    dependencies: {
      createRuntime?: () => Promise<Pick<PrivateRuntimeRoot, "path" | "close">>;
      writeBytes?: (handle: FileHandle, bytes: Buffer) => Promise<void>;
      removeFile?: (path: string) => Promise<void>;
    } = {},
  ) {
    this.createRuntime =
      dependencies.createRuntime ??
      (() => PrivateRuntimeRoot.create({ prefix: "rea-fact-" }));
    this.writeBytes =
      dependencies.writeBytes ?? ((handle, bytes) => handle.writeFile(bytes));
    this.removeFile = dependencies.removeFile ?? unlink;
  }
  get pendingResources(): string[] {
    return [...this.pending].map((owner) => owner.path);
  }
  async runtime() {
    const root = await this.createRuntime();
    this.pending.add(root);
    return root;
  }
  descriptor(handle: FileHandle, path: string): FactOwnedResource {
    const descriptor = new OwnedFileHandle(handle);
    const owner = { path, close: () => descriptor.close() };
    this.retain(owner);
    return owner;
  }
  retain(owner: FactOwnedResource): void {
    this.pending.add(owner);
  }
  forget(owner: FactOwnedResource): void {
    this.pending.delete(owner);
  }
  async release(owner: FactOwnedResource) {
    try {
      await owner.close();
      this.pending.delete(owner);
      return ok(undefined);
    } catch (cause) {
      this.pending.add(owner);
      return err(cause);
    }
  }
  async close(): Promise<void> {
    const failures: unknown[] = [];
    for (const owner of this.pending) {
      const result = await this.release(owner);
      if (!result.ok) failures.push(result.error);
    }
    if (failures.length)
      throw new AggregateError(
        failures,
        "FACT resource cleanup remains unresolved",
      );
  }
}
export class FactPublicationFailure extends Error {
  constructor(
    readonly publication: {
      path: string;
      written_bytes: number | null;
      cleanup: "removed" | "retained";
    },
    cause: unknown,
  ) {
    super(
      "FACT output publication failed; uncommitted output ownership is tracked",
      { cause },
    );
  }
}

/** Owned immutable snapshot with original basename and SHA-256 readback. */
export async function snapshotFactFile(
  path: string,
  signal: AbortSignal,
  resources: FactFileResources,
  maxBytes: number = FACT_LIMITS.rawBytes,
) {
  const runtime = await resources.runtime();
  const root = runtime.path;
  const selected = join(root, basename(path));
  try {
    signal.throwIfAborted();
    const source = await open(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const sourceOwner = resources.descriptor(source, path);
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
      const closed = await resources.release(sourceOwner);
      if (!closed.ok) throw closed.error;
    }
    await chmod(selected, 0o400);
    const handle = await open(
      selected,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    const snapshotOwner = resources.descriptor(handle, selected);
    let bytes: Buffer;
    try {
      const data = await readBoundedFileBytes(handle, maxBytes, signal);
      if (data === undefined || data.length !== size)
        throw Error("Snapshot readback mismatch");
      bytes = data;
    } finally {
      const closed = await resources.release(snapshotOwner);
      if (!closed.ok) throw closed.error;
    }
    return {
      root,
      runtime,
      path: selected,
      bytes,
      sha256: factHash(bytes),
      original_path: path,
    };
  } catch (cause) {
    const cleaned = await resources.release(runtime);
    if (!cleaned.ok)
      throw new AggregateError(
        [cause, cleaned.error],
        `FACT snapshot acquisition failed; cleanup ownership retained at ${root}`,
      );
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
  resources: FactFileResources,
): Promise<void> {
  await requireFreshFactOutput(path);
  const handle = await open(
    path,
    constants.O_RDWR |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    0o600,
  );
  const descriptor = new OwnedFileHandle(handle);
  let identity: { dev: number; ino: number } | undefined;
  const owner: FactOwnedResource = {
    path,
    close: async () => {
      await descriptor.close();
      if (identity === undefined)
        throw Error(`Uncommitted output identity is unknown: ${path}`);
      const current = await lstat(path);
      if (
        !current.isFile() ||
        current.isSymbolicLink() ||
        current.dev !== identity.dev ||
        current.ino !== identity.ino
      )
        throw Error(`Uncommitted output identity changed: ${path}`);
      await resources.removeFile(path);
    },
  };
  resources.retain(owner);
  let writtenBytes: number | null = null;
  try {
    const info = await handle.stat();
    identity = { dev: info.dev, ino: info.ino };
    await resources.writeBytes(handle, bytes);
    const ready = await handle.stat();
    writtenBytes = ready.size;
    if (ready.size !== bytes.length)
      throw Error("Published output byte count differs from verified bytes");
    await descriptor.close();
    resources.forget(owner);
  } catch (cause) {
    try {
      writtenBytes = (await handle.stat()).size;
    } catch {
      /* Preserve unknown if descriptor is already closed. */
    }
    const cleaned = await resources.release(owner);
    throw new FactPublicationFailure(
      {
        path,
        written_bytes: writtenBytes,
        cleanup: cleaned.ok ? "removed" : "retained",
      },
      cause,
    );
  }
}
