import { constants } from "node:fs";
import { access, open, realpath, stat } from "node:fs/promises";
import { join } from "node:path";
import { FactFileResources } from "./FactFiles.js";
import { parseFactNativeConfiguration } from "./FactNativeConfiguration.js";
import { FACT_NATIVE_SOURCE_PINS } from "./FactNativeProfiles.js";
import { FACT_LIMITS, factHash } from "./FactProtocol.js";
import { readBoundedFileBytes } from "../../process/BoundedFileBytes.js";

type Profile = keyof typeof FACT_NATIVE_SOURCE_PINS;
export class FactNativeFileCleanupFailure extends Error {
  constructor(
    readonly path: string,
    readonly identity:
      | {
          path: string;
          sha256: string;
          size: number;
          device: string;
          inode: string;
          mtime_ns: string;
          ctime_ns: string;
        }
      | undefined,
    cause: unknown,
    readonly primary?: unknown,
  ) {
    super("FACT native descriptor cleanup failed; ownership retained", {
      cause,
    });
  }
}
export function verifyFactNativeSources(
  profile: Profile,
  hashes: Readonly<Record<string, string>>,
): void {
  for (const [path, expected] of Object.entries(
    FACT_NATIVE_SOURCE_PINS[profile],
  ))
    if (hashes[path] !== expected)
      throw Error(
        `FACT native source identity contradicts selected profile: ${path}`,
      );
}

/** Descriptor admission owns every identity read, including special-file refusal. */
export async function readFactNativeFile(
  path: string,
  maximum: number,
  signal: AbortSignal,
  resources: FactFileResources,
) {
  signal.throwIfAborted();
  const handle = await open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  const owner = resources.descriptor(handle, path);
  let identity: FactNativeFileCleanupFailure["identity"];
  let primary: unknown;
  try {
    const info = await handle.stat({ bigint: true });
    if (!info.isFile() || info.size > BigInt(maximum))
      throw Error("FACT native identity/input requires a bounded regular file");
    const bytes = await readBoundedFileBytes(
      handle,
      maximum,
      signal,
      Number(info.size),
    );
    if (bytes === undefined || BigInt(bytes.length) !== info.size)
      throw Error("FACT native file identity changed during read");
    const after = await handle.stat({ bigint: true });
    if (
      info.size !== after.size ||
      info.mtimeNs !== after.mtimeNs ||
      info.ctimeNs !== after.ctimeNs
    )
      throw Error("FACT native file changed during identity read");
    identity = {
      path,
      sha256: factHash(bytes),
      size: bytes.length,
      device: String(info.dev),
      inode: String(info.ino),
      mtime_ns: String(info.mtimeNs),
      ctime_ns: String(info.ctimeNs),
    };
    return { bytes, identity };
  } catch (cause) {
    primary = cause;
    throw cause;
  } finally {
    const released = await resources.release(owner);
    if (!released.ok)
      throw new FactNativeFileCleanupFailure(
        path,
        identity,
        released.error,
        primary,
      );
  }
}

/** The selected interpreter invocation path preserves venv semantics. */
export async function observeFactNativeIdentity(
  input: { interpreter: string; checkout: string; profile: Profile },
  limiter: string,
  signal: AbortSignal,
  resources: FactFileResources,
) {
  const checkout = await realpath(input.checkout);
  if (!(await stat(checkout)).isDirectory())
    throw Error("FACT checkout must be a directory");
  const interpreter = await realpath(input.interpreter);
  await access(input.interpreter, constants.X_OK);
  const interpreterFile = await readFactNativeFile(
    interpreter,
    FACT_LIMITS.rawBytes,
    signal,
    resources,
  );
  const limiterPath = await realpath(limiter);
  await access(limiter, constants.X_OK);
  const limiterFile = await readFactNativeFile(
    limiterPath,
    FACT_LIMITS.rawBytes,
    signal,
    resources,
  );
  const sources: Record<
    string,
    Awaited<ReturnType<typeof readFactNativeFile>>["identity"]
  > = {};
  const hashes: Record<string, string> = {};
  for (const path of Object.keys(FACT_NATIVE_SOURCE_PINS[input.profile])) {
    const source = await readFactNativeFile(
      join(checkout, "src", path),
      FACT_LIMITS.jsonBytes,
      signal,
      resources,
    );
    sources[path] = source.identity;
    hashes[path] = source.identity.sha256;
  }
  verifyFactNativeSources(input.profile, hashes);
  const configuration = await readFactNativeFile(
    join(checkout, "src/config/fact-core-config.toml"),
    FACT_LIMITS.jsonBytes,
    signal,
    resources,
  );
  const parsed = parseFactNativeConfiguration(configuration.bytes);
  const socket = join(
    parsed.projection.postgres.effective,
    `.s.PGSQL.${parsed.projection.postgres.port}`,
  );
  if (!(await stat(socket)).isSocket())
    throw Error(
      "FACT native local PostgreSQL socket is unavailable; admin DB authority is an external prerequisite",
    );
  return {
    public: {
      namespace: "host" as const,
      interpreter: {
        selected_path: input.interpreter,
        ...interpreterFile.identity,
      },
      checkout: { selected_path: input.checkout, resolved_path: checkout },
      sources,
      configuration: {
        ...configuration.identity,
        projection: parsed.projection,
      },
      resource_limiter: { selected_path: limiter, ...limiterFile.identity },
      critical_source_profile_verified: true,
      remaining_imported_dependencies:
        "caller-trusted; not independently attested",
    },
    credentials: parsed.credentials,
    command: input.interpreter,
    script: join(checkout, "src/firmware_import_export.py"),
    limiter,
  };
}
export type FactNativeIdentity = Awaited<
  ReturnType<typeof observeFactNativeIdentity>
>;
