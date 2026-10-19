import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { constants } from "node:fs";
import { access, lstat, mkdir, realpath } from "node:fs/promises";
import { basename, isAbsolute, join, posix, relative, sep } from "node:path";
import { z } from "zod";
import { firmwareToolUnavailable } from "../FirmwareCommand.js";
import type { FirmwareFileAccess } from "../FirmwareFiles.js";

const unavailable = (reason: string) =>
  firmwareToolUnavailable("binwalk-ng", "binwalk_ng_confinement", reason);
const pathSchema = z
  .string()
  .min(1)
  .refine((path) => isAbsolute(path) && !path.includes("\0"));
const helperNameSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._+-]*$/u)
  .refine((name) => name !== "." && name !== "..")
  .refine((name) => !name.includes("/") && !name.includes("\\"))
  .refine((name) => name !== "binwalk");
const manifestSchema = z.strictObject({
  profile: z.literal("binwalk-ng-4.0.0"),
  helpers: z
    .array(
      z.strictObject({
        name: helperNameSchema,
        source: pathSchema,
        sha256: z.string().regex(/^[a-f0-9]{64}$/u),
        version_arguments: z.array(
          z.string().refine((arg) => !arg.includes("\0")),
        ),
        expected_version: z.string().min(1),
        supported_signatures: z.array(z.string().min(1)).min(1),
      }),
    )
    .default([]),
  mounts: z.array(
    z.strictObject({
      source: pathSchema,
      destination: z.string().min(1),
      kind: z.enum(["executable", "library", "support"]),
    }),
  ),
});
const inside = (root: string, path: string) => {
  const rel = relative(root, path);
  return (
    rel === "" ||
    (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`))
  );
};
const allowedDestination = (destination: string, kind: string) => {
  if (
    !posix.isAbsolute(destination) ||
    posix.normalize(destination) !== destination ||
    destination.includes("\0") ||
    destination.endsWith("/")
  )
    return false;
  if (destination === "/runtime/bin/binwalk") return false;
  if (kind === "support")
    return (
      destination.startsWith("/runtime/support/") ||
      destination.startsWith("/usr/libexec/7zip/")
    );
  if (kind === "library")
    return ["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"].some((prefix) =>
      destination.startsWith(prefix),
    );
  return (
    destination.startsWith("/runtime/bin/") ||
    /^\/(?:usr\/)?bin\/[^/]+$/u.test(destination)
  );
};

/** A selected regular-file identity; aliases remain separate from the resolved mount source. */
export const identifyBinwalkNgRuntimeFile = async (
  configured: string,
  executable: boolean,
  context: {
    signal?: AbortSignal;
    scope?: ArtifactResourceScope;
    operation?: string;
    files: FirmwareFileAccess;
  },
) => {
  context?.signal?.throwIfAborted();
  if (!isAbsolute(configured) || configured.includes("\0"))
    throw unavailable("Runtime paths must be explicit absolute local paths");
  try {
    const path = await realpath(configured);
    await access(path, constants.R_OK | (executable ? constants.X_OK : 0));
    if (!(await lstat(path)).isFile())
      throw new Error(
        "Only selected regular files can be mounted; directories, sockets and special files are forbidden",
      );
    return {
      configured_path: configured,
      path,
      sha256: await context.files.hash(path, context.signal),
    };
  } catch (cause: unknown) {
    if (
      context?.signal?.aborted ||
      (cause instanceof AnalysisError && cause.cleanupIncomplete)
    )
      throw cause;
    throw unavailable(
      `Cannot identify selected runtime file ${configured}: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
};

/** Explicit minimal runtime file manifest and the exact policy reused by probe and execution. */
export const prepareBinwalkNgSandbox = async (input: {
  readonly command: string;
  readonly bubblewrap: string;
  readonly limiter: string;
  readonly systemdRun?: string;
  readonly manifest: string;
  readonly inputPath: string;
  readonly workRoot: string;
  readonly signal?: AbortSignal;
  readonly scope?: ArtifactResourceScope;
  readonly files: FirmwareFileAccess;
  readonly operation?: string;
}) => {
  if (process.platform !== "linux")
    throw unavailable("binwalk-ng containment requires Linux");
  const command = await identifyBinwalkNgRuntimeFile(
    input.command,
    true,
    input,
  );
  const bubblewrap = await identifyBinwalkNgRuntimeFile(
    input.bubblewrap,
    true,
    input,
  );
  const limiter = await identifyBinwalkNgRuntimeFile(
    input.limiter,
    true,
    input,
  );
  const systemdRun = await identifyBinwalkNgRuntimeFile(
    input.systemdRun ?? "/usr/bin/systemd-run",
    true,
    input,
  );
  if (!isAbsolute(input.manifest))
    throw unavailable(
      "Runtime manifest must be an explicit absolute file path",
    );
  const manifestFile = await identifyBinwalkNgRuntimeFile(
    input.manifest,
    false,
    input,
  );
  const parsed = manifestSchema.safeParse(
    await input.files.report(
      manifestFile.path,
      input.operation ?? "binwalk_ng_confinement",
      input.signal,
    ),
  );
  if (!parsed.success)
    throw unavailable(
      `Runtime manifest violates the selected regular-file policy: ${parsed.error.message}`,
    );
  const workRoot = await realpath(input.workRoot);
  const inputPath = await realpath(input.inputPath);
  if (
    !isAbsolute(input.workRoot) ||
    !isAbsolute(input.inputPath) ||
    !(await lstat(workRoot)).isDirectory() ||
    !(await lstat(inputPath)).isFile() ||
    inside(workRoot, inputPath)
  )
    throw unavailable(
      "Read-only input must be a regular file outside the private writable work tree",
    );
  const destinations = new Set<string>();
  const runtimeMounts = [];
  for (const mount of parsed.data.mounts) {
    input.signal?.throwIfAborted();
    if (!allowedDestination(mount.destination, mount.kind))
      throw unavailable(`Unsafe runtime destination: ${mount.destination}`);
    if (mount.kind === "executable")
      throw unavailable(
        "Executable mounts must use the helper identity mapping so PATH cannot expose unbound commands",
      );
    if (destinations.has(mount.destination))
      throw unavailable(`Duplicate runtime destination: ${mount.destination}`);
    destinations.add(mount.destination);
    const identified = await identifyBinwalkNgRuntimeFile(
      mount.source,
      false,
      input,
    );
    if (inside(workRoot, identified.path))
      throw unavailable(
        "Runtime files cannot also be exposed through writable work mounts",
      );
    runtimeMounts.push({
      configured_source: mount.source,
      source: identified.path,
      destination: mount.destination,
      kind: mount.kind,
      sha256: identified.sha256,
    });
  }
  const helperNames = new Set<string>();
  const helpers = [];
  for (const helper of parsed.data.helpers) {
    input.signal?.throwIfAborted();
    if (helperNames.has(helper.name))
      throw unavailable(`Duplicate helper command name: ${helper.name}`);
    helperNames.add(helper.name);
    const destination = posix.join("/runtime/bin", helper.name);
    if (
      posix.normalize(destination) !== destination ||
      posix.dirname(destination) !== "/runtime/bin" ||
      posix.basename(destination) !== helper.name
    )
      throw unavailable(
        `Helper ${helper.name} must resolve to one direct child of /runtime/bin`,
      );
    if (destinations.has(destination))
      throw unavailable(`Duplicate runtime destination: ${destination}`);
    destinations.add(destination);
    const identified = await identifyBinwalkNgRuntimeFile(
      helper.source,
      true,
      input,
    );
    if (identified.sha256 !== helper.sha256)
      throw unavailable(
        `Selected helper ${helper.name} digest does not match its declared identity`,
      );
    if (inside(workRoot, identified.path))
      throw unavailable(
        "Helper executables cannot also be exposed through writable work mounts",
      );
    runtimeMounts.push({
      configured_source: helper.source,
      source: identified.path,
      destination,
      kind: "executable" as const,
      sha256: identified.sha256,
    });
    helpers.push({
      name: helper.name,
      configured_source: helper.source,
      source: identified.path,
      destination,
      sha256: identified.sha256,
      version_arguments: helper.version_arguments,
      expected_version: helper.expected_version,
      supported_signatures: helper.supported_signatures,
      source_provenance: null,
    });
  }
  if (inside(workRoot, command.path))
    throw unavailable(
      "The provider executable cannot be inside its writable workspace",
    );
  input.signal?.throwIfAborted();
  await mkdir(join(workRoot, "home"), { recursive: true });
  await mkdir(join(workRoot, "tmp"), { recursive: true });
  const inputDestination = `/input/${basename(input.inputPath)}`;
  const policyArguments = [
    "--unshare-user",
    "--unshare-pid",
    "--unshare-net",
    "--unshare-ipc",
    "--unshare-uts",
    "--new-session",
    "--die-with-parent",
    "--cap-drop",
    "ALL",
    "--clearenv",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--ro-bind",
    command.path,
    "/runtime/bin/binwalk",
    ...runtimeMounts.flatMap((mount) => [
      "--ro-bind",
      mount.source,
      mount.destination,
    ]),
    "--ro-bind",
    inputPath,
    inputDestination,
    "--bind",
    workRoot,
    "/work",
    "--symlink",
    "/work/tmp",
    "/tmp",
    "--setenv",
    "HOME",
    "/work/home",
    "--setenv",
    "TMPDIR",
    "/work/tmp",
    "--setenv",
    "PATH",
    "/runtime/bin",
    "--setenv",
    "LC_ALL",
    "C",
    "--setenv",
    "TZ",
    "UTC",
    "--setenv",
    "BINWALK_RM_EXTRACTION_SYMLINK",
    "1",
    "--chdir",
    "/work",
  ];
  return {
    profile: parsed.data.profile,
    command,
    bubblewrap,
    limiter,
    systemdRun,
    manifest: manifestFile,
    runtime_mounts: runtimeMounts,
    helpers,
    input_path: inputDestination,
    work_root: workRoot,
    policy_arguments: policyArguments,
  };
};
