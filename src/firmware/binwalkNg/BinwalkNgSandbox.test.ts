import { createHash } from "node:crypto";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";

const prepare = async (mounts: unknown[] = [], helpers: unknown[] = []) => {
  const root = await createTestTempDirectory("rea-ng-policy-");
  const input = join(root, "source.bin");
  const work = join(root, "work");
  await writeFile(input, "private input");
  await mkdir(work);
  const manifest = join(root, "runtime.json");
  await writeFile(
    manifest,
    JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts, helpers }),
  );
  return {
    root,
    input,
    work,
    manifest,
    sandbox: () =>
      prepareBinwalkNgSandbox({
        command: "/usr/bin/true",
        bubblewrap: "/usr/bin/true",
        limiter: "/usr/bin/true",
        systemdRun: "/usr/bin/true",
        manifest,
        inputPath: input,
        workRoot: work,
      }),
  };
};

it("builds a minimal explicit namespace policy with isolated input, private work and cleared environment", async () => {
  const fixture = await prepare();
  const sandbox = await fixture.sandbox();
  expect(sandbox.policy_arguments).toEqual(
    expect.arrayContaining([
      "--unshare-user",
      "--unshare-pid",
      "--unshare-net",
      "--unshare-ipc",
      "--unshare-uts",
      "--new-session",
      "--die-with-parent",
      "--clearenv",
    ]),
  );
  expect(sandbox.policy_arguments.join(" ")).toContain(
    `--ro-bind ${fixture.input} /input/source.bin`,
  );
  expect(sandbox.policy_arguments.join(" ")).toContain(
    `--bind ${fixture.work} /work`,
  );
  expect(sandbox.policy_arguments).not.toContain("--share-net");
  expect(sandbox.policy_arguments).not.toContain("--ro-bind-try");
  expect(sandbox.command.sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(sandbox.runtime_mounts).toEqual([]);
});

it("does not resolve an absent helper through the ambient host PATH", async () => {
  const fixture = await prepare();
  const sandbox = await fixture.sandbox();
  const pathIndex = sandbox.policy_arguments.indexOf("PATH");
  expect(sandbox.policy_arguments[pathIndex + 1]).toBe("/runtime/bin");
  expect(sandbox.helpers).toEqual([]);
  expect(
    sandbox.runtime_mounts.some((mount) => mount.destination === "/usr/bin"),
  ).toBe(false);
  expect(sandbox.policy_arguments).not.toContain("/usr/bin:/bin");
});

it("binds each helper command name to its exact selected executable and expected identity", async () => {
  const source = "/usr/bin/true";
  const sha256 = createHash("sha256")
    .update(await readFile(source))
    .digest("hex");
  const fixture = await prepare(
    [],
    [
      {
        name: "sevenzip",
        source,
        sha256,
        version_arguments: ["--version"],
        expected_version: "GNU coreutils",
        supported_signatures: ["7z_archive"],
      },
    ],
  );
  const sandbox = await fixture.sandbox();
  expect(sandbox.helpers).toEqual([
    expect.objectContaining({
      name: "sevenzip",
      configured_source: source,
      source,
      destination: "/runtime/bin/sevenzip",
      sha256,
      expected_version: "GNU coreutils",
      supported_signatures: ["7z_archive"],
    }),
  ]);
  expect(sandbox.policy_arguments.join(" ")).toContain(
    `--ro-bind ${source} /runtime/bin/sevenzip`,
  );
  const pathIndex = sandbox.policy_arguments.indexOf("PATH");
  expect(sandbox.policy_arguments[pathIndex + 1]).toBe("/runtime/bin");
});

it("rejects helper digest mismatches, unsafe command names and unbound executable mounts", async () => {
  for (const helpers of [
    [
      {
        name: "sevenzip",
        source: "/usr/bin/true",
        sha256: "0".repeat(64),
        version_arguments: ["--version"],
        expected_version: "GNU coreutils",
        supported_signatures: ["7z_archive"],
      },
    ],
    [
      {
        name: "../sevenzip",
        source: "/usr/bin/true",
        sha256: "0".repeat(64),
        version_arguments: ["--version"],
        expected_version: "GNU coreutils",
        supported_signatures: ["7z_archive"],
      },
    ],
  ]) {
    const fixture = await prepare([], helpers);
    await expect(fixture.sandbox()).rejects.toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
    });
  }
  const fixture = await prepare([
    {
      source: "/usr/bin/true",
      destination: "/runtime/bin/undeclared",
      kind: "executable",
    },
  ]);
  await expect(fixture.sandbox()).rejects.toMatchObject({
    _tag: "AnalysisCapabilityUnavailableError",
  });
});

it("rejects dot-segment and path-component helper names before mounting them", async () => {
  for (const name of [".", "..", "nested/sevenzip", "nested\\sevenzip"]) {
    const fixture = await prepare(
      [],
      [
        {
          name,
          source: "/usr/bin/true",
          sha256: createHash("sha256")
            .update(await readFile("/usr/bin/true"))
            .digest("hex"),
          version_arguments: ["--version"],
          expected_version: "GNU coreutils",
          supported_signatures: ["7z_archive"],
        },
      ],
    );
    await expect(fixture.sandbox()).rejects.toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
    });
  }
});

it("rejects broad directory and socket exposure instead of broadening the runtime", async () => {
  for (const source of ["/", "/etc", "/home", "/run", "/var"]) {
    const fixture = await prepare([
      { source, destination: "/runtime/support/root", kind: "support" },
    ]);
    await expect(fixture.sandbox()).rejects.toMatchObject({
      _tag: "AnalysisCapabilityUnavailableError",
      providerId: "binwalk-ng",
    });
  }
});

it("admits the caller-selected 7-Zip support object as an exact read-only file", async () => {
  const fixture = await prepare([
    {
      source: "/usr/bin/true",
      destination: "/usr/libexec/7zip/7z.so",
      kind: "support",
    },
  ]);
  const sandbox = await fixture.sandbox();
  expect(sandbox.policy_arguments.join(" ")).toContain(
    `--ro-bind /usr/bin/true /usr/libexec/7zip/7z.so`,
  );
  const broad = await prepare([
    {
      source: "/usr/bin/true",
      destination: "/usr/libexec/7zip/../../bin/sh",
      kind: "support",
    },
  ]);
  await expect(broad.sandbox()).rejects.toThrow();
});

it("rejects unsafe destinations and collisions with input, work or selected executable mounts", async () => {
  for (const destination of [
    "/",
    "/etc/passwd",
    "/input/source.bin",
    "/work/escape",
    "/runtime/bin/binwalk",
    "/runtime/bin/../escape",
  ]) {
    const fixture = await prepare([
      { source: "/usr/bin/true", destination, kind: "executable" },
    ]);
    await expect(fixture.sandbox()).rejects.toThrow();
  }
});

it("rejects a symlink to a broad host directory but preserves explicit selected regular-file alias identity", async () => {
  const fixture = await prepare();
  const alias = join(fixture.root, "alias");
  await symlink("/etc", alias);
  await writeFile(
    fixture.manifest,
    JSON.stringify({
      profile: "binwalk-ng-4.0.0",
      mounts: [
        { source: alias, destination: "/runtime/support/etc", kind: "support" },
      ],
    }),
  );
  await expect(fixture.sandbox()).rejects.toThrow();
  await writeFile(
    fixture.manifest,
    JSON.stringify({
      profile: "binwalk-ng-4.0.0",
      mounts: [
        {
          source: "/usr/bin/true",
          destination: "/runtime/support/helper",
          kind: "support",
        },
        {
          source: "/usr/bin/true",
          destination: "/runtime/support/helper",
          kind: "support",
        },
      ],
    }),
  );
  await expect(fixture.sandbox()).rejects.toThrow(
    "Duplicate runtime destination",
  );
});

it("requires explicit absolute bubblewrap, provider and manifest paths", async () => {
  const fixture = await prepare();
  for (const patch of [
    { bubblewrap: "bwrap" },
    { command: "binwalk" },
    { manifest: "runtime.json" },
  ]) {
    await expect(
      prepareBinwalkNgSandbox({
        command: "/usr/bin/true",
        bubblewrap: "/usr/bin/true",
        limiter: "/usr/bin/true",
        systemdRun: "/usr/bin/true",
        manifest: fixture.manifest,
        inputPath: fixture.input,
        workRoot: fixture.work,
        ...patch,
      }),
    ).rejects.toMatchObject({ _tag: "AnalysisCapabilityUnavailableError" });
  }
});
