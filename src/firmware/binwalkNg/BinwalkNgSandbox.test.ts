import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { prepareBinwalkNgSandbox } from "./BinwalkNgSandbox.js";

const prepare = async (mounts: unknown[] = []) => {
  const root = await createTestTempDirectory("rea-ng-policy-");
  const input = join(root, "source.bin");
  const work = join(root, "work");
  await writeFile(input, "private input");
  await mkdir(work);
  const manifest = join(root, "runtime.json");
  await writeFile(
    manifest,
    JSON.stringify({ profile: "binwalk-ng-4.0.0", mounts }),
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
  const fixture = await prepare([
    {
      source: "/usr/bin/true",
      destination: "/runtime/bin/helper",
      kind: "executable",
    },
  ]);
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
  expect(sandbox.runtime_mounts[0]).toMatchObject({
    configured_source: "/usr/bin/true",
    destination: "/runtime/bin/helper",
    kind: "executable",
    sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
  });
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
          destination: "/runtime/bin/helper",
          kind: "executable",
        },
        {
          source: "/usr/bin/true",
          destination: "/runtime/bin/helper",
          kind: "executable",
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
