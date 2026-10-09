import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, expect, it } from "vitest";

import { GdbSessionManager } from "../../../src/gdb/GdbSessionManager.js";
import { RizinDebugSessionManager } from "../../../src/rizin/RizinDebugSessionManager.js";

let directory: string | undefined;
const managers: Array<{ closeAll(): Promise<void> }> = [];

afterEach(async () => {
  await Promise.all(
    managers
      .splice(0)
      .map((manager) => manager.closeAll().catch(() => undefined)),
  );
  if (directory !== undefined)
    await rm(directory, { recursive: true, force: true });
  directory = undefined;
});

it.skipIf(process.platform === "win32")(
  "returns cancellation when GDB startup is cancelled after spawn",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-start-cancel-"));
    const provider = join(directory, "fake-gdb-start-cancel.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node\nprocess.stdin.resume();\nsetInterval(() => {}, 1000);\n`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);

    const started = await manager.start(controller.signal);

    expect(started.ok).toBe(false);
    if (!started.ok) expect(started.error._tag).toBe("AnalysisCancelledError");
  },
);

it.skipIf(process.platform === "win32")(
  "returns a timeout error for a GDB command deadline",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-command-timeout-"));
    const provider = join(directory, "fake-gdb-command-timeout.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line);
    if (match && line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
      commandTimeoutMs: 40,
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    const result = await manager.execute(
      started.value.session_id,
      "shell sleep 5",
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisTimeoutError");
  },
);

it.skipIf(process.platform === "win32")(
  "cancels a running GDB command and retains its closed status",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-command-cancel-"));
    const provider = join(directory, "fake-gdb-command-cancel.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line);
    if (match && line.includes("auto-load off")) process.stdout.write(match[1] + "^done\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);

    const result = await manager.execute(
      started.value.session_id,
      "shell sleep 600",
      controller.signal,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
    expect(manager.status(started.value.session_id)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "reports bounded GDB stderr retention in session status",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-diagnostic-limit-"));
    const provider = join(directory, "fake-gdb-diagnostic-limit.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stderr.write("x".repeat(100000));
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n");
    if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line);
    if (match) process.stdout.write(match[1] + "^done\\n");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;

    expect(
      manager.status(started.value.session_id)?.diagnostics_truncated,
    ).toBe(true);
  },
);

it.skipIf(process.platform === "win32")(
  "converts a GDB stdin pipe failure into a provider session error",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-gdb-stdin-error-"));
    const provider = join(directory, "fake-gdb-stdin-error.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("(gdb)\\n");
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n"); if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    const match = /^(\\d+)/.exec(line);
    if (match && line.includes("auto-load off")) {
      process.stdout.write(match[1] + "^done\\n");
      setTimeout(() => import("node:fs").then((fs) => fs.closeSync(0)), 50);
    }
  }
});
setInterval(() => {}, 1000);
`,
    );
    await chmod(provider, 0o700);
    const manager = new GdbSessionManager({
      environment: { REA_GDB_COMMAND: provider },
    });
    managers.push(manager);
    const started = await manager.start();
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));

    const result = await manager.execute(
      started.value.session_id,
      "info files",
    );

    expect(result.ok).toBe(false);
    expect(manager.status(started.value.session_id)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "cancels a running Rizin command and retains its closed status",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-rizin-command-cancel-"));
    const provider = join(directory, "fake-rizin-command-cancel.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("\\0");
let input = "";
let stalled = false;
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  input += chunk;
  for (;;) {
    const boundary = input.indexOf("\\n"); if (boundary < 0) break;
    const line = input.slice(0, boundary); input = input.slice(boundary + 1);
    if (line === "slow") stalled = true;
    else if (line.startsWith("!echo ") && !stalled) process.stdout.write(line.slice(6) + "\\n\\0");
  }
});
`,
    );
    await chmod(provider, 0o700);
    const manager = new RizinDebugSessionManager(
      { REA_RIZIN_COMMAND: provider },
      { frameTimeoutMs: 5_000 },
    );
    managers.push(manager);
    const started = await manager.start({ path: "/tmp/fixture.bin" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);

    const result = await manager.execute(
      started.value.session_id,
      "slow",
      controller.signal,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error._tag).toBe("AnalysisCancelledError");
    expect(manager.status(started.value.session_id)?.state).toBe("closed");
  },
);

it.skipIf(process.platform === "win32")(
  "reports bounded Rizin stderr retention in session status",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-rizin-diagnostic-limit-"));
    const provider = join(directory, "fake-rizin-diagnostic-limit.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stderr.write("x".repeat(100000));
process.stdout.write("\\0");
process.stdin.resume();
`,
    );
    await chmod(provider, 0o700);
    const manager = new RizinDebugSessionManager({
      REA_RIZIN_COMMAND: provider,
    });
    managers.push(manager);
    const started = await manager.start({ path: "/tmp/fixture.bin" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 50));

    expect(
      manager.status(started.value.session_id)?.diagnostics_truncated,
    ).toBe(true);
  },
);

it.skipIf(process.platform === "win32")(
  "returns cancellation when Rizin startup is cancelled after spawn",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-rizin-start-cancel-"));
    const provider = join(directory, "fake-rizin-start-cancel.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node\nprocess.stdin.resume();\nsetInterval(() => {}, 1000);\n`,
    );
    await chmod(provider, 0o700);
    const manager = new RizinDebugSessionManager({
      REA_RIZIN_COMMAND: provider,
    });
    managers.push(manager);
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);

    const started = await manager.start(
      { path: "/tmp/fixture.bin" },
      controller.signal,
    );

    expect(started.ok).toBe(false);
    if (!started.ok) expect(started.error._tag).toBe("AnalysisCancelledError");
  },
);

it.skipIf(process.platform === "win32")(
  "converts a Rizin stdin pipe failure into a provider session error",
  async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-rizin-stdin-error-"));
    const provider = join(directory, "fake-rizin-stdin-error.mjs");
    await writeFile(
      provider,
      `#!/usr/bin/env node
process.stdout.write("\\0");
setTimeout(() => import("node:fs").then((fs) => fs.closeSync(0)), 40);
setInterval(() => {}, 1000);
`,
    );
    await chmod(provider, 0o700);
    const manager = new RizinDebugSessionManager({
      REA_RIZIN_COMMAND: provider,
    });
    managers.push(manager);
    const started = await manager.start({ path: "/tmp/fixture.bin" });
    expect(started.ok).toBe(true);
    if (!started.ok) return;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 80));

    const result = await manager.execute(started.value.session_id, "dr");

    expect(result.ok).toBe(false);
    expect(manager.status(started.value.session_id)?.state).toBe("closed");
  },
);
