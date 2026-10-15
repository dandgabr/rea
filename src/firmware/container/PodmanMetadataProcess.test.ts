import { open, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { runFirmwareCommand } from "../FirmwareCommand.js";

it.skipIf(process.platform !== "linux")(
  "delivers bounded protocol input and explicitly inherited descriptor with metadata-specific native limits",
  async () => {
    const root = await createTestTempDirectory("rea-metadata-process-");
    const path = join(root, "authority");
    await writeFile(path, "authority bytes");
    const file = await open(path, "r");
    try {
      const result = await runFirmwareCommand({
        engine: "podman",
        operation: "firmware_container_runtime",
        command: "/usr/bin/python3",
        limiter: "/usr/bin/prlimit",
        args: [
          "-I",
          "-S",
          "-c",
          "import os,sys,json,resource; request=json.loads(sys.stdin.buffer.read()); print(json.dumps({'value':request['value'],'bytes':os.read(3,32).decode(),'cpu':resource.getrlimit(resource.RLIMIT_CPU)[0],'fsize':resource.getrlimit(resource.RLIMIT_FSIZE)[0]}))",
        ],
        cwd: root,
        environment: { PATH: "/usr/bin:/bin" },
        signal: AbortSignal.timeout(5000),
        limitProfile: "metadata-observer",
        protocolInput: Buffer.from('{"value":"exact input"}'),
        inheritedDescriptors: [file.fd],
        retainCleanup: () => {
          throw Error("Unexpected pending cleanup");
        },
      });
      expect(JSON.parse(result.stdout.text)).toEqual({
        value: "exact input",
        bytes: "authority bytes",
        cpu: 5,
        fsize: 1048576,
      });
      expect(file.fd).toBeGreaterThanOrEqual(0);
    } finally {
      await file.close();
    }
  },
);

it.skipIf(process.platform !== "linux")(
  "rejects over-budget protocol bytes before launch and cancels an actually running bounded helper with retained diagnostics and caller FD ownership",
  async () => {
    const root = await createTestTempDirectory("rea-metadata-process-cancel-");
    const path = join(root, "authority");
    await writeFile(path, "still owned");
    const file = await open(path, "r");
    const controller = new AbortController();
    const ready = join(root, "ready");
    const base = {
      engine: "podman",
      operation: "firmware_container_runtime",
      command: "/usr/bin/python3",
      limiter: "/usr/bin/prlimit",
      cwd: root,
      environment: { PATH: "/usr/bin:/bin" },
      signal: controller.signal,
      limitProfile: "metadata-observer" as const,
      protocolInput: Buffer.from("{}"),
      inheritedDescriptors: [file.fd],
      retainCleanup: () => {
        throw Error("unexpected pending process");
      },
    };
    const launcher = vi
      .fn()
      .mockRejectedValue(Error("unexpected overbudget spawn"));
    try {
      await expect(
        runFirmwareCommand({
          ...base,
          args: [],
          protocolInput: Buffer.alloc(16385),
          launcher,
        }),
      ).rejects.toMatchObject({ _tag: "AnalysisCapabilityUnavailableError" });
      expect(launcher).not.toHaveBeenCalled();
      const running = runFirmwareCommand({
        ...base,
        args: [
          "-I",
          "-S",
          "-c",
          `import os,sys,time;sys.stdin.buffer.read();print('captured before cancel',flush=True);open(${JSON.stringify(ready)},'w').write(str(os.getpid()));time.sleep(20)`,
        ],
      }).catch((cause: unknown) => cause);
      let pid: number | undefined;
      const deadline = performance.now() + 3000;
      while (pid === undefined) {
        try {
          pid = Number(await readFile(ready, "utf8"));
        } catch (cause) {
          if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
        }
        if (performance.now() > deadline)
          throw Error("actual helper readiness deadline");
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      controller.abort();
      const failure = await running;
      expect(failure).toMatchObject({
        _tag: "AnalysisCancelledError",
        capturedOutput: {
          stdout: "captured before cancel\n",
          stdout_utf8_valid: true,
          truncated: false,
        },
      });
      expect(file.fd).toBeGreaterThanOrEqual(0);
      const bytes = Buffer.alloc(16);
      expect((await file.read(bytes, 0, 16, 0)).bytesRead).toBe(
        Buffer.byteLength("still owned"),
      );
      await expect(readFile(`/proc/${pid}/stat`)).rejects.toMatchObject({
        code: "ENOENT",
      });
    } finally {
      await file.close();
    }
  },
);
