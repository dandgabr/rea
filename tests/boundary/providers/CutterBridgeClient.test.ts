import { createServer } from "node:net";
import { readFileSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { CutterBridgeClient } from "../../../src/cutter/CutterBridgeClient.js";

const createClient = (environment: NodeJS.ProcessEnv): CutterBridgeClient => {
  if (process.platform !== "win32") return new CutterBridgeClient(environment);
  return new CutterBridgeClient(environment, {
    windowsPrivateReader: {
      verifyDirectory: () => true,
      readDescriptor: (root, name, maxBytes) => {
        const bytes = readFileSync(join(root, name));
        if (bytes.byteLength > maxBytes)
          throw new Error("Descriptor too large");
        return bytes;
      },
    },
  });
};

describe("CutterBridgeClient", () => {
  let directory: string | undefined;
  let server: ReturnType<typeof createServer> | undefined;

  afterEach(async () => {
    if (server !== undefined)
      await new Promise<void>((resolve) => server?.close(() => resolve()));
    if (directory !== undefined)
      await rm(directory, { recursive: true, force: true });
    server = undefined;
    directory = undefined;
  });

  it("discovers a live bridge using the exact session ID from its descriptor", async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-cutter-bridge-test-"));
    const sessionId = "27d3e3f1-f1e5-49ae-91ec-95af1f343a5a";
    const token = "synthetic-cutter-bridge-token-for-test";
    let requestText = "";
    server = createServer((connection) => {
      connection.setEncoding("utf8");
      connection.on("data", (chunk: string) => {
        requestText += chunk;
        const newline = requestText.indexOf("\n");
        if (newline < 0) return;
        const request = JSON.parse(requestText.slice(0, newline)) as Record<
          string,
          unknown
        >;
        connection.end(
          `${JSON.stringify({
            ok: request.token === token,
            session_id: request.session_id,
            current_file: "/tmp/sample.bin",
            document_generation: 4,
            cutter_version: "Cutter fixture version",
            identity_status: "partial",
          })}\n`,
        );
      });
    });
    await new Promise<void>((resolve) =>
      server?.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("Expected an ephemeral IPv4 listener");
    await writeFile(
      join(directory, `cutter-${process.pid}-${sessionId}.json`),
      JSON.stringify({
        session_id: sessionId,
        pid: process.pid,
        host: "127.0.0.1",
        port: address.port,
        token,
        document_generation: 0,
        current_file: null,
        cutter_version: "Cutter fixture version",
        identity_status: "partial",
      }),
      { mode: 0o600 },
    );

    const result = await createClient({
      REA_CUTTER_BRIDGE_DIR: directory,
    }).listSessions();

    expect(result).toMatchObject({
      discovery_status: "sessions_found",
      bridge_directory_security: "private_verified",
      sessions: [
        {
          session_id: sessionId,
          document_generation: 4,
          current_file: "/tmp/sample.bin",
          cutter_version: "Cutter fixture version",
        },
      ],
    });
    expect(JSON.parse(requestText)).toMatchObject({
      kind: "status",
      session_id: sessionId,
    });
  });

  it("rejects a POSIX bridge directory that is accessible to other users", async () => {
    if (process.platform === "win32") return;
    directory = await mkdtemp(join(tmpdir(), "rea-cutter-insecure-"));
    await chmod(directory, 0o755);

    const result = await new CutterBridgeClient({
      REA_CUTTER_BRIDGE_DIR: directory,
    }).listSessions();

    expect(result).toMatchObject({
      sessions: [],
      discovery_status: "bridge_directory_insecure",
      bridge_directory_security: "not_private",
    });
  });

  it("preserves unknown execution state when a live bridge closes after command dispatch", async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-cutter-close-test-"));
    const sessionId = "27d3e3f1-f1e5-49ae-91ec-95af1f343a5a";
    server = createServer((connection) =>
      connection.on("data", () => connection.destroy()),
    );
    await new Promise<void>((resolve) =>
      server?.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("Expected an ephemeral IPv4 listener");
    await writeFile(
      join(directory, `cutter-${process.pid}-${sessionId}.json`),
      JSON.stringify({
        session_id: sessionId,
        pid: process.pid,
        host: "127.0.0.1",
        port: address.port,
        token: "synthetic-cutter-bridge-token-for-test",
        document_generation: 0,
        current_file: null,
        cutter_version: "Cutter fixture version",
        identity_status: "partial",
      }),
      { mode: 0o600 },
    );

    await expect(
      createClient({ REA_CUTTER_BRIDGE_DIR: directory }).execute({
        sessionId,
        expectedGeneration: 0,
        command: "Ps /tmp/possibly-saved.rzdb",
        json: false,
      }),
    ).resolves.toMatchObject({
      executionState: "unknown",
      error: "transport-response-missing",
      message: expect.stringContaining("do not retry automatically"),
      documentGeneration: 0,
    });
  });
});

describe("CutterBridgeClient Windows descriptor security", () => {
  let directory: string | undefined;
  let server: ReturnType<typeof createServer> | undefined;

  afterEach(async () => {
    if (server !== undefined)
      await new Promise<void>((resolve) => server?.close(() => resolve()));
    if (directory !== undefined)
      await rm(directory, { recursive: true, force: true });
    server = undefined;
    directory = undefined;
  });

  it("uses verified Windows handle reads before trusting Cutter descriptors", async () => {
    directory = await mkdtemp(
      join(tmpdir(), "rea-cutter-windows-bridge-test-"),
    );
    const sessionId = "27d3e3f1-f1e5-49ae-91ec-95af1f343a5a";
    const token = "synthetic-cutter-bridge-token-for-test";
    server = createServer((connection) => {
      connection.setEncoding("utf8");
      connection.on("data", (chunk: string) => {
        const request = JSON.parse(chunk.split("\n", 1)[0] ?? "{}") as Record<
          string,
          unknown
        >;
        connection.end(
          `${JSON.stringify({
            ok: request.token === token,
            session_id: request.session_id,
            current_file: "C:\\fixtures\\sample.exe",
            document_generation: 1,
            cutter_version: "Cutter fixture version",
            identity_status: "partial",
          })}\n`,
        );
      });
    });
    await new Promise<void>((resolve) =>
      server?.listen(0, "127.0.0.1", resolve),
    );
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("Expected an ephemeral IPv4 listener");
    const entry = `cutter-${process.pid}-${sessionId}.json`;
    const descriptor = {
      session_id: sessionId,
      pid: process.pid,
      host: "127.0.0.1",
      port: address.port,
      token,
      document_generation: 0,
      current_file: null,
      cutter_version: "Cutter fixture version",
      identity_status: "partial",
    };
    await writeFile(
      join(directory, entry),
      "native reader owns descriptor bytes",
    );
    let reads = 0;
    const result = await new CutterBridgeClient(
      { REA_CUTTER_BRIDGE_DIR: directory },
      {
        platform: "win32",
        windowsPrivateReader: {
          verifyDirectory: () => true,
          readDescriptor: (root, name, maxBytes) => {
            expect(root).toBe(directory);
            expect(name).toBe(entry);
            expect(maxBytes).toBe(64 * 1024);
            reads += 1;
            return Buffer.from(JSON.stringify(descriptor));
          },
        },
      },
    ).listSessions();

    expect(reads).toBe(1);
    expect(result).toMatchObject({
      discovery_status: "sessions_found",
      bridge_directory_security: "private_verified",
      sessions: [
        {
          session_id: sessionId,
          document_generation: 1,
          current_file: "C:\\fixtures\\sample.exe",
          cutter_version: "Cutter fixture version",
        },
      ],
    });
  });

  it("fails closed when Windows ACL verification is unavailable", async () => {
    directory = await mkdtemp(join(tmpdir(), "rea-cutter-windows-insecure-"));

    const result = await new CutterBridgeClient(
      { REA_CUTTER_BRIDGE_DIR: directory },
      {
        platform: "win32",
        windowsPrivateReader: {
          verifyDirectory: () => false,
          readDescriptor: () => Buffer.from("{}"),
        },
      },
    ).listSessions();

    expect(result).toMatchObject({
      sessions: [],
      discovery_status: "bridge_directory_insecure",
      bridge_directory_security: "not_private",
    });
  });
});
