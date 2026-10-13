import type { Result } from "../../domain/result.js";
const unwrap = <T>(result: Result<T, Error>): T => {
  if (!result.ok) throw result.error;
  return result.value;
};
import { expect, it } from "vitest";
import { knownSensitiveValueRedactor } from "../../domain/knownSensitiveValueRedaction.js";
import { parseFactNativeConfiguration } from "./FactNativeConfiguration.js";

const config = (server: string, storage = "/tmp/owned-fact-storage") =>
  Buffer.from(`
[common.postgres]
server = ${JSON.stringify(server)}
port = 5432
database = "owned_test"
admin-user = "private-admin"
admin-pw = "private-password"
[backend]
firmware-file-storage-directory = ${JSON.stringify(storage)}
`);
it("projects only namespace-local default config identity without credentials", () => {
  for (const server of [
    "localhost",
    "127.0.0.1",
    "::1",
    "/tmp/owned-postgres-socket",
  ]) {
    const parsed = parseFactNativeConfiguration(config(server));
    expect(parsed.projection).toEqual({
      postgres: {
        source: server,
        effective: server.startsWith("/") ? server : "/var/run/postgresql",
        port: 5432,
        database: "owned_test",
        transport: "unix-socket",
      },
      storage_root: "/tmp/owned-fact-storage",
    });
    const exported = JSON.stringify(parsed.projection);
    expect(exported).not.toContain("private-admin");
    expect(exported).not.toContain("private-password");
    expect(parsed.credentials).toContain("private-password");
    expect(parsed.credentials).not.toContain("private-admin");
  }
});
it("rejects remote/unresolved database selectors and relative storage without printing private TOML", () => {
  for (const server of [
    "remote.example",
    "localhost.example",
    "127.0.0.2",
    "unix:custom",
    "./socket",
  ]) {
    expect(() => parseFactNativeConfiguration(config(server))).toThrow(
      /local|selector/iu,
    );
  }
  expect(() =>
    parseFactNativeConfiguration(config("localhost", "relative")),
  ).toThrow(/absolute|storage/iu);
  try {
    parseFactNativeConfiguration(Buffer.from('admin-pw = "private-password\n'));
  } catch (cause) {
    expect(String(cause)).not.toContain("private-password");
  }
});
it("rejects duplicate semantic hyphen/underscore selectors and invalid UTF-8 rather than repairing them", () => {
  const ambiguous = Buffer.from(
    config("localhost")
      .toString()
      .replace(
        "admin-pw =",
        'admin_pw = "another-private-password"\nadmin-pw =',
      ),
  );
  expect(() => parseFactNativeConfiguration(ambiguous)).toThrow(
    /ambiguous|duplicate/iu,
  );
  expect(() =>
    parseFactNativeConfiguration(
      Buffer.concat([config("localhost"), Buffer.from([0xff])]),
    ),
  ).toThrow(/UTF|configuration/iu);
});
it("runs seeded local-config properties without leaking malformed private source", () => {
  let seed = 0xfac70003;
  for (let index = 0; index < 64; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const local = `/tmp/rea-${seed.toString(16)}-é`;
    const good = parseFactNativeConfiguration(config(local));
    expect(good.projection.postgres.effective).toBe(local);
    expect(JSON.stringify(good.projection)).not.toContain("private-password");
    const bad =
      seed % 2
        ? config(`remote-${seed}.invalid`)
        : Buffer.concat([config(local), Buffer.from([0xff])]);
    let rejected = false;
    try {
      parseFactNativeConfiguration(bad);
    } catch (cause) {
      rejected = true;
      expect(String(cause)).not.toContain("private-password");
    }
    expect(rejected).toBe(true);
  }
});

it("keeps native scalar credentials independent of the HTTP header byte constraint", () => {
  const secret = "秘密🗝️";
  const bytes = Buffer.from(
    config("localhost")
      .toString()
      .replace('"private-password"', JSON.stringify(secret)),
  );
  const parsed = parseFactNativeConfiguration(bytes);
  expect(parsed.credentials).toContain(secret);
  expect(
    unwrap(
      knownSensitiveValueRedactor(secret).value({
        diagnostic: secret,
        path: "/firmware/漢字😀.bin",
      }),
    ),
  ).toEqual({ diagnostic: "[REDACTED]", path: "/firmware/漢字😀.bin" });
  for (const escaped of ["\\uD800", "\\uDFFF"])
    expect(() =>
      parseFactNativeConfiguration(
        Buffer.from(
          config("localhost")
            .toString()
            .replace('"private-password"', `"${escaped}"`),
        ),
      ),
    ).toThrow(/TOML|UTF/iu);
});
