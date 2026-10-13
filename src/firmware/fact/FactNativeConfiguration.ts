import { parse } from "smol-toml";
import { isAbsolute } from "node:path";
import { FACT_LIMITS } from "./FactProtocol.js";

const table = (value: unknown): Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw Error("FACT default configuration requires native tables");
  const result: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
  for (const [key, item] of Object.entries(value)) {
    const normalized = key.replaceAll("-", "_");
    if (Object.hasOwn(result, normalized))
      throw Error(
        "FACT default configuration has ambiguous duplicate semantic keys",
      );
    result[normalized] = item;
  }
  return result;
};

/** Private transport credentials never belong to the exported projection. */
export function parseFactNativeConfiguration(bytes: Buffer) {
  if (bytes.length > FACT_LIMITS.jsonBytes)
    throw Error("FACT default configuration exceeds JSON/config byte budget");
  let source: Record<string, unknown>;
  try {
    source = parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw Error(
      "FACT default configuration is invalid TOML or UTF-8; private source omitted",
    );
  }
  const common = table(source.common);
  const postgres = table(common.postgres);
  const backend = table(source.backend);
  const server = postgres.server;
  if (
    typeof server !== "string" ||
    server.includes("\0") ||
    (!isAbsolute(server) && !["localhost", "127.0.0.1", "::1"].includes(server))
  )
    throw Error(
      "FACT native PostgreSQL selector must be literal namespace-local loopback or an absolute Unix socket directory",
    );
  const port = Number(postgres.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
    throw Error("FACT PostgreSQL port is outside its protocol range");
  const database = postgres.database;
  if (
    typeof database !== "string" ||
    !database.length ||
    database.includes("\0")
  )
    throw Error("FACT PostgreSQL database selector is unresolved");
  const storage = backend.firmware_file_storage_directory;
  if (
    typeof storage !== "string" ||
    !isAbsolute(storage) ||
    storage.includes("\0")
  )
    throw Error("FACT native storage root must be absolute");
  const credentials = ["rw_pw", "ro_pw", "del_pw", "admin_pw"].flatMap((key) =>
    typeof postgres[key] === "string" && postgres[key].length
      ? [postgres[key]]
      : [],
  );
  const credential = (value: unknown, key: string) => {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      const selected = table(value)[key];
      if (typeof selected === "string" && selected.length)
        credentials.push(selected);
    }
  };
  credential(common.redis, "password");
  if (source.frontend !== undefined) {
    const frontend = table(source.frontend);
    credential(frontend.authentication, "password_salt");
    credential(frontend.hasura, "admin_secret");
  }
  return {
    projection: {
      postgres: {
        source: server,
        effective: isAbsolute(server) ? server : "/var/run/postgresql",
        port,
        database,
        transport: "unix-socket" as const,
      },
      storage_root: storage,
    },
    credentials,
  };
}
