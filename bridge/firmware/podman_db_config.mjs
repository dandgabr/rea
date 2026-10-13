import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { constants } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const [snapshot, expectedDigest, rawSize] = process.argv.slice(2);
if (
  snapshot === undefined ||
  expectedDigest === undefined ||
  !/^[a-f0-9]{64}$/u.test(expectedDigest) ||
  rawSize === undefined ||
  !/^[1-9][0-9]*$/u.test(rawSize)
)
  throw Error("Invalid fixed snapshot admission arguments");
const identify = async () => {
  const handle = await open(
    snapshot,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size.toString() !== rawSize)
      throw Error("Private snapshot source size differs");
    const hash = createHash("sha256");
    let bytes = 0;
    for await (const chunk of handle.createReadStream({
      autoClose: false,
      highWaterMark: 64 * 1024,
    })) {
      bytes += chunk.length;
      if (bytes > Number(rawSize)) throw Error("Private snapshot grew");
      hash.update(chunk);
    }
    const after = await handle.stat({ bigint: true });
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      hash.digest("hex") !== expectedDigest ||
      bytes !== Number(rawSize)
    )
      throw Error("Private snapshot identity changed");
  } finally {
    await handle.close();
  }
};

await identify();
const db = new DatabaseSync(snapshot, {
  readOnly: true,
  allowExtension: false,
  readBigInts: true,
  enableDoubleQuotedStringLiterals: false,
  timeout: 0,
  limits: {
    length: 64 * 1024,
    sqlLength: 4096,
    column: 16,
    attached: 0,
    triggerDepth: 0,
  },
});
let result;
try {
  if (
    db.limits.length > 64 * 1024 ||
    db.limits.sqlLength > 4096 ||
    db.limits.column > 16
  )
    throw Error("SQLite bounded representation is unavailable");
  db.exec(
    "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; PRAGMA mmap_size=0; PRAGMA cache_size=-2048;",
  );
  result = {
    snapshot_sha256: expectedDigest,
    tables: db
      .prepare(
        "SELECT type, sql FROM sqlite_schema WHERE name='DBConfig' LIMIT 2",
      )
      .all(),
    configuration: db
      .prepare(
        "SELECT ID, SchemaVersion, OS, StaticDir, TmpDir, GraphRoot, RunRoot, GraphDriver, VolumeDir FROM DBConfig LIMIT 2",
      )
      .all(),
  };
} finally {
  db.close();
}
await identify();
process.stdout.write(
  JSON.stringify(result, (_key, value) =>
    typeof value === "bigint" ? { integer: value.toString() } : value,
  ) + "\n",
);
