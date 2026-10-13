import { expect, it } from "vitest";
import { ZipWriter, Uint8ArrayWriter, Uint8ArrayReader } from "@zip.js/zip.js";
import { FactJsonParser } from "./FactJsonParser.js";
import { factHash, factUid } from "./FactProtocol.js";
import { preflightFactArchive, FactArchiveFailure } from "./FactArchive.js";

const rootBytes = Buffer.from("firmware");
const childBytes = Buffer.from("child");
const uid = factUid(rootBytes);
const child = factUid(childBytes);
const object = (bytes: Buffer, parents: string[] = []) => ({
  uid: factUid(bytes),
  sha256: factHash(bytes),
  size: bytes.length,
  file_name: "synthetic.bin",
  files_included: [],
  virtual_file_path: Object.fromEntries(
    parents.map((parent) => [parent, ["synthetic.bin"]]),
  ),
  processed_analysis: {},
  comments: [],
  depth: parents.length,
});
const data = () => ({
  db_revision: "test-revision",
  uid,
  firmware: {
    ...object(rootBytes),
    files_included: [child],
    device_class: "test",
    device_name: "test",
    vendor: "test",
    version: "1",
    part: "",
    release_date: "1970-01-01",
    tags: {},
  },
  files: [object(childBytes, [uid])],
});
async function archive(
  metadata: unknown,
  extra?: {
    name: string;
    bytes: Buffer;
    options?: Parameters<ZipWriter<Uint8Array>["add"]>[2];
  },
) {
  const writer = new ZipWriter(new Uint8ArrayWriter(), {
    useWebWorkers: false,
  });
  await writer.add(
    "data.json",
    new Uint8ArrayReader(
      Buffer.isBuffer(metadata)
        ? metadata
        : Buffer.from(JSON.stringify(metadata)),
    ),
  );
  await writer.add(`files/${uid}`, new Uint8ArrayReader(rootBytes));
  await writer.add(`files/${child}`, new Uint8ArrayReader(childBytes));
  if (extra)
    await writer.add(
      extra.name,
      new Uint8ArrayReader(extra.bytes),
      extra.options,
    );
  return Buffer.from(await writer.close());
}
async function inspect(bytes: Buffer, budget = 256 * 1024 * 1024) {
  const parser = new FactJsonParser();
  try {
    return await preflightFactArchive(
      bytes,
      parser,
      new AbortController().signal,
      { bytes: budget, entries: 10_000 },
    );
  } finally {
    await parser.close();
  }
}
it("verifies native member bytes, revision and unordered parent graph without extracting paths", async () => {
  const result = await inspect(await archive(data()));
  expect(result).toMatchObject({
    uid,
    db_revision: "test-revision",
    binary_bytes: 13,
    ignored_orphans: [],
    object_count: 2,
  });
  expect(result.members).toEqual(
    expect.arrayContaining([
      {
        path: `files/${uid}`,
        uid,
        sha256: factHash(rootBytes),
        size: rootBytes.length,
      },
      {
        path: `files/${child}`,
        uid: child,
        sha256: factHash(childBytes),
        size: childBytes.length,
      },
    ]),
  );
});
it("rejects traversal, encrypted, symlink and undeclared members before import", async () => {
  for (const extra of [
    { name: "../escape", bytes: Buffer.from("x") },
    { name: "unexpected", bytes: Buffer.from("x") },
    {
      name: "files/link",
      bytes: Buffer.from("../outside"),
      options: { externalFileAttributes: 0o120777 << 16 },
    },
    {
      name: "encrypted",
      bytes: Buffer.from("x"),
      options: { password: "test", zipCrypto: true },
    },
  ])
    await expect(inspect(await archive(data(), extra))).rejects.toThrow();
});
it("rejects binary/object UID, digest and size contradictions", async () => {
  for (const patch of [
    { uid: child },
    { sha256: "0".repeat(64) },
    { size: 1 },
  ]) {
    const metadata = data();
    Object.assign(metadata.firmware, patch);
    await expect(inspect(await archive(metadata))).rejects.toThrow();
  }
  const metadata = data();
  metadata.files[0]!.uid = uid;
  await expect(inspect(await archive(metadata))).rejects.toThrow();
});
it("rejects cyclic and unresolved descendants after native one-pass orphan pruning", async () => {
  const cyclic = data();
  cyclic.files[0]!.virtual_file_path = { [child]: ["self"] };
  await expect(inspect(await archive(cyclic))).rejects.toThrow(
    /graph|parent|cycle/iu,
  );
  const orphan = data();
  orphan.files[0]!.virtual_file_path = {
    ["f".repeat(64) + "_1"]: ["external"],
  };
  const accepted = await inspect(await archive(orphan));
  expect(accepted.ignored_orphans).toEqual([child]);
  const descendantBytes = Buffer.from("descendant");
  const descendant = object(descendantBytes, [child]);
  orphan.files.push(descendant);
  const bytes = await archive(orphan, {
    name: `files/${descendant.uid}`,
    bytes: descendantBytes,
  });
  await expect(inspect(bytes)).rejects.toThrow(/graph|parent|unresolved/iu);
});
it("bounds aggregate actual decompressed bytes independently of compressed archive size", async () => {
  const bytes = await archive(data());
  const metadataBytes = Buffer.byteLength(JSON.stringify(data()));
  const exact = rootBytes.length + childBytes.length + metadataBytes;
  await expect(inspect(bytes, exact)).resolves.toMatchObject({
    expanded_bytes: exact,
  });
  await expect(inspect(bytes, exact - 1)).rejects.toThrow(/budget|bytes/iu);
});
it("rejects a forged central CRC even when actual member SHA256 and metadata remain correct", async () => {
  const positive = await archive(data());
  await expect(inspect(positive)).resolves.toMatchObject({ uid });
  const forged = Buffer.from(positive);
  let central = -1;
  for (let at = 0; at + 46 < forged.length; at++) {
    if (forged.readUInt32LE(at) !== 0x02014b50) continue;
    const name = forged
      .subarray(at + 46, at + 46 + forged.readUInt16LE(at + 28))
      .toString("utf8");
    if (name === `files/${uid}`) {
      central = at;
      break;
    }
  }
  expect(central).toBeGreaterThan(0);
  forged.writeUInt32LE(
    (forged.readUInt32LE(central + 16) ^ 1) >>> 0,
    central + 16,
  );
  await expect(inspect(forged)).rejects.toThrow(/CRC|signature|invalid/iu);
});
it("preserves native duplicate object occurrences and applies the producer's last occurrence graph", async () => {
  const metadata = data();
  metadata.files.push({ ...metadata.files[0]!, virtual_file_path: {} });
  const result = await inspect(await archive(metadata));
  expect(result).toMatchObject({
    object_count: 2,
    duplicate_object_uids: [child],
    effective_object_selection: { [child]: 1 },
  });
  expect(result.metadata).toEqual(metadata);
  const cyclic = data();
  cyclic.files.push({
    ...cyclic.files[0]!,
    virtual_file_path: { [child]: ["self"] },
  });
  await expect(inspect(await archive(cyclic))).rejects.toThrow(/cycle/iu);
  const earlier = data();
  earlier.files.push({ ...earlier.files[0]!, virtual_file_path: {} });
  earlier.files[0]!.sha256 = "0".repeat(64);
  await expect(inspect(await archive(earlier))).rejects.toThrow(
    /occurrence|digest|SHA/iu,
  );
});
it("retains verified binary hashes and producer metadata when native DB export omits an object", async () => {
  const metadata = data();
  metadata.files = [];
  const failure: unknown = await inspect(await archive(metadata)).catch(
    (cause: unknown) => cause,
  );
  expect(failure).toBeInstanceOf(FactArchiveFailure);
  if (!(failure instanceof FactArchiveFailure))
    throw Error("Missing owned partial archive observation");
  expect(failure.partial.members).toContainEqual({
    path: `files/${child}`,
    uid: child,
    sha256: factHash(childBytes),
    size: childBytes.length,
  });
  expect(failure.partial.producer_metadata).toEqual(metadata);
});
it("rejects special member mode independently of declared name, CRC and SHA identity", async () => {
  const positive = await archive(data());
  const special = Buffer.from(positive);
  for (let at = 0; at + 46 < special.length; at++) {
    if (special.readUInt32LE(at) !== 0x02014b50) continue;
    const name = special
      .subarray(at + 46, at + 46 + special.readUInt16LE(at + 28))
      .toString("utf8");
    if (name === `files/${uid}`)
      special.writeUInt32LE((0o120777 << 16) >>> 0, at + 38);
  }
  await expect(inspect(positive)).resolves.toMatchObject({ uid });
  await expect(inspect(special)).rejects.toThrow(/regular|links|special/iu);
});
it("rejects duplicate central-directory member paths before native import can select an alias", async () => {
  const duplicate = await archive(data());
  let changed = false;
  for (let at = 0; at + 46 < duplicate.length; at++) {
    if (duplicate.readUInt32LE(at) !== 0x02014b50) continue;
    const name = duplicate.subarray(
      at + 46,
      at + 46 + duplicate.readUInt16LE(at + 28),
    );
    if (name.toString("utf8") === `files/${child}`) {
      name.set(Buffer.from(`files/${uid}`));
      changed = true;
    }
  }
  expect(changed).toBe(true);
  await expect(inspect(duplicate)).rejects.toThrow(/duplicate member path/iu);
});
it("runs bounded seeded metadata/graph/UTF8/duplicate-key fuzz with independent rejection and ownership oracles", async () => {
  let seed = 0xfac70002;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return seed >>> 0;
  };
  const parser = new FactJsonParser();
  let rejected = 0,
    controls = 0;
  try {
    for (let index = 0; index < 40; index++) {
      const metadata = data();
      let source: unknown = metadata;
      switch (next() % 5) {
        case 0:
          metadata.firmware.sha256 = next().toString(16).padStart(64, "0");
          break;
        case 1:
          metadata.files[0]!.size = childBytes.length + 1 + (next() % 16);
          break;
        case 2:
          metadata.files[0]!.virtual_file_path = {
            [child]: [`cycle-${next()}`],
          };
          break;
        case 3:
          source = Buffer.concat([
            Buffer.from(JSON.stringify(metadata)),
            Buffer.from([0xff]),
          ]);
          break;
        case 4:
          source = Buffer.from(
            JSON.stringify(metadata).replace(
              '"db_revision":',
              '"db_revision":"duplicate","db_revision":',
            ),
          );
          break;
      }
      await expect(
        preflightFactArchive(
          await archive(source),
          parser,
          new AbortController().signal,
          { bytes: 4096, entries: 3 },
        ),
      ).rejects.toThrow();
      expect(parser.pendingResources).toEqual([]);
      rejected++;
      if (index % 8 === 0) {
        const valid = await preflightFactArchive(
          await archive(data()),
          parser,
          new AbortController().signal,
          { bytes: 4096, entries: 3 },
        );
        expect(
          valid.members.find((member) => member.uid === child)?.sha256,
        ).toBe(factHash(childBytes));
        expect(
          valid.members.reduce((sum, member) => sum + member.size, 0),
        ).toBe(13);
        controls++;
      }
    }
    expect({ rejected, controls }).toEqual({ rejected: 40, controls: 5 });
  } finally {
    await parser.close();
  }
}, 10000);

it("rejects local-header names that contradict central member identity while retaining prior verified facts", async () => {
  const positive = await archive(data());
  expect((await inspect(positive)).members).toHaveLength(2);
  const forged = Buffer.from(positive);
  const localName = forged.indexOf(Buffer.from(`files/${child}`));
  expect(forged.readUInt32LE(localName - 30)).toBe(0x04034b50);
  forged[localName + 6] = forged[localName + 6] === 48 ? 49 : 48;
  const cause: unknown = await inspect(forged).catch(
    (failure: unknown) => failure,
  );
  expect(cause).toBeInstanceOf(FactArchiveFailure);
  if (!(cause instanceof FactArchiveFailure))
    throw Error("Missing archive failure");
  expect(cause.partial.producer_metadata).toEqual(data());
  expect(cause.partial.members).toContainEqual({
    path: `files/${uid}`,
    uid,
    sha256: factHash(rootBytes),
    size: rootBytes.length,
  });
});

it("runs bounded seeded local-header identity contradictions without altering central UID or member bytes", async () => {
  const positive = await archive(data());
  let seed = 0xfac70005;
  const parser = new FactJsonParser();
  try {
    for (let index = 0; index < 24; index++) {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      const forged = Buffer.from(positive);
      const localName = forged.indexOf(Buffer.from(`files/${child}`));
      const offset = localName + 6 + ((seed >>> 0) % 64);
      forged[offset] = forged[offset] === 48 ? 49 : 48;
      expect(forged.lastIndexOf(Buffer.from(`files/${child}`))).toBe(
        positive.lastIndexOf(Buffer.from(`files/${child}`)),
      );
      await expect(
        preflightFactArchive(forged, parser, new AbortController().signal, {
          bytes: 4096,
          entries: 3,
        }),
      ).rejects.toThrow();
      expect(parser.pendingResources).toEqual([]);
    }
    expect(
      (
        await preflightFactArchive(
          positive,
          parser,
          new AbortController().signal,
          { bytes: 4096, entries: 3 },
        )
      ).members.find((member) => member.uid === child)?.sha256,
    ).toBe(factHash(childBytes));
  } finally {
    await parser.close();
  }
});
