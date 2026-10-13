import { createHash } from "node:crypto";
import { ZipReader, Uint8ArrayReader, Writer } from "@zip.js/zip.js";
import { FactJsonParser } from "./FactJsonParser.js";
import { FACT_LIMITS, factHash } from "./FactProtocol.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { z } from "zod";
import { corpusUidSchema } from "../../domain/corpus/firmwareCorpus.js";

const object = (value: unknown): value is Record<string, JsonValue> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const nativeObject = z.object({
  uid: corpusUidSchema,
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  size: z.number().int().nonnegative(),
  file_name: z.string(),
  files_included: z.array(corpusUidSchema),
  virtual_file_path: z.record(corpusUidSchema, z.array(z.string())),
  processed_analysis: z.custom<Record<string, JsonValue>>(object),
  comments: z.array(z.custom<Record<string, JsonValue>>(object)),
  depth: z.number().int().nonnegative(),
});
export class FactArchiveFailure extends Error {
  constructor(
    message: string,
    readonly partial: {
      members: FactArchivePreflight["members"];
      producer_metadata: JsonValue;
      data_sha256: string;
      expanded_bytes: number;
    },
    cause: unknown,
  ) {
    super(message, { cause });
  }
}

function validateGraph(
  metadata: Record<string, JsonValue>,
  members: FactArchivePreflight["members"],
) {
  const root = nativeObject.parse(metadata.firmware);
  if (root.uid !== metadata.uid || !Array.isArray(metadata.files))
    throw Error("FACT archive root identity contradicts metadata UID");
  const nodes = new Map([[root.uid, root]]);
  const binaries = new Map(members.map((member) => [member.uid, member]));
  const duplicates = new Set<string>();
  const effectiveSelection: Record<string, number> = {};
  for (const [index, item] of metadata.files.entries()) {
    const node = nativeObject.parse(item);
    if (node.uid === root.uid)
      throw Error("FACT archive firmware root occurs as a child object");
    const member = binaries.get(node.uid);
    if (
      member === undefined ||
      node.sha256 !== member.sha256 ||
      node.size !== member.size ||
      `${node.sha256}_${node.size}` !== node.uid
    )
      throw Error(
        "FACT archive object occurrence UID, SHA256 or size contradicts binary bytes",
      );
    if (nodes.has(node.uid)) duplicates.add(node.uid);
    // Native FwImporter._import_objects dictionary comprehension selects the
    // final metadata occurrence. Keep the original ordered source untouched.
    nodes.set(node.uid, node);
    effectiveSelection[node.uid] = index;
  }
  if (nodes.size !== members.length)
    throw Error("FACT archive undeclared or missing binary members");
  for (const member of members) {
    const node = nodes.get(member.uid);
    if (
      node === undefined ||
      node.sha256 !== member.sha256 ||
      node.size !== member.size ||
      `${member.sha256}_${member.size}` !== member.uid
    )
      throw Error(
        "FACT archive binary UID, SHA256 or size contradicts object metadata",
      );
  }
  for (const node of nodes.values())
    if (node.files_included.some((uid) => !nodes.has(uid)))
      throw Error(
        "FACT archive included-file graph references an undeclared object",
      );
  const all = new Set(nodes.keys());
  const ignored = [...nodes.values()]
    .filter(
      (node) =>
        node.uid !== root.uid &&
        Object.keys(node.virtual_file_path).some((parent) => !all.has(parent)),
    )
    .map((node) => node.uid);
  const ignoredSet = new Set(ignored);
  const remaining = new Map(
    [...nodes].filter(([uid]) => uid !== root.uid && !ignoredSet.has(uid)),
  );
  const successors = new Map<string, string[]>();
  const degrees = new Map<string, number>();
  const ready: string[] = [];
  for (const node of remaining.values()) {
    const parents = Object.keys(node.virtual_file_path).filter(
      (parent) => parent !== root.uid,
    );
    if (parents.some((parent) => !remaining.has(parent)))
      throw Error("FACT archive unresolved parent after native orphan pruning");
    degrees.set(node.uid, parents.length);
    if (!parents.length) ready.push(node.uid);
    for (const parent of parents) {
      const children = successors.get(parent) ?? [];
      children.push(node.uid);
      successors.set(parent, children);
    }
  }
  let visited = 0;
  while (ready.length) {
    const uid = ready.pop()!;
    visited++;
    for (const child of successors.get(uid) ?? []) {
      const degree = degrees.get(child)! - 1;
      degrees.set(child, degree);
      if (!degree) ready.push(child);
    }
  }
  if (visited !== remaining.size)
    throw Error("FACT archive parent graph contains a cycle");
  return {
    objectCount: nodes.size,
    ignored,
    duplicates: [...duplicates],
    effectiveSelection,
  };
}

export interface FactArchivePreflight {
  uid: string;
  db_revision: string;
  binary_bytes: number;
  expanded_bytes: number;
  object_count: number;
  ignored_orphans: string[];
  duplicate_object_uids: string[];
  effective_object_selection: Record<string, number>;
  members: { path: string; uid: string; sha256: string; size: number }[];
  data_sha256: string;
  metadata: JsonValue;
}

/** Read members under actual expansion accounting; no archive path is extracted. */
export async function preflightFactArchive(
  bytes: Buffer,
  parser: FactJsonParser,
  signal: AbortSignal,
  budget: {
    bytes: number;
    entries: number;
    metadataBytes?: number;
    archiveBytes?: number;
    retainCleanup?: (owner: { path: string; close(): Promise<void> }) => void;
  },
): Promise<FactArchivePreflight> {
  signal.throwIfAborted();
  if (bytes.length > (budget.archiveBytes ?? FACT_LIMITS.rawBytes))
    throw Error("FACT archive exceeds input byte budget");
  const reader = new ZipReader(new Uint8ArrayReader(bytes), {
    useWebWorkers: false,
    checkCrc32: true,
    checkOverlappingEntry: true,
    filenameValidation: "tolerant",
  });
  let expanded = 0;
  let metadata: JsonValue = null;
  let dataDigest = "";
  const members: FactArchivePreflight["members"] = [];
  const paths = new Set<string>();
  try {
    for await (const entry of reader.getEntriesGenerator()) {
      signal.throwIfAborted();
      const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
      if (
        entry.directory ||
        (mode !== 0 && mode !== 0o100000) ||
        entry.encrypted
      )
        throw Error(
          "FACT archive requires unencrypted regular members; links and special entries are rejected",
        );
      if (
        entry.filename !== "data.json" &&
        !/^files\/[a-f0-9]{64}_(?:0|[1-9][0-9]*)$/u.test(entry.filename)
      )
        throw Error(
          "FACT archive member path is not declared by the native format",
        );
      if (paths.has(entry.filename))
        throw Error("FACT archive duplicate member path");
      paths.add(entry.filename);
      if (paths.size > budget.entries)
        throw Error("FACT archive entry budget exceeded");
      if (
        !Number.isSafeInteger(entry.uncompressedSize) ||
        entry.uncompressedSize < 0 ||
        expanded + entry.uncompressedSize > budget.bytes
      )
        throw Error("FACT archive declared expansion exceeds byte budget");
      if (
        entry.filename === "data.json" &&
        entry.uncompressedSize > (budget.metadataBytes ?? FACT_LIMITS.jsonBytes)
      )
        throw Error("FACT archive declared metadata exceeds JSON budget");
      const hash = createHash("sha256");
      const chunks: Buffer[] = [];
      let size = 0;
      class MemberWriter extends Writer<void> {
        override async writeUint8Array(chunk: Uint8Array) {
          signal.throwIfAborted();
          size += chunk.length;
          expanded += chunk.length;
          if (expanded > budget.bytes)
            throw Error("FACT archive expansion exceeds byte budget");
          hash.update(chunk);
          if (entry.filename === "data.json") {
            if (size > (budget.metadataBytes ?? FACT_LIMITS.jsonBytes))
              throw Error("FACT archive metadata exceeds JSON budget");
            chunks.push(Buffer.from(chunk));
          }
        }
        override async getData() {}
      }
      await entry.getData(new MemberWriter(), { signal });
      if (size !== entry.uncompressedSize)
        throw Error("FACT archive member size disagrees with actual bytes");
      const digest = hash.digest("hex");
      if (entry.filename === "data.json") {
        dataDigest = digest;
        const owned = Buffer.allocUnsafeSlow(size);
        let at = 0;
        for (const chunk of chunks) {
          chunk.copy(owned, at);
          at += chunk.length;
        }
        metadata = (await parser.parse(owned, false, signal)).data;
      } else
        members.push({
          path: entry.filename,
          uid: entry.filename.slice(6),
          sha256: digest,
          size,
        });
    }
    if (
      !object(metadata) ||
      !corpusUidSchema.safeParse(metadata.uid).success ||
      typeof metadata.db_revision !== "string" ||
      !metadata.db_revision.length ||
      !Array.isArray(metadata.files) ||
      !paths.has("data.json")
    )
      throw Error("FACT archive requires native data.json fields");
    const graph = validateGraph(metadata, members);
    return {
      uid: corpusUidSchema.parse(metadata.uid),
      db_revision: metadata.db_revision,
      binary_bytes: members.reduce((sum, item) => sum + item.size, 0),
      expanded_bytes: expanded,
      object_count: graph.objectCount,
      ignored_orphans: graph.ignored,
      duplicate_object_uids: graph.duplicates,
      effective_object_selection: graph.effectiveSelection,
      members,
      data_sha256: dataDigest,
      metadata,
    };
  } catch (cause) {
    throw new FactArchiveFailure(
      cause instanceof Error ? cause.message : String(cause),
      {
        members,
        producer_metadata: metadata,
        data_sha256: dataDigest,
        expanded_bytes: expanded,
      },
      cause,
    );
  } finally {
    try {
      await reader.close();
    } catch (cause) {
      budget.retainCleanup?.({
        path: "FACT ZIP preflight reader",
        close: () => reader.close(),
      });
      if (budget.retainCleanup === undefined) throw cause;
    }
  }
}
