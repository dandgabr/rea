import { z } from "zod";
import { isDeepStrictEqual } from "node:util";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  corpusUidSchema,
  firmwareCorpusInputs,
  type FirmwareCorpusInput,
  type FirmwareCorpusOperation,
} from "../../domain/corpus/firmwareCorpus.js";

const envelope = z.object({
  status: z.literal(0),
  timestamp: z.number().int(),
  request_resource: z.string(),
});
const errorEnvelope = envelope.extend({
  status: z.literal(1),
  error_message: z.string(),
});
// The owned parser has already established JSON meaning. Structural checks must
// not clone arbitrary plugin payloads just to decide the selected route shape.
const isObject = (value: unknown): value is Record<string, JsonValue> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const producerObject = z.custom<Record<string, JsonValue>>(isObject);
const records = z.custom<Record<string, Record<string, JsonValue>>>((value) => {
  if (!isObject(value)) return false;
  for (const key in value) if (!isObject(value[key])) return false;
  return true;
});
const uidLists = z.record(z.string(), z.array(corpusUidSchema));
const nativeAnalysis = z.object({
  analysis_date: z.number().finite(),
  plugin_version: z.string(),
  system_version: z.string().nullable(),
  summary: z.array(z.string()),
  tags: producerObject,
  result: producerObject,
});
const commonObjectMetadata = z.object({
  hid: z.string(),
  size: z.number().int().nonnegative(),
  number_of_included_files: z.number().int().nonnegative(),
  included_files: z.array(corpusUidSchema),
  total_files_in_firmware: z.union([
    z.literal("unknown"),
    z.number().int().nonnegative(),
  ]),
});
const firmwareMetadata = commonObjectMetadata.extend({
  device_name: z.string().nullable(),
  device_class: z.string().nullable(),
  device_part: z.string(),
  vendor: z.string().nullable(),
  version: z.string().nullable(),
  release_date: z.string().nullable(),
});
const fileMetadata = commonObjectMetadata.extend({
  firmwares_including_this_file: z.array(corpusUidSchema),
  virtual_file_path: z.record(corpusUidSchema, z.array(z.string())),
});
const schemas = {
  inspect_firmware_corpus: envelope.extend({
    system_status: z.object({
      frontend: producerObject.nullable(),
      database: producerObject.nullable(),
      backend: producerObject.nullable(),
    }),
    plugins: z.record(
      z.string(),
      z.object({ description: z.string(), version: z.string() }),
    ),
  }),
  search_corpus_objects: envelope.extend({ uids: z.array(corpusUidSchema) }),
  inspect_corpus_analysis: envelope.extend({ analysis: nativeAnalysis }),
  upload_corpus_firmware: envelope.extend({ uid: corpusUidSchema }),
  reanalyze_corpus_firmware: envelope.extend({
    request: z.object({ uid: corpusUidSchema, update: z.array(z.string()) }),
  }),
  enqueue_corpus_analysis: envelope.extend({ success: z.literal(true) }),
  start_corpus_comparison: envelope.extend({ message: z.string().min(1) }),
  inspect_corpus_comparison: envelope.extend({
    general: z.object({ hid: z.record(corpusUidSchema, z.string()) }),
    _id: z.string(),
    submission_date: z.number().finite(),
  }),
  start_corpus_yara: envelope.extend({
    message: z.string().min(1),
    request: z.object({ search_id: z.string().min(1) }),
  }),
  collect_corpus_yara: envelope.extend({ binary_search_results: uidLists }),
  inspect_corpus_gaps: envelope.extend({
    missing_analyses: z.record(z.string(), z.array(z.string())),
    failed_analyses: z.record(z.string(), z.array(z.string())),
  }),
  download_corpus_binary: envelope.extend({
    binary: z.string(),
    file_name: z.string(),
    SHA256: z.string().regex(/^[a-f0-9]{64}$/u),
  }),
  delete_corpus_firmware: envelope.extend({
    deleted_files: z.number().int().nonnegative(),
  }),
};

/** Native echoes describe the selection, never an independent target authority. */
function contradictoryRequest(
  operation: FirmwareCorpusOperation,
  input: FirmwareCorpusInput,
  data: JsonValue,
): string | undefined {
  // Statistics are a raw data dictionary, without an envelope/request namespace.
  if (
    operation === "inspect_corpus_statistics" ||
    !isObject(data) ||
    !isObject(data.request)
  )
    return undefined;
  const request = data.request;
  const expected: Record<string, JsonValue> = {};
  if ("uid" in input && input.uid !== undefined) expected.uid = input.uid;
  if ("plugin" in input) expected.plugin = input.plugin;
  if ("repacked" in input) expected.tar = input.repacked;
  if ("search_id" in input) expected.search_id = input.search_id;
  if (operation === "search_corpus_objects" && "query" in input) {
    expected.query = input.query;
    expected.offset = input.offset;
    expected.limit = input.limit;
    if (input.kind === "firmware") {
      expected.recursive = input.recursive;
      expected.inverted = input.inverted;
    }
  }
  if (
    operation === "start_corpus_comparison" &&
    "uids" in input &&
    "redo" in input
  ) {
    expected.uid_list = input.uids;
    expected.redo = input.redo;
  }
  if (operation === "inspect_corpus_comparison" && "uids" in input)
    expected.compare_id = [...input.uids].sort().join(";");
  if (
    operation === "upload_corpus_firmware" &&
    "metadata" in input &&
    "plugins" in input
  ) {
    Object.assign(expected, input.metadata);
    expected.requested_analysis_systems = input.plugins;
    // The returned UID and any binary echo are checked against the snapshot by
    // the adapter that owns it, rather than reconstructed from a local path.
  }
  for (const key of Object.keys(expected))
    if (
      Object.hasOwn(request, key) &&
      !isDeepStrictEqual(request[key], expected[key])
    )
      return `Native request.${key} contradicts the caller's selected ${operation}`;
  if (
    operation === "reanalyze_corpus_firmware" &&
    "plugins" in input &&
    "re_unpack" in input &&
    Object.hasOwn(request, "update")
  ) {
    const actual = request.update;
    const effective = [
      ...input.plugins,
      ...(input.re_unpack && data.status === 0 ? ["unpacker"] : []),
    ];
    // FACT removes every unpacker occurrence, schedules plugins, and appends one
    // unpacker on successful unpack requests. Plugin-validation errors precede
    // that append. Compare selection/multiplicity, not ordering.
    if (
      !Array.isArray(actual) ||
      !isDeepStrictEqual([...actual].sort(), effective.sort())
    )
      return "Native request.update contradicts the selected plugins/re_unpack";
  }
  return undefined;
}

/** Validate the selected producer representation before asserting job or fact completion. */
export function validateFactProducerResponse(
  operation: FirmwareCorpusOperation,
  input: FirmwareCorpusInput,
  data: JsonValue,
  httpStatus: number,
) {
  const resource =
    operation === "inspect_corpus_parent_analysis" && "plugin" in input
      ? `/plugins/${input.plugin}/rest/<uid>`
      : operation === "inspect_corpus_object" ||
          operation === "search_corpus_objects"
        ? "kind" in input && input.kind === "file"
          ? "/rest/file_object"
          : "/rest/firmware"
        : operation === "upload_corpus_firmware" ||
            operation === "reanalyze_corpus_firmware" ||
            operation === "delete_corpus_firmware"
          ? "/rest/firmware"
          : operation === "inspect_corpus_analysis" ||
              operation === "enqueue_corpus_analysis"
            ? "/rest/analysis"
            : operation === "inspect_corpus_comparison" ||
                operation === "start_corpus_comparison"
              ? "/rest/compare"
              : operation === "collect_corpus_yara" ||
                  operation === "start_corpus_yara"
                ? "/rest/binary_search"
                : operation === "inspect_firmware_corpus"
                  ? "/rest/status"
                  : operation === "inspect_corpus_gaps"
                    ? "/rest/missing"
                    : operation === "inspect_corpus_statistics"
                      ? "/rest/statistics"
                      : "/rest/binary";
  const error = errorEnvelope.safeParse(data);
  const contradiction = contradictoryRequest(operation, input, data);
  if (contradiction !== undefined)
    return {
      state: "unknown" as const,
      diagnostics: [contradiction],
      collectionDisposition: "retain" as const,
    };
  if (error.success && error.data.request_resource === resource)
    return {
      state: "failed" as const,
      diagnostics: [],
      collectionDisposition:
        operation === "collect_corpus_yara" &&
        httpStatus === 400 &&
        error.data.error_message ===
          "The result is not ready yet or it has already been fetched"
          ? ("explicit-reattempt" as const)
          : ("retain" as const),
    };
  if (httpStatus < 200 || httpStatus >= 300)
    return {
      state: "failed" as const,
      diagnostics: [
        "HTTP request was rejected; producer response does not establish requested facts",
      ],
      collectionDisposition: "retain" as const,
    };
  let valid = false;
  if (operation === "inspect_corpus_statistics") {
    const statistics = records.safeParse(data);
    const categories =
      "category" in input && input.category !== undefined
        ? [input.category]
        : firmwareCorpusInputs.inspect_corpus_statistics.shape.category.unwrap()
            .options;
    valid =
      statistics.success &&
      categories.every((category) => Object.hasOwn(statistics.data, category));
  } else if (operation === "inspect_corpus_object" && "kind" in input) {
    valid = envelope
      .extend({
        [input.kind === "file" ? "file_object" : "firmware"]: z.object({
          meta_data: input.kind === "file" ? fileMetadata : firmwareMetadata,
          analysis: records,
        }),
      })
      .safeParse(data).success;
  } else if (
    operation === "inspect_corpus_parent_analysis" &&
    "plugin" in input
  ) {
    valid = envelope
      .extend({
        [input.plugin]:
          input.plugin === "file_system_metadata"
            ? z.array(producerObject)
            : records,
      })
      .safeParse(data).success;
  } else if (operation in schemas) {
    const schema = schemas[operation as keyof typeof schemas];
    valid = schema.safeParse(data).success;
  }
  if (operation !== "inspect_corpus_statistics")
    valid =
      valid &&
      data !== null &&
      typeof data === "object" &&
      !Array.isArray(data) &&
      data.request_resource === resource;
  if (
    valid &&
    operation === "inspect_corpus_object" &&
    "kind" in input &&
    "uid" in input &&
    isObject(data)
  ) {
    const object = data[input.kind === "file" ? "file_object" : "firmware"];
    if (isObject(object) && isObject(object.meta_data))
      valid =
        typeof object.meta_data.size === "number" &&
        BigInt(object.meta_data.size) === BigInt(input.uid.split("_")[1]!);
  }
  if (
    valid &&
    operation === "inspect_corpus_comparison" &&
    "uids" in input &&
    data !== null &&
    typeof data === "object" &&
    !Array.isArray(data)
  )
    valid = data._id === [...input.uids].sort().join(";");
  return {
    state: valid
      ? [
          "upload_corpus_firmware",
          "reanalyze_corpus_firmware",
          "enqueue_corpus_analysis",
          "start_corpus_comparison",
          "start_corpus_yara",
        ].includes(operation)
        ? ("accepted" as const)
        : ("completed" as const)
      : ("unknown" as const),
    diagnostics: valid
      ? []
      : [
          `Malformed ${operation} producer response; requested facts or acknowledgement remain unknown`,
        ],
    collectionDisposition: "retain" as const,
  };
}
