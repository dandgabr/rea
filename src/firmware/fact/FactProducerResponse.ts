import { z } from "zod";
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
