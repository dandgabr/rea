import { podmanProfileUnavailable } from "./PodmanProfileFiles.js";

export interface PodmanMountEntry {
  readonly id: number;
  readonly parent: number;
  readonly device: string;
  readonly root: string;
  readonly destination: string;
  readonly options: readonly string[];
  readonly optional: readonly string[];
  readonly filesystem: string;
  readonly source: string;
  readonly super_options: readonly string[];
}
const mountPath = (field: string) => {
  if (/\\(?!040|011|012|134)/u.test(field))
    throw podmanProfileUnavailable("Unsupported mountinfo path escape");
  return field.replace(/\\(040|011|012|134)/gu, (_, code: string) =>
    String.fromCharCode(Number.parseInt(code, 8)),
  );
};
const numeric = (field: string | undefined) => {
  if (
    field === undefined ||
    !/^[1-9][0-9]*$/u.test(field) ||
    !Number.isSafeInteger(Number(field))
  )
    throw podmanProfileUnavailable("Invalid mountinfo identity");
  return Number(field);
};

/** Linux proc mountinfo has escaped fields and may contain multiple stacked mounts at one destination. */
export const parsePodmanMountInfo = (
  text: string,
): readonly PodmanMountEntry[] => {
  if (
    Buffer.byteLength(text) > 8 * 1024 * 1024 ||
    text.includes("\0") ||
    !text.endsWith("\n")
  )
    throw podmanProfileUnavailable(
      "Incomplete or oversized prepared mountinfo",
    );
  const lines = text.slice(0, -1).split("\n");
  if (lines.length > 10_000)
    throw podmanProfileUnavailable(
      "Prepared mountinfo exceeds its 10000-entry projection budget",
    );
  const ids = new Set<number>();
  return lines.map((line) => {
    const fields = line.split(" ");
    const separator = fields.indexOf("-");
    if (
      fields.some((field) => field === "") ||
      separator < 6 ||
      fields.length !== separator + 4 ||
      !/^[0-9]+:[0-9]+$/u.test(fields[2] ?? "")
    )
      throw podmanProfileUnavailable("Malformed prepared mountinfo");
    const id = numeric(fields[0]);
    if (ids.has(id))
      throw podmanProfileUnavailable("Duplicate prepared mountinfo ID");
    ids.add(id);
    const root = mountPath(fields[3]!);
    const destination = mountPath(fields[4]!);
    if (!root.startsWith("/") || !destination.startsWith("/"))
      throw podmanProfileUnavailable("Mountinfo paths must be absolute");
    const optional = fields.slice(6, separator);
    if (
      optional.some(
        (field) =>
          !/^(?:shared:[1-9][0-9]*|master:[1-9][0-9]*|propagate_from:[1-9][0-9]*|unbindable)$/u.test(
            field,
          ),
      )
    )
      throw podmanProfileUnavailable(
        "Unknown prepared mount propagation field",
      );
    return {
      id,
      parent: numeric(fields[1]),
      device: fields[2]!,
      root,
      destination,
      options: fields[5]!.split(","),
      optional,
      filesystem: fields[separator + 1]!,
      source: mountPath(fields[separator + 2]!),
      super_options: fields[separator + 3]!.split(","),
    };
  });
};
