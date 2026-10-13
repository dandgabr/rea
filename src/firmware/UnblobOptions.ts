import type { FirmwareRequest } from "../domain/firmware/firmwareAnalysis.js";

/** Audited Unblob26.6.4 default skip prefixes; do not inject them into native argv. */
export const UNBLOB_DEFAULT_SKIP_MAGIC = [
  "BFLT",
  "Erlang BEAM file",
  "GIF",
  "GNU message catalog",
  "HP Printer Job Language",
  "JPEG",
  "Java module image",
  "MPEG",
  "MS Windows icon resource",
  "Macromedia Flash data",
  "Microsoft Excel",
  "Microsoft PowerPoint",
  "Microsoft Word",
  "OpenDocument",
  "PDF document",
  "PNG",
  "SQLite",
  "TrueType Font data",
  "Web Open Font Format",
  "Windows Embedded CE binary image",
  "Xilinx BIT data",
  "compiled Java class",
  "magic binary file",
  "python",
] as const;

/** Preserve native option values as single argv tokens, including flag-like prefixes. */
export const unblobExecutionOptions = (request: FirmwareRequest) => {
  if (
    request.input.provider_id !== "unblob" ||
    request.operation === "inspect_firmware_provider"
  )
    throw new TypeError(
      "Unblob execution options require the Unblob provider branch",
    );
  const { options } = request.input;
  const args: string[] = [
    "--process-num",
    String(options.workers),
    "--randomness-depth",
    String(options.randomness_depth),
  ];
  if (options.plugins_path !== undefined)
    args.push(`--plugins-path=${options.plugins_path}`);
  if (options.skip_magic?.mode === "replace") args.push("--clear-skip-magics");
  for (const magic of options.skip_magic?.values ?? [])
    args.push(`--skip-magic=${magic}`);
  for (const extension of options.skip_extensions ?? [])
    args.push(`--skip-extension=${extension}`);
  if (request.operation === "inspect_firmware_regions")
    args.push("--skip-extraction", "--depth", "1");
  else {
    args.push("--depth", String(request.input.max_depth));
    const extraction = request.input.options;
    if (extraction.keep_extracted_chunks) args.push("--keep-extracted-chunks");
    const deletion = extraction.delete_extracted_files;
    args.push(
      `--delete-extracted-files=${deletion.mode === "selected" ? `selected:${deletion.handlers.join(",")}` : deletion.mode}`,
      `--carve-suffix=${extraction.carve_suffix}`,
      `--extract-suffix=${extraction.extract_suffix}`,
    );
  }
  return {
    args,
    skipMagic: [
      ...new Set([
        ...(options.skip_magic?.mode === "replace"
          ? []
          : UNBLOB_DEFAULT_SKIP_MAGIC),
        ...(options.skip_magic?.values ?? []),
      ]),
    ].sort(),
    skipExtensions: options.skip_extensions ?? [".rlib"],
  };
};
