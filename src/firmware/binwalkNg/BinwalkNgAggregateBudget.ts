/** Logical operation-wide ceilings for transferred output and recursive snapshots.
 * These limits bound bytes and entries admitted by REA; they are not filesystem quotas.
 */
export class BinwalkNgAggregateBudget {
  readonly #limits: {
    artifactBytes: number;
    artifactFiles: number;
    reportBytes: number;
    reportFiles: number;
    entries: number;
    childSnapshotBytes: number;
    childSnapshotFiles: number;
  };
  readonly #directories = new Set<string>();
  #artifactBytes = 0;
  #artifactFiles = 0;
  #reportBytes = 0;
  #reportFiles = 0;
  #entries = 0;
  #childSnapshotBytes = 0;
  #childSnapshotFiles = 0;

  constructor(limits: {
    readonly artifactBytes: number;
    readonly artifactFiles: number;
    readonly reportBytes: number;
    readonly reportFiles: number;
    readonly entries: number;
    readonly childSnapshotBytes: number;
    readonly childSnapshotFiles: number;
  }) {
    for (const value of Object.values(limits))
      if (!Number.isSafeInteger(value) || value < 0)
        throw new Error("Invalid Binwalk-NG aggregate budget");
    this.#limits = { ...limits };
  }

  get remainingArtifactBytes(): number {
    return this.#limits.artifactBytes - this.#artifactBytes;
  }

  get remainingArtifactFiles(): number {
    return this.#limits.artifactFiles - this.#artifactFiles;
  }

  get remainingReportBytes(): number {
    return this.#limits.reportBytes - this.#reportBytes;
  }

  admitTransfer(path: string, bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0)
      throw new Error("Invalid Binwalk-NG transferred byte count");
    const report = path.startsWith("reports/");
    const artifact = path.startsWith("artifacts/");
    if (!report && !artifact && path !== "entropy.png")
      throw new Error("Binwalk-NG transfer path has no aggregate budget owner");
    if (report) {
      if (bytes > this.#limits.reportBytes - this.#reportBytes)
        throw new Error(
          "Binwalk-NG transfer exceeds aggregate report byte budget",
        );
      if (this.#reportFiles >= this.#limits.reportFiles)
        throw new Error(
          "Binwalk-NG transfer exceeds aggregate report file budget",
        );
    } else if (artifact) {
      if (bytes > this.#limits.artifactBytes - this.#artifactBytes)
        throw new Error(
          "Binwalk-NG transfer exceeds aggregate artifact byte budget",
        );
      if (this.#artifactFiles >= this.#limits.artifactFiles)
        throw new Error(
          "Binwalk-NG transfer exceeds aggregate artifact file budget",
        );
    } else if (bytes > this.#limits.reportBytes) {
      throw new Error("Binwalk-NG transfer exceeds entropy PNG byte budget");
    }

    const parts = path.split("/");
    let addedDirectories = 0;
    for (let index = 1; index < parts.length; index++) {
      const directory = parts.slice(0, index).join("/");
      if (!this.#directories.has(directory)) addedDirectories++;
    }
    if (this.#entries + addedDirectories + 1 > this.#limits.entries)
      throw new Error("Binwalk-NG transfer exceeds aggregate entry budget");

    if (report) {
      this.#reportBytes += bytes;
      this.#reportFiles++;
    } else if (artifact) {
      this.#artifactBytes += bytes;
      this.#artifactFiles++;
    }
    for (let index = 1; index < parts.length; index++)
      this.#directories.add(parts.slice(0, index).join("/"));
    this.#entries += addedDirectories + 1;
  }

  admitChildSnapshot(bytes: number): void {
    if (
      !Number.isSafeInteger(bytes) ||
      bytes < 0 ||
      bytes > this.#limits.childSnapshotBytes - this.#childSnapshotBytes
    )
      throw new Error(
        "Binwalk-NG recursive snapshots exceed aggregate byte budget",
      );
    if (this.#childSnapshotFiles >= this.#limits.childSnapshotFiles)
      throw new Error(
        "Binwalk-NG recursive snapshots exceed aggregate file budget",
      );
    // The child tree root is shared; each snapshot adds one child directory
    // and one file. Include those host-side entries in the same ledger.
    const addedEntries = this.#childSnapshotFiles === 0 ? 3 : 2;
    if (this.#entries + addedEntries > this.#limits.entries)
      throw new Error(
        "Binwalk-NG recursive snapshots exceed aggregate entry budget",
      );
    this.#childSnapshotBytes += bytes;
    this.#childSnapshotFiles++;
    this.#entries += addedEntries;
  }
}
