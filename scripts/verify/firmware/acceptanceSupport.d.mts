export interface OracleFile {
  readonly size: number;
  readonly sha256: string;
}

export interface PublishedFile extends OracleFile {
  readonly relative_path: string;
  readonly path: string;
}

export function oracleFilesForSelectedRange(
  oracleFiles: Readonly<Record<string, OracleFile>>,
  selectedPrefix: string,
): Readonly<Record<string, OracleFile>>;

export function assertOracleOutputFiles(
  files: readonly PublishedFile[],
  expectedFiles: Readonly<Record<string, OracleFile>>,
  expectedOutputRoot: string,
  hashFile: (path: string) => Promise<string>,
): Promise<void>;

export function runWithCleanup<T>(
  operation: () => Promise<T>,
  cleanup: () => Promise<void>,
): Promise<T>;

export function closeClientAndRemoveWorkspace(
  closeClient: () => Promise<unknown>,
  workspace: string,
  removeWorkspace: (workspace: string) => Promise<unknown>,
): Promise<void>;
