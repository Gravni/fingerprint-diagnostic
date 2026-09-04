export const BUILD_ID_ALGORITHM: "sha256-executable-tree-v1";

export type BuildProvenanceErrorCode =
  | "INVALID_PATH"
  | "INVALID_MANIFEST"
  | "DUPLICATE_PATH"
  | "PATH_COLLISION"
  | "MISSING_FILE"
  | "MISSING_ROOT"
  | "UNSAFE_FILE_TYPE"
  | "INVALID_SCHEMA_VERSION"
  | "INVALID_ROOT"
  | "EMPTY_TREE"
  | "FILE_OUTSIDE_ROOTS"
  | "UNLISTED_FILE";

export class BuildProvenanceError extends Error {
  readonly code: BuildProvenanceErrorCode;
  readonly details: Readonly<Record<string, unknown>>;
  constructor(
    code: BuildProvenanceErrorCode,
    message: string,
    details?: Readonly<Record<string, unknown>>,
  );
}

export interface ExecutableTreeManifest {
  /** Closed directories: every entry below them must be declared in `files`. */
  readonly roots: readonly string[];
  /** Complete list of regular files that make up the executable package. */
  readonly files: readonly string[];
}

export interface BuildIdentityOptions {
  readonly rootDir: string;
  /** Explicit data/schema protocol version; never inferred or defaulted. */
  readonly schemaVersion: string;
  readonly executableTree: ExecutableTreeManifest;
}

export interface ExecutableFileIdentity {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export interface BuildIdentity {
  readonly algorithm: typeof BUILD_ID_ALGORITHM;
  /** Full lowercase SHA-256 of the canonical executable-tree document. */
  readonly buildId: string;
  /** Separate from buildId: changing schema metadata alone does not alter code identity. */
  readonly schemaVersion: string;
  readonly files: readonly ExecutableFileIdentity[];
}

export function normalizeExecutablePath(input: string): string;

/**
 * Computes an identity for a closed executable tree. Missing, unlisted, symlink,
 * or otherwise non-regular entries throw BuildProvenanceError.
 */
export function computeBuildIdentity(options: BuildIdentityOptions): BuildIdentity;
