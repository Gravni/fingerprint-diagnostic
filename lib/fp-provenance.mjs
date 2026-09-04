import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { isAbsolute, join, posix, resolve } from "node:path";

export const BUILD_ID_ALGORITHM = "sha256-executable-tree-v1";

export class BuildProvenanceError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "BuildProvenanceError";
    this.code = code;
    this.details = details;
  }
}

const fail = (code, message, details) => {
  throw new BuildProvenanceError(code, message, details);
};

/**
 * Convert a manifest path into a platform-independent, repository-relative path.
 * Traversal is rejected before normalization rather than silently rewritten.
 */
export function normalizeExecutablePath(input) {
  if (typeof input !== "string" || input.length === 0 || input.includes("\0")) {
    fail("INVALID_PATH", "Executable paths must be non-empty strings without NUL bytes", { input });
  }

  const portable = input.replaceAll("\\", "/").normalize("NFC");
  const segments = portable.split("/");
  if (
    isAbsolute(portable)
    || /^\/?[A-Za-z]:\//.test(portable)
    || portable.startsWith("//")
    || segments.includes("..")
  ) {
    fail("INVALID_PATH", "Executable paths must stay below the declared root", { input });
  }

  const normalized = posix.normalize(portable).replace(/^\.\//, "");
  if (normalized === "" || normalized === "." || normalized.startsWith("../")) {
    fail("INVALID_PATH", "Executable paths must name a repository-relative entry", { input });
  }
  return normalized;
}

function normalizeUnique(values, label) {
  if (!Array.isArray(values)) {
    fail("INVALID_MANIFEST", `${label} must be an array`, { label });
  }
  const normalized = values.map(normalizeExecutablePath);
  if (new Set(normalized).size !== normalized.length) {
    fail("DUPLICATE_PATH", `${label} contains duplicate paths after normalization`, { label, values });
  }
  return normalized.sort(comparePaths);
}

function comparePaths(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function safeLstat(path, missingCode, relativePath) {
  try {
    return lstatSync(path);
  } catch (error) {
    if (error && error.code === "ENOENT") {
      fail(missingCode, `Declared path does not exist: ${relativePath}`, { path: relativePath });
    }
    throw error;
  }
}

function assertRegularFile(absolutePath, relativePath) {
  const stat = safeLstat(absolutePath, "MISSING_FILE", relativePath);
  if (!stat.isFile()) {
    fail("UNSAFE_FILE_TYPE", `Executable entry is not a regular file: ${relativePath}`, { path: relativePath });
  }
  return stat;
}

function scanClosedRoot(absoluteRoot, relativeRoot, discovered) {
  const rootStat = safeLstat(absoluteRoot, "MISSING_ROOT", relativeRoot);
  if (!rootStat.isDirectory()) {
    fail("UNSAFE_FILE_TYPE", `Executable root is not a regular directory: ${relativeRoot}`, { path: relativeRoot });
  }

  const walk = (absoluteDirectory, relativeDirectory) => {
    const entries = readdirSync(absoluteDirectory, { withFileTypes: true })
      .sort((left, right) => comparePaths(left.name.normalize("NFC"), right.name.normalize("NFC")));
    for (const entry of entries) {
      const name = entry.name.normalize("NFC");
      const relativePath = normalizeExecutablePath(`${relativeDirectory}/${name}`);
      const absolutePath = join(absoluteDirectory, entry.name);
      if (entry.isDirectory()) {
        walk(absolutePath, relativePath);
      } else if (entry.isFile()) {
        if (discovered.has(relativePath)) {
          fail(
            "PATH_COLLISION",
            `Distinct filesystem entries normalize to the same executable path: ${relativePath}`,
            { path: relativePath },
          );
        }
        discovered.add(relativePath);
      } else {
        fail("UNSAFE_FILE_TYPE", `Unsupported entry in executable tree: ${relativePath}`, { path: relativePath });
      }
    }
  };

  walk(absoluteRoot, relativeRoot);
}

function isBelowRoot(file, root) {
  return file.startsWith(`${root}/`);
}

function validateSchemaVersion(schemaVersion) {
  if (
    typeof schemaVersion !== "string"
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(schemaVersion)
    || schemaVersion.toLowerCase() === "unknown"
  ) {
    fail("INVALID_SCHEMA_VERSION", "schemaVersion must be an explicit version identifier", { schemaVersion });
  }
}

/**
 * Hash a closed, explicitly enumerated executable tree.
 *
 * Canonical root document (UTF-8 JSON, keys in this exact order):
 *   {algorithm, files:[{path,sha256,size}, ...]}
 * `schemaVersion` is deliberately returned beside the build identity and is not
 * mixed into it: schema compatibility and executable provenance are different.
 */
export function computeBuildIdentity({ rootDir, schemaVersion, executableTree } = {}) {
  validateSchemaVersion(schemaVersion);
  if (typeof rootDir !== "string" || rootDir.length === 0) {
    fail("INVALID_ROOT", "rootDir must identify an existing directory", { rootDir });
  }
  if (!executableTree || typeof executableTree !== "object") {
    fail("INVALID_MANIFEST", "executableTree is required");
  }

  const roots = normalizeUnique(executableTree.roots, "executableTree.roots");
  const files = normalizeUnique(executableTree.files, "executableTree.files");
  if (roots.length === 0 || files.length === 0) {
    fail("EMPTY_TREE", "Executable provenance requires at least one root and one file");
  }
  for (const file of files) {
    if (!roots.some((root) => isBelowRoot(file, root))) {
      fail("FILE_OUTSIDE_ROOTS", `Declared file is outside executable roots: ${file}`, { path: file, roots });
    }
  }

  const absoluteRoot = resolve(rootDir);
  const rootStat = safeLstat(absoluteRoot, "INVALID_ROOT", rootDir);
  if (!rootStat.isDirectory()) {
    fail("INVALID_ROOT", "rootDir must identify a directory", { rootDir });
  }
  // Resolve once so relative paths cannot escape through a symlinked root.
  const canonicalRoot = realpathSync(absoluteRoot);

  for (const file of files) {
    assertRegularFile(join(canonicalRoot, ...file.split("/")), file);
  }

  const discovered = new Set();
  for (const root of roots) {
    scanClosedRoot(join(canonicalRoot, ...root.split("/")), root, discovered);
  }
  const declared = new Set(files);
  const unlisted = [...discovered].filter((path) => !declared.has(path)).sort(comparePaths);
  if (unlisted.length > 0) {
    fail("UNLISTED_FILE", `Executable tree contains unlisted files: ${unlisted.join(", ")}`, { paths: unlisted });
  }

  const fileRecords = files.map((path) => {
    const bytes = readFileSync(join(canonicalRoot, ...path.split("/")));
    return Object.freeze({
      path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      size: bytes.byteLength,
    });
  });
  const canonicalDocument = JSON.stringify({
    algorithm: BUILD_ID_ALGORITHM,
    files: fileRecords,
  });

  return Object.freeze({
    algorithm: BUILD_ID_ALGORITHM,
    buildId: createHash("sha256").update(canonicalDocument, "utf8").digest("hex"),
    schemaVersion,
    files: Object.freeze(fileRecords),
  });
}
