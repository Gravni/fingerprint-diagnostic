import { createHash } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let provenance = {};
try {
  provenance = await import("../lib/fp-provenance.mjs");
} catch {
  // RED phase: report missing implementation as ordinary contract failures.
}

let pass = 0;
let fail = 0;
const ok = (label, condition) => {
  if (condition) pass++;
  else {
    fail++;
    console.log("  ✗ " + label);
  }
};
const equal = (label, actual, expected) => ok(label, Object.is(actual, expected));
const throwsCode = (label, fn, code) => {
  try {
    fn();
    ok(label, false);
  } catch (error) {
    ok(label, error && error.code === code);
  }
};

const { computeBuildIdentity, normalizeExecutablePath } = provenance;
ok("exports computeBuildIdentity", typeof computeBuildIdentity === "function");
ok("exports normalizeExecutablePath", typeof normalizeExecutablePath === "function");

if (typeof computeBuildIdentity === "function" && typeof normalizeExecutablePath === "function") {
  const fixture = mkdtempSync(join(tmpdir(), "fp-provenance-"));
  try {
    mkdirSync(join(fixture, "lib"));
    mkdirSync(join(fixture, "scripts"));
    writeFileSync(join(fixture, "lib", "alpha.mjs"), "export const alpha = 1;\n");
    writeFileSync(join(fixture, "scripts", "run.mjs"), "import '../lib/alpha.mjs';\n");

    const base = {
      rootDir: fixture,
      schemaVersion: "net-v6",
      executableTree: {
        roots: ["scripts", "lib"],
        files: ["scripts/run.mjs", "lib/alpha.mjs"],
      },
    };
    const reversed = {
      ...base,
      executableTree: {
        roots: ["lib", "scripts"],
        files: ["lib/alpha.mjs", "scripts/run.mjs"],
      },
    };

    const first = computeBuildIdentity(base);
    const second = computeBuildIdentity(reversed);
    equal("build ID is a full lowercase SHA-256", /^[0-9a-f]{64}$/.test(first.buildId), true);
    equal("algorithm is explicit and versioned", first.algorithm, "sha256-executable-tree-v1");
    equal("schema version is returned verbatim", first.schemaVersion, "net-v6");
    equal("manifest ordering cannot change build ID", first.buildId, second.buildId);
    equal(
      "reported files use reproducible lexical order",
      first.files.map((entry) => entry.path).join(","),
      "lib/alpha.mjs,scripts/run.mjs",
    );
    ok(
      "every file carries a content SHA-256 and byte size",
      first.files.every((entry) => /^[0-9a-f]{64}$/.test(entry.sha256) && Number.isSafeInteger(entry.size)),
    );

    const expectedDocument = JSON.stringify({
      algorithm: "sha256-executable-tree-v1",
      files: first.files.map(({ path, sha256, size }) => ({ path, sha256, size })),
    });
    equal(
      "root is SHA-256 of the documented canonical tree document",
      first.buildId,
      createHash("sha256").update(expectedDocument, "utf8").digest("hex"),
    );

    const otherSchema = computeBuildIdentity({ ...base, schemaVersion: "net-v7" });
    equal("schema version changes independently", otherSchema.schemaVersion, "net-v7");
    equal("schema version is not disguised as executable identity", otherSchema.buildId, first.buildId);

    writeFileSync(join(fixture, "lib", "alpha.mjs"), "export const alpha = 2;\n");
    const mutated = computeBuildIdentity(base);
    ok("mutating an executable changes build ID", mutated.buildId !== first.buildId);
    writeFileSync(join(fixture, "lib", "alpha.mjs"), "export const alpha = 1;\n");

    unlinkSync(join(fixture, "lib", "alpha.mjs"));
    throwsCode("missing declared executable blocks the build", () => computeBuildIdentity(base), "MISSING_FILE");
    writeFileSync(join(fixture, "lib", "alpha.mjs"), "export const alpha = 1;\n");

    writeFileSync(join(fixture, "lib", "surprise.mjs"), "export default 1;\n");
    throwsCode("unlisted file in a watched tree blocks the build", () => computeBuildIdentity(base), "UNLISTED_FILE");
    unlinkSync(join(fixture, "lib", "surprise.mjs"));

    // POSIX permits a literal backslash in a filename. The portable manifest
    // normalizer maps that character to `/`, so a literal file and a nested
    // file must not collapse into one discovered Set entry.
    mkdirSync(join(fixture, "scripts", "collision"));
    writeFileSync(join(fixture, "scripts", "collision", "payload.mjs"), "export const nested = true;\n");
    writeFileSync(join(fixture, "scripts", "collision\\payload.mjs"), "export const hidden = true;\n");
    throwsCode(
      "distinct filesystem entries that normalize to one path block the build",
      () => computeBuildIdentity({
        ...base,
        executableTree: {
          ...base.executableTree,
          files: [...base.executableTree.files, "scripts/collision/payload.mjs"],
        },
      }),
      "PATH_COLLISION",
    );
    rmSync(join(fixture, "scripts", "collision"), { recursive: true, force: true });
    unlinkSync(join(fixture, "scripts", "collision\\payload.mjs"));

    symlinkSync(join(fixture, "lib", "alpha.mjs"), join(fixture, "lib", "alias.mjs"));
    throwsCode("symlink in a watched tree blocks the build", () => computeBuildIdentity(base), "UNSAFE_FILE_TYPE");
    unlinkSync(join(fixture, "lib", "alias.mjs"));

    equal("backslashes normalize to portable separators", normalizeExecutablePath("lib\\alpha.mjs"), "lib/alpha.mjs");
    equal("redundant path segments normalize reproducibly", normalizeExecutablePath("./lib//alpha.mjs"), "lib/alpha.mjs");
    throwsCode("absolute paths are rejected", () => normalizeExecutablePath("/lib/alpha.mjs"), "INVALID_PATH");
    throwsCode("parent traversal is rejected", () => normalizeExecutablePath("lib/../alpha.mjs"), "INVALID_PATH");
    throwsCode("empty paths are rejected", () => normalizeExecutablePath(""), "INVALID_PATH");

    throwsCode(
      "duplicate paths after normalization are rejected",
      () => computeBuildIdentity({
        ...base,
        executableTree: { ...base.executableTree, files: ["lib/alpha.mjs", "lib\\alpha.mjs"] },
      }),
      "DUPLICATE_PATH",
    );
    throwsCode(
      "declared files must be covered by a watched root",
      () => computeBuildIdentity({
        ...base,
        executableTree: { roots: ["scripts"], files: base.executableTree.files },
      }),
      "FILE_OUTSIDE_ROOTS",
    );
    throwsCode(
      "missing watched root blocks the build",
      () => computeBuildIdentity({
        ...base,
        executableTree: { roots: ["lib", "missing"], files: ["lib/alpha.mjs"] },
      }),
      "MISSING_ROOT",
    );
    throwsCode(
      "empty executable tree cannot produce an identity",
      () => computeBuildIdentity({
        rootDir: fixture,
        schemaVersion: "net-v6",
        executableTree: { roots: [], files: [] },
      }),
      "EMPTY_TREE",
    );
    for (const value of [undefined, null, "", "unknown", "UNKNOWN", "net v6"]) {
      throwsCode(
        `invalid schema version is rejected: ${String(value)}`,
        () => computeBuildIdentity({ ...base, schemaVersion: value }),
        "INVALID_SCHEMA_VERSION",
      );
    }

    // A watched directory is closed-world: even non-code files influence the
    // executable package and therefore must be explicitly declared.
    writeFileSync(join(fixture, "scripts", "runtime.json"), "{\"flag\":true}\n");
    throwsCode("unlisted runtime data also blocks the build", () => computeBuildIdentity(base), "UNLISTED_FILE");
    const withRuntime = computeBuildIdentity({
      ...base,
      executableTree: {
        ...base.executableTree,
        files: [...base.executableTree.files, "scripts/runtime.json"],
      },
    });
    ok("declared runtime data participates in build ID", withRuntime.buildId !== first.buildId);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

// ---- reviewer #9: the collector build manifest covers the renderer + its import closure ----
{
  const { FP_COLLECTOR_INPUTS, FP_EXECUTABLE_TREE } = await import("../lib/fp-executable-tree.mjs");
  const { readFileSync: rf, existsSync: ex } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { dirname, join: j, posix } = await import("node:path");
  const root = j(dirname(fileURLToPath(import.meta.url)), "..");
  ok("collector manifest lists the renderer", FP_COLLECTOR_INPUTS.includes("lib/fp-probe-artifact.mjs"));
  ok("collector manifest lists template + encoder", FP_COLLECTOR_INPUTS.includes("assets/fingerprint-probe.html") && FP_COLLECTOR_INPUTS.includes("lib/fp-encode.mjs"));
  ok("every collector input exists as a regular file", FP_COLLECTOR_INPUTS.every((p) => ex(j(root, p))));
  // static import closure of the renderer (relative .mjs imports only — the renderer is dependency-free)
  const closure = new Set();
  const walk = (rel) => {
    if (closure.has(rel)) return; closure.add(rel);
    const src = rf(j(root, rel), "utf8");
    for (const m of src.matchAll(/\bfrom\s+["'](\.{1,2}\/[^"']+)["']/g)) walk(posix.normalize(posix.join(posix.dirname(rel), m[1])));
  };
  walk("lib/fp-probe-artifact.mjs");
  ok("renderer import closure ⊆ collector manifest (" + [...closure].join(", ") + ")", [...closure].every((p) => FP_COLLECTOR_INPUTS.includes(p)));
  ok("every lib/ collector input is part of the closed executable tree", FP_COLLECTOR_INPUTS.filter((p) => p.startsWith("lib/")).every((p) => FP_EXECUTABLE_TREE.files.includes(p)));
  ok("collector manifest is sorted + unique", JSON.stringify([...FP_COLLECTOR_INPUTS]) === JSON.stringify([...new Set(FP_COLLECTOR_INPUTS)].sort()));
}

console.log(`\nfp-provenance: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
