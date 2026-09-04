// Comparator rule engine (Codex v4 §Компаратор). Pure & dependency-free.
//
// Hard rules it enforces:
//  - compare values ONLY when BOTH sides are status=ok;
//  - if either side is not ok → `unresolved` (coverage/errors) — NEVER leaked/masked;
//  - `leaked`/`masked` are emitted ONLY when the profile explicitly says this path
//    is supposed to be isolated/changed (opts.profileProtects); without a profile,
//    only same/different/plain-only/anti-only/unresolved are possible;
//  - `volatile` paths are surfaced separately, never as a masking verdict;
//  - plain and anti value+type are both carried so the exporter can show them apart.

const keyOf = (r) => (r.context || "") + "|" + (r.path || "");
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    // Null-prototype storage keeps `__proto__`, `constructor`, etc. as data.
    // A normal object would interpret `out.__proto__ = value` as prototype
    // mutation and silently drop that key from the canonical JSON.
    const out = Object.create(null);
    for (const k of Object.keys(value).sort()) out[k] = canonical(value[k]);
    return out;
  }
  return value;
}
const encOf = (r) => JSON.stringify(canonical({
  t: r.valueType,
  v: r.value,
  s: r.meta && r.meta.special,
  // A capped array's inline prefix can be identical while the original lengths
  // differ. `count` is part of the value identity, not disposable metadata.
  c: r.meta && r.meta.count,
}));

function hasIncompleteEncodedValue(value, seen = new Set()) {
  if (!value || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (!Array.isArray(value) && value.__blobRef && typeof value.__blobRef === "object") {
    if (value.__blobRef.complete === false || value.__blobRef.hashScope === "marker") return true;
  }
  if (Array.isArray(value)) return value.some((entry) => hasIncompleteEncodedValue(entry, seen));
  return Object.keys(value).some((key) => hasIncompleteEncodedValue(value[key], seen));
}

// Keep the comparison row self-explanatory. `value` already carries nested
// blob/cycle markers; `error` and metadata must travel with it as well or two
// different records can render as the same value in reports (notably capped
// arrays whose inline prefixes match but whose original counts differ).
// `special` remains as a compatibility alias for existing exporters.
function sideView(r) {
  if (!r) return null;
  const meta = r.meta && typeof r.meta === "object" && !Array.isArray(r.meta)
    ? { ...r.meta }
    : {};
  return {
    status: r.status,
    valueType: r.valueType,
    value: r.value,
    error: r.error === undefined ? null : r.error,
    meta,
    special: meta.special,
    count: meta.count,
  };
}

function index(list) {
  const m = new Map();
  for (const r of list || []) {
    const k = keyOf(r), rows = m.get(k) || [];
    rows.push(r);
    m.set(k, rows);
  }
  return m;
}

/**
 * @param {Array} plain typed records
 * @param {Array} anti  typed records
 * @param {object} opts { hasProfile?:boolean, profileProtects?:(path,context)=>bool,
 *                        volatile?:(path,context)=>bool }
 * @returns {Array<{key,path,context,verdict,reason,plain,anti}>}
 */
export function compareMeasurements(plain, anti, opts = {}) {
  const hasProfile = !!opts.hasProfile;
  const protects = opts.profileProtects || (() => false);
  const isVolatile = opts.volatile || (() => false);
  const P = index(plain), A = index(anti);
  const keys = new Set([...P.keys(), ...A.keys()]);
  const rows = [];

  for (const k of keys) {
    const ps = P.get(k) || [], as = A.get(k) || [];
    const exemplar = ps[0] || as[0];
    const p = ps.length === 1 ? ps[0] : null, a = as.length === 1 ? as[0] : null;
    const path = exemplar.path, context = exemplar.context;
    const base = {
      key: k, path, context,
      plainCount: ps.length,
      antiCount: as.length,
      plain: sideView(p),
      anti: sideView(a),
    };
    const emit = (verdict, reason) => rows.push({ ...base, verdict, reason });

    if (ps.length > 1 || as.length > 1) {
      emit("unresolved", "duplicate measurement key");
      continue;
    }
    if (p && !a) { emit("plain-only", "missing in anti"); continue; }
    if (!p && a) { emit("anti-only", "missing in plain"); continue; }

    const pOk = p.status === "ok", aOk = a.status === "ok";
    if (!pOk || !aOk) {
      // at least one side isn't a real value → this is coverage, NOT a verdict.
      emit("unresolved", `status plain=${p.status} anti=${a.status}`);
      continue;
    }

    // Defense in depth for callers that compare raw input before validating it:
    // a marker-scope digest identifies the truncation event, not the omitted
    // content, so equality/difference is unknowable.
    if (hasIncompleteEncodedValue(p.value) || hasIncompleteEncodedValue(a.value)) {
      emit("unresolved", "incomplete encoded value");
      continue;
    }

    if (isVolatile(path, context)) { emit("volatile", "env-dependent path"); continue; }

    const same = p.valueType === a.valueType && encOf(p) === encOf(a);
    const protectedPath = hasProfile && protects(path, context);
    if (same) {
      // identical. Only a leak if the profile SAID this path must have changed.
      if (protectedPath) emit("leaked", "profile expected isolation/change, values identical");
      else emit("same", "identical value+type");
    } else {
      if (protectedPath) emit("masked", "profile target changed as expected");
      else emit("different", "value or type differs (no profile rule → not a masking claim)");
    }
  }
  return rows;
}

/** Roll up verdict counts for reporting. */
export function summarize(rows) {
  const c = {};
  for (const r of rows) c[r.verdict] = (c[r.verdict] || 0) + 1;
  return c;
}
