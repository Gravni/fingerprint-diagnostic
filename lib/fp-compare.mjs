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
const encOf = (r) => JSON.stringify({ t: r.valueType, v: r.value, s: r.meta && r.meta.special });

function index(list) {
  const m = new Map();
  for (const r of list || []) m.set(keyOf(r), r);
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
    const p = P.get(k) || null, a = A.get(k) || null;
    const path = (p || a).path, context = (p || a).context;
    const base = {
      key: k, path, context,
      plain: p && { status: p.status, valueType: p.valueType, value: p.value, special: p.meta && p.meta.special },
      anti: a && { status: a.status, valueType: a.valueType, value: a.value, special: a.meta && a.meta.special },
    };
    const emit = (verdict, reason) => rows.push({ ...base, verdict, reason });

    if (p && !a) { emit("plain-only", "missing in anti"); continue; }
    if (!p && a) { emit("anti-only", "missing in plain"); continue; }

    const pOk = p.status === "ok", aOk = a.status === "ok";
    if (!pOk || !aOk) {
      // at least one side isn't a real value → this is coverage, NOT a verdict.
      emit("unresolved", `status plain=${p.status} anti=${a.status}`);
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
