// ═══ RFC 8785 JSON Canonicalization Scheme (JCS) — the subset WRIT receipts use ════════════════════════════════
// Produces deterministic, byte-identical canonical JSON for the value types a receipt contains (objects, arrays,
// strings, integers, booleans, null). Object member keys are sorted by UTF-16 code unit (the default JS string
// order), there is no insignificant whitespace, and strings use JSON's minimal escaping. undefined members are
// dropped. Numbers here are integers (minor units) + small counts — serialized via JSON's ECMAScript number form,
// which is JCS-compliant for these. (We do not emit arbitrary floats in receipts; if one appears it still round-trips
// through JSON's number form.) The SAME bytes are produced by the issuer and by the offline verifier, so the
// signature covers exactly what a verifier recomputes.
'use strict';

function jcs(value) {
  if (value === null || value === undefined) return 'null';
  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') { if (!Number.isFinite(value)) throw new Error('JCS_NON_FINITE_NUMBER'); return JSON.stringify(value); }
  if (t === 'bigint') return value.toString();
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();   // UTF-16 code-unit order
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
  }
  throw new Error('JCS_UNSUPPORTED_TYPE:' + t);
}

module.exports = { jcs };
