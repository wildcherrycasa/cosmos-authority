// ═══ DETERMINISTIC CBOR (RFC 8949 §4.2) — the subset a Cosmos receipt needs ════════════════════════════
//
// Why hand-rolled: `core/` depends on nothing but `crypto`, which is what makes it auditable in an
// afternoon. A verifier written by a stranger will use THEIR OWN CBOR library, so Cosmos only has to emit
// bytes that every library agrees on. That is exactly the interop trap that bit the signing preimage on
// 2026-09-01 (it signed ASCII hex, not the digest bytes), so the rules below are quoted from the RFC
// rather than remembered.
//
// RFC 8949 §4.2.1, verified 2026-09-05:
//   - "Preferred serialization MUST be used" — the shortest head that fits the argument.
//     0..23 → in the head byte · <256 → +uint8 · <65536 → +uint16 · <2^32 → +uint32 · else +uint64
//   - "The keys in every map MUST be sorted in the bytewise lexicographic order of their deterministic
//     encodings."  ← BYTEWISE on the ENCODED key, not length-first, and not on the source string.
//   - "Indefinite-length items MUST NOT appear."
//
// FLOATS ARE REFUSED. Deterministic float encoding requires emitting the shortest of binary16/32/64 that
// round-trips, which is a genuine trap. Cosmos uses integer minor units everywhere precisely so it never
// needs one — so this refuses rather than guesses. (Same reasoning as jcs.js rejecting non-finite numbers.)
'use strict';

const MT_UINT = 0, MT_NEGINT = 1, MT_BSTR = 2, MT_TSTR = 3, MT_ARRAY = 4, MT_MAP = 5, MT_TAG = 6, MT_SIMPLE = 7;

class Tagged {
  constructor(tag, value) { this.tag = tag; this.value = value; }
}

// The head: major type in the top 3 bits, then the shortest additional-info form that holds `n`.
function head(major, n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('CBOR_BAD_HEAD_ARG:' + n);
  const mt = major << 5;
  if (n < 24) return Buffer.from([mt | n]);
  if (n < 0x100) return Buffer.from([mt | 24, n]);
  if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = mt | 25; b.writeUInt16BE(n, 1); return b; }
  if (n < 0x100000000) { const b = Buffer.alloc(5); b[0] = mt | 26; b.writeUInt32BE(n, 1); return b; }
  const b = Buffer.alloc(9); b[0] = mt | 27; b.writeBigUInt64BE(BigInt(n), 1); return b;
}

function encode(v) {
  if (v === null) return Buffer.from([0xf6]);                       // major 7, value 22
  if (v === true) return Buffer.from([0xf5]);
  if (v === false) return Buffer.from([0xf4]);
  if (v === undefined) throw new Error('CBOR_UNDEFINED_NOT_ENCODABLE');

  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('CBOR_FLOAT_UNSUPPORTED:' + v);
    if (!Number.isSafeInteger(v)) throw new Error('CBOR_INTEGER_UNSAFE:' + v);
    return v >= 0 ? head(MT_UINT, v) : head(MT_NEGINT, -1 - v);
  }
  if (typeof v === 'bigint') {
    if (v > 9007199254740991n || v < -9007199254740991n) throw new Error('CBOR_BIGINT_OUT_OF_RANGE');
    return encode(Number(v));
  }
  if (typeof v === 'string') {
    const b = Buffer.from(v, 'utf8');
    return Buffer.concat([head(MT_TSTR, b.length), b]);
  }
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) {
    const b = Buffer.isBuffer(v) ? v : Buffer.from(v);
    return Buffer.concat([head(MT_BSTR, b.length), b]);
  }
  if (v instanceof Tagged) return Buffer.concat([head(MT_TAG, v.tag), encode(v.value)]);
  if (Array.isArray(v)) return Buffer.concat([head(MT_ARRAY, v.length), ...v.map(encode)]);

  // Maps. A JS Map is used where keys are integers (COSE headers); a plain object where they are strings.
  if (v instanceof Map || (typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype)) {
    const entries = v instanceof Map ? [...v.entries()] : Object.entries(v).filter(([, val]) => val !== undefined);
    // §4.2.1: sort by the BYTEWISE LEXICOGRAPHIC order of the keys' deterministic encodings.
    const encoded = entries.map(([k, val]) => [encode(k), encode(val)]);
    encoded.sort((a, b) => Buffer.compare(a[0], b[0]));
    for (let i = 1; i < encoded.length; i++) {
      if (Buffer.compare(encoded[i - 1][0], encoded[i][0]) === 0) throw new Error('CBOR_DUPLICATE_MAP_KEY');
    }
    return Buffer.concat([head(MT_MAP, encoded.length), ...encoded.flatMap(([k, val]) => [k, val])]);
  }
  throw new Error('CBOR_UNSUPPORTED_TYPE:' + Object.prototype.toString.call(v));
}

// ── decode: only what a verifier needs to open a COSE_Sign1 and read its payload ────────────────────────
function decode(buf, offset) {
  const st = { b: Buffer.isBuffer(buf) ? buf : Buffer.from(buf), i: offset || 0 };
  const v = readItem(st);
  return offset === undefined ? v : { value: v, end: st.i };
}

function need(st, n) { if (st.i + n > st.b.length) throw new Error('CBOR_TRUNCATED'); }

function readArg(st, ai) {
  if (ai < 24) return ai;
  if (ai === 24) { need(st, 1); return st.b[st.i++]; }
  if (ai === 25) { need(st, 2); const n = st.b.readUInt16BE(st.i); st.i += 2; return n; }
  if (ai === 26) { need(st, 4); const n = st.b.readUInt32BE(st.i); st.i += 4; return n; }
  if (ai === 27) {
    need(st, 8); const n = st.b.readBigUInt64BE(st.i); st.i += 8;
    if (n > 9007199254740991n) throw new Error('CBOR_INTEGER_UNSAFE');
    return Number(n);
  }
  throw new Error('CBOR_INDEFINITE_LENGTH_FORBIDDEN');   // ai 31; §4.2.1 forbids it outright
}

function readItem(st) {
  need(st, 1);
  const ib = st.b[st.i++], major = ib >> 5, ai = ib & 0x1f;
  switch (major) {
    case MT_UINT: return readArg(st, ai);
    case MT_NEGINT: return -1 - readArg(st, ai);
    case MT_BSTR: { const n = readArg(st, ai); need(st, n); const out = st.b.subarray(st.i, st.i + n); st.i += n; return Buffer.from(out); }
    case MT_TSTR: { const n = readArg(st, ai); need(st, n); const out = st.b.toString('utf8', st.i, st.i + n); st.i += n; return out; }
    case MT_ARRAY: { const n = readArg(st, ai); const a = new Array(n); for (let k = 0; k < n; k++) a[k] = readItem(st); return a; }
    case MT_MAP: { const n = readArg(st, ai); const m = new Map(); for (let k = 0; k < n; k++) { const key = readItem(st); m.set(key, readItem(st)); } return m; }
    case MT_TAG: { const t = readArg(st, ai); return new Tagged(t, readItem(st)); }
    case MT_SIMPLE:
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      throw new Error('CBOR_UNSUPPORTED_SIMPLE:' + ai);
    default: throw new Error('CBOR_UNSUPPORTED_MAJOR:' + major);
  }
}

// A map decoded from CBOR is a Map (keys may be integers). This flattens string-keyed Maps to plain
// objects, recursing through ARRAYS as well — a proof path is an array of maps, and the first version of
// this function skipped arrays, so `step.hash` came back undefined and every capability proof failed.
function mapToObject(v) {
  if (v instanceof Map) { const o = {}; for (const [k, val] of v) o[String(k)] = mapToObject(val); return o; }
  if (Array.isArray(v)) return v.map(mapToObject);
  return v;
}

module.exports = { encode, decode, Tagged, head, mapToObject };
