// ═══ RFC 8785 (JCS) CANONICALIZATION VECTORS ═══════════════════════════════════════════════════════════
//
// Why this file exists: EVERY signature Cosmos issues is Ed25519 over sha256(jcs(body)). If jcs() and a
// verifier's JCS implementation ever disagree by one byte, every receipt ever issued becomes unverifiable
// by anyone else's tooling — silently, and retroactively. 26 lines of core/jcs.js carry the whole product.
//
// Writ never tested this. Its certificate suites executed jcs() constantly but only asserted round-trips
// through ITSELF, which any self-consistent function passes — including a wrong one.
//
// Rules asserted here are quoted from RFC 8785 (https://www.rfc-editor.org/rfc/rfc8785.txt):
//   §3.2.3 sorting  — "formatted as arrays of UTF-16 code units ... treated as unsigned integers"
//   §3.2.2.3 numbers— ECMA-262 7.1.12.1 (Number::toString); NaN/Infinity MUST error
//   §3.2.2.2 strings— U+0008/09/0A/0C/0D as \b \t \n \f \r; other C0 as LOWERCASE \uhhhh;
//                     everything else literal except \ and " ; non-ASCII emitted as-is
'use strict';
const { jcs } = require('../core/jcs');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
// eq prints BOTH values on failure — a mutation must be legible from the output alone.
const eq = (actual, expected, m) => {
  if (actual === expected) { pass++; console.log('  ✓ ' + m); return; }
  fail++;
  console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(expected));
  console.log('      actual:   ' + JSON.stringify(actual));
};
const throws = (fn, code, m) => {
  try { fn(); fail++; console.log('  ✗ ' + m); console.log('      expected throw ' + code + ', got none'); }
  catch (e) {
    if (String(e.message).includes(code)) { pass++; console.log('  ✓ ' + m); }
    else { fail++; console.log('  ✗ ' + m); console.log('      expected throw ' + code); console.log('      actual:   ' + e.message); }
  }
};

console.log('\n── A · OBJECT KEY SORTING (§3.2.3) — the highest-risk rule ────────────────────────────────────');

eq(jcs({ b: 1, a: 2, c: 3 }), '{"a":2,"b":1,"c":3}',
   'A1 · keys are sorted, not emitted in insertion order');

eq(jcs({ a: 1, b: 2, c: 3 }), jcs({ c: 3, b: 2, a: 1 }),
   'A2 · ★ insertion order is irrelevant — the SAME content yields byte-identical output');

// JS puts integer-like keys first in ascending NUMERIC order in Object.keys(). RFC 8785 sorts the key
// STRINGS, so "10" precedes "2". A canonicalizer that trusted Object.keys() order would get this wrong.
eq(jcs({ '2': 'two', '10': 'ten', '1': 'one' }), '{"1":"one","10":"ten","2":"two"}',
   'A3 · ★ integer-like keys sort LEXICOGRAPHICALLY ("1" < "10" < "2"), not numerically');

// ── The discriminating vector, straight out of RFC 8785's own worked example. ──────────────────────────
// € = U+20AC              → one code unit 0x20AC
// 😀 = U+1F600            → surrogate PAIR 0xD83D 0xDE00, so it sorts on 0xD83D
// דּ = U+FB33             → one code unit 0xFB33
// UTF-16 code-unit order : € (20AC) < 😀 (D83D) < דּ (FB33)      ← what RFC 8785 requires
// Unicode codepoint order: € (20AC) < דּ (FB33) < 😀 (1F600)     ← what a "sort by codepoint" impl gives
// These two orders DISAGREE, which is exactly why this vector is worth having.
{
  const s = jcs({ 'דּ': 'hebrew', '😀': 'emoji', '€': 'euro' });
  eq(s, '{"€":"euro","😀":"emoji","דּ":"hebrew"}',
     'A4 · ★★ surrogate pairs sort by UTF-16 CODE UNIT, not codepoint (RFC 8785 §3.2.3 worked example)');
  const iEuro = s.indexOf('euro'), iEmoji = s.indexOf('emoji'), iHeb = s.indexOf('hebrew');
  ok(iEuro < iEmoji && iEmoji < iHeb,
     'A4b · ★ the emoji sorts BETWEEN euro and hebrew — codepoint order would put it last');
}

eq(jcs({ z: { d: 1, b: 2 }, a: { y: 3, x: 4 } }), '{"a":{"x":4,"y":3},"z":{"b":2,"d":1}}',
   'A5 · sorting recurses — nested objects are sorted too');

eq(jcs([{ b: 1, a: 2 }, { d: 3, c: 4 }]), '[{"a":2,"b":1},{"c":4,"d":3}]',
   'A6 · objects nested inside arrays are sorted');

// Array order is DATA, not something to normalize away.
ok(jcs([3, 1, 2]) !== jcs([1, 2, 3]), 'A7 · ★ array element order is PRESERVED — arrays are not sorted');

console.log('\n── B · NUMBERS (§3.2.2.3 — ECMA-262 Number::toString) ─────────────────────────────────────────');

eq(jcs(0), '0', 'B1 · zero');
eq(jcs(-0), '0', 'B2 · ★ negative zero serializes as "0" (RFC 8785 Appendix B)');
eq(jcs(1200), '1200', 'B3 · a minor-unit integer');
eq(jcs(-1200), '-1200', 'B4 · a negative integer');
eq(jcs(1e30), '1e+30', 'B5 · ★ large exponent uses lowercase e with an EXPLICIT + sign');
eq(jcs(1e-27), '1e-27', 'B6 · small exponent');
eq(jcs(5e-324), '5e-324', 'B7 · ★ smallest subnormal double round-trips');
eq(jcs(1e21), '1e+21', 'B8 · ★ 1e21 is the exponent-notation boundary in ECMAScript');
eq(jcs(1e20), '100000000000000000000', 'B9 · ★ 1e20 stays in positional notation — the boundary is exact');
eq(jcs(9007199254740991), '9007199254740991', 'B10 · Number.MAX_SAFE_INTEGER is exact');
eq(jcs(0.1), '0.1', 'B11 · ★ 0.1 emits shortest round-trip form, not 0.1000000000000000055511151231257827');

throws(() => jcs(NaN), 'JCS_NON_FINITE_NUMBER', 'B12 · ★ NaN MUST error (RFC 8785: "MUST cause ... terminate")');
throws(() => jcs(Infinity), 'JCS_NON_FINITE_NUMBER', 'B13 · ★ Infinity MUST error');
throws(() => jcs(-Infinity), 'JCS_NON_FINITE_NUMBER', 'B14 · ★ -Infinity MUST error');

console.log('\n── C · STRING ESCAPING (§3.2.2.2) ─────────────────────────────────────────────────────────────');

eq(jcs('\b\t\n\f\r'), '"\\b\\t\\n\\f\\r"',
   'C1 · ★ U+0008/09/0A/0C/0D use the five short forms, NOT \\u escapes');
eq(jcs(''), '"\\u000f"',
   'C2 · ★ other C0 controls use LOWERCASE hex \\uhhhh');
eq(jcs(''), '"\\u001f"', 'C3 · U+001F is the top of the escaped control range');
eq(jcs(' '), '" "', 'C4 · U+0020 (space) is NOT escaped — the range ends at U+001F');
eq(jcs('a"b'), '"a\\"b"', 'C5 · double quote is escaped');
eq(jcs('a\\b'), '"a\\\\b"', 'C6 · backslash is escaped');
eq(jcs('a/b'), '"a/b"', 'C7 · ★ forward slash is NOT escaped');
eq(jcs("it's"), '"it\'s"'.replace("\\'", "'"), 'C8 · single quote is NOT escaped');
eq(jcs('€ö'), '"€ö"',
   'C9 · ★ non-ASCII is emitted literally as UTF-8, never \\u-escaped');
eq(jcs('😀'), '"😀"', 'C10 · astral characters are emitted literally');
eq(jcs({ '\n': 1 }), '{"\\n":1}', 'C11 · ★ KEYS are escaped by the same rules as values');

console.log('\n── D · STRUCTURE, LITERALS, EMPTIES ───────────────────────────────────────────────────────────');

eq(jcs(true), 'true', 'D1 · true');
eq(jcs(false), 'false', 'D2 · false');
eq(jcs(null), 'null', 'D3 · null');
eq(jcs({}), '{}', 'D4 · empty object');
eq(jcs([]), '[]', 'D5 · empty array');
eq(jcs({ a: {}, b: [] }), '{"a":{},"b":[]}', 'D6 · nested empties');
eq(jcs([1, [2, [3]]]), '[1,[2,[3]]]', 'D7 · nested arrays');
eq(jcs({ a: 1, b: undefined, c: 2 }), '{"a":1,"c":2}',
   'D8 · ★ undefined MEMBERS are dropped (matches JSON.stringify)');
eq(jcs([1, undefined, 2]), '[1,null,2]',
   'D9 · ★ undefined ARRAY ELEMENTS become null (matches JSON.stringify)');
eq(jcs({ a: null }), '{"a":null}', 'D10 · an explicit null member is KEPT, unlike undefined');
ok(!/\s/.test(jcs({ a: 1, b: [1, 2], c: { d: 3 } })),
   'D11 · ★ no insignificant whitespace anywhere');

console.log('\n── E · THE PRODUCT PROPERTY: a receipt body canonicalizes identically ─────────────────────────');

{
  // The two objects below are the SAME receipt with keys written in a different order — which is exactly
  // what happens when an issuer and a verifier build the body independently.
  const issuer = {
    cosmos_schema: 1, receipt_id: 'rcp_01J8ZK', kid: 'cosmos-receipt-2026-09', decision: 'ALLOW',
    amount_minor: 1200, currency: 'USD', merchant: 'api.openai.com', reason: null,
    checks: [{ name: 'Active', pass: true }, { name: 'Category allowed', pass: true }],
    decided_at: 1788134400000,
  };
  const verifier = {
    decided_at: 1788134400000, reason: null, merchant: 'api.openai.com', currency: 'USD',
    checks: [{ pass: true, name: 'Active' }, { pass: true, name: 'Category allowed' }],
    amount_minor: 1200, decision: 'ALLOW', kid: 'cosmos-receipt-2026-09',
    receipt_id: 'rcp_01J8ZK', cosmos_schema: 1,
  };
  eq(jcs(verifier), jcs(issuer),
     'E1 · ★★ issuer and verifier build the body independently → byte-identical canonical form');

  const tampered = Object.assign({}, issuer, { amount_minor: 1201 });
  ok(jcs(tampered) !== jcs(issuer),
     'E2 · ★ a one-cent change to the amount changes the canonical bytes (so it changes the digest)');

  // Reordering the CHECKS array must change the bytes — checks are a sequence, not a set.
  const reordered = Object.assign({}, issuer, { checks: [issuer.checks[1], issuer.checks[0]] });
  ok(jcs(reordered) !== jcs(issuer),
     'E3 · ★ reordering the checks array changes the bytes — array order is signed, not normalized');
}

console.log('\n── F · HONESTY GUARDS — documented divergences from JSON.stringify and from RFC 8785 ──────────');

eq(jcs(undefined), 'null',
   'F1 · ⚠ top-level undefined → "null", where JSON.stringify returns undefined (deliberate divergence)');
eq(jcs(10n), '10',
   'F2 · ⚠ bigint is an EXTENSION beyond RFC 8785 — JSON has no bigint; do not put one in a receipt');
throws(() => jcs(() => {}), 'JCS_UNSUPPORTED_TYPE', 'F3 · a function is refused, not silently dropped');
throws(() => jcs(Symbol('x')), 'JCS_UNSUPPORTED_TYPE', 'F4 · a symbol is refused');

// RFC 8785 requires numbers be "expressible as IEEE 754 double-precision values". A bigint past 2^53 is
// NOT, and jcs() will happily emit it. That is a real gap in the module — recorded, not hidden.
eq(jcs(9007199254740993n), '9007199254740993',
   'F5 · ⚠ a bigint past 2^53 is emitted verbatim and is NOT RFC-8785-expressible — Cosmos must never emit one');

console.log('\njcs (RFC 8785 vectors): ' + pass + ' passed, ' + fail + ' failed');
if (fail) process.exit(1);
