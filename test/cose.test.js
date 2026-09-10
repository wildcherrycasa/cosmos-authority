// ═══ DETERMINISTIC CBOR + COSE_Sign1 ═══════════════════════════════════════════════════════════════════
//
// The receipt format, converted from bespoke JCS+Ed25519 on 2026-09-05 after that day's research.
// Every signature Cosmos issues now depends on these bytes being what every other CBOR/COSE library
// produces. That is the same interop trap that bit the signing preimage on 2026-09-01, so §C below is
// a REAL cross-implementation vector, not a round-trip through our own decoder.
//
// PROVENANCE OF THE VECTORS — stated because it matters:
//   §C  cose-wg/Examples sign1-tests/sign-pass-01.json — an INDEPENDENT implementation's ToBeSign bytes.
//       This is the only vector here produced by software other than ours.
//   §A  hand-derived from the normative rules quoted in core/cbor.js, plus two values confirmed directly
//       from RFC 8949 prose (10 → 0x0a, 500 → 0x1901f4).
//   ⚠ OPEN: RFC 8949 Appendix A could not be fetched (the RFC truncates before it in every mirror tried).
//     The §A vectors are therefore derived-from-rules, NOT copied from the RFC's own table. Cross-checking
//     the encoder against an independent CBOR library is an OPEN TODO before any receipt ships publicly.
'use strict';
const crypto = require('crypto');
const cbor = require('../core/cbor');
const cose = require('../core/cose');
const { makeKeystore } = require('../core/receipt-keystore');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (a, e, m) => {
  if (a === e) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(e));
  console.log('      actual:   ' + JSON.stringify(a));
};
const throws = (fn, code, m) => {
  try { fn(); fail++; console.log('  ✗ ' + m); console.log('      expected throw ' + code + ', got none'); }
  catch (e) {
    if (String(e.message).includes(code)) { pass++; console.log('  ✓ ' + m); }
    else { fail++; console.log('  ✗ ' + m); console.log('      expected ' + code); console.log('      actual:   ' + e.message); }
  }
};
const hex = (v) => cbor.encode(v).toString('hex');

console.log('\n── A · CBOR PRIMITIVES — preferred (shortest) serialization, RFC 8949 §4.2.1 ─────────────────');

// Head thresholds: 0..23 in the head byte · <256 +uint8 · <65536 +uint16 · <2^32 +uint32 · else +uint64
for (const [v, h, note] of [
  [0, '00', 'zero'], [1, '01', 'one'], [10, '0a', 'ten (RFC-confirmed)'], [23, '17', '23 is the last in-head value'],
  [24, '1818', '★ 24 crosses to +uint8'], [25, '1819', '25'], [100, '1864', '100'],
  [500, '1901f4', '★ 500 (RFC-confirmed)'], [1000, '1903e8', '1000 crosses to +uint16'],
  [1000000, '1a000f4240', '★ 1000000 crosses to +uint32'],
  [65535, '19ffff', '65535 is the last uint16'], [65536, '1a00010000', '★ 65536 crosses to +uint32'],
  [-1, '20', '-1'], [-10, '29', '-10'], [-24, '37', '-24 is the last in-head negative'],
  [-25, '3818', '★ -25 crosses to +uint8'], [-100, '3863', '-100'], [-1000, '3903e7', '-1000'],
  [-8, '27', '★ -8 — the EdDSA algorithm value, IANA-confirmed'],
]) eq(hex(v), h, 'A · ' + note + ' → ' + h);

eq(hex(''), '60', 'A20 · empty text string');
eq(hex('a'), '6161', 'A21 · "a"');
eq(hex('IETF'), '6449455446', 'A22 · "IETF"');
eq(hex('水'), '63e6b0b4', 'A23 · ★ non-ASCII is UTF-8 bytes, length counts BYTES not characters');
eq(hex(Buffer.alloc(0)), '40', 'A24 · empty byte string');
eq(hex(Buffer.from([1, 2, 3, 4])), '4401020304', 'A25 · h\'01020304\'');
eq(hex([]), '80', 'A26 · empty array');
eq(hex([1, 2, 3]), '83010203', 'A27 · [1,2,3]');
eq(hex([1, [2, 3], [4, 5]]), '8301820203820405', 'A28 · nested arrays');
eq(hex({}), 'a0', 'A29 · empty map');
eq(hex(false), 'f4', 'A30 · false');
eq(hex(true), 'f5', 'A31 · true');
eq(hex(null), 'f6', 'A32 · null');

console.log('\n── B · DETERMINISM — the rules that make two implementations agree ───────────────────────────');

// §4.2.1: "The keys in every map MUST be sorted in the bytewise lexicographic order of their
// deterministic encodings." NOT the source strings — and for these keys the two DISAGREE.
//   "10" encodes 62 31 30   ·   "9" encodes 61 39   →  0x61 < 0x62, so "9" comes FIRST.
// A JS .sort() on the source strings would put "10" first. jcs.js sorts source strings (correct for
// RFC 8785); CBOR does not. Getting this backwards silently breaks every third-party verifier.
eq(hex({ '10': 1, '9': 2 }), 'a2613902623130 01'.replace(/ /g, ''),
   'B1 · ★★ map keys sort BYTEWISE ON THE ENCODED BYTES — "9" before "10", the opposite of a string sort');
eq(hex({ b: 2, a: 1 }), 'a2616101616202', 'B2 · insertion order is irrelevant');
eq(hex({ a: 1, b: 2 }), hex({ b: 2, a: 1 }), 'B3 · ★ the same content encodes identically either way');
eq(hex(new Map([[4, 'x'], [1, 'y']])), 'a2016179046178', 'B4 · ★ integer keys sort numerically-by-encoding (1 < 4)');
eq(hex(new Map([['a', 1], [1, 2]])), 'a2010261610 1'.replace(/ /g, ''),
   'B5 · ★ an integer key (0x01) sorts before a text key (0x61)');

throws(() => cbor.encode({ a: 1.5 }), 'CBOR_FLOAT_UNSUPPORTED',
       'B6 · ★★ floats are REFUSED — deterministic float encoding is a trap and minor units never need one');
throws(() => cbor.encode(Number.MAX_SAFE_INTEGER + 2), 'CBOR_INTEGER_UNSAFE', 'B7 · ★ an unsafe integer is refused');
throws(() => cbor.encode(undefined), 'CBOR_UNDEFINED_NOT_ENCODABLE', 'B8 · undefined is refused, not silently dropped');
// A JS Map dedupes [[1,'a'],[1,'b']] on construction, so that proves nothing. The real collision is two
// keys JS considers DISTINCT that encode to the SAME bytes: the number 1 and the bigint 1n both → 0x01.
// Without the guard that silently emits a map with a repeated key, which is invalid CBOR.
throws(() => cbor.encode(new Map([[1, 'a'], [1n, 'b']])), 'CBOR_DUPLICATE_MAP_KEY',
       'B9 · ★★ keys that are distinct in JS but encode identically (1 vs 1n) are refused');
throws(() => cbor.decode(Buffer.from('9f01ff', 'hex')), 'CBOR_INDEFINITE_LENGTH_FORBIDDEN',
       'B10 · ★★ indefinite-length items are REJECTED on decode (§4.2.1 forbids them)');
throws(() => cbor.decode(Buffer.from('8301', 'hex')), 'CBOR_TRUNCATED', 'B11 · a truncated item is refused');

{ const v = { z: [1, 2, { q: null }], a: 'x', n: -7, b: Buffer.from([9]) };
  eq(cbor.encode(cbor.decode(cbor.encode(v))).toString('hex'), cbor.encode(v).toString('hex'),
     'B12 · ★ encode → decode → encode is byte-stable'); }

console.log('\n── C · ★★ INDEPENDENT VECTOR — cose-wg/Examples sign1-tests/sign-pass-01 ─────────────────────');

// The ONLY vector here produced by software other than ours. If our Sig_structure construction disagrees
// with the COSE working group's by a single byte, every signature we issue is unverifiable elsewhere.
const WG_TOBESIGN = '846a5369676e617475726531404054546869732069732074686520636f6e74656e742e';
{
  const tbs = cose.toBeSigned(Buffer.alloc(0), Buffer.from('This is the content.', 'utf8'));
  eq(tbs.toString('hex'), WG_TOBESIGN,
     'C1 · ★★ our ToBeSigned matches the COSE-WG reference byte-for-byte');

  const parts = cbor.decode(tbs);
  eq(parts[0], 'Signature1', 'C2 · ★ the context string is exactly "Signature1"');
  eq(parts.length, 4, 'C3 · Sig_structure is a 4-element array for COSE_Sign1');
  eq(parts[1].length, 0, 'C4 · ★ an empty protected bucket is a ZERO-LENGTH BSTR, not an encoded empty map');
  eq(parts[2].length, 0, 'C5 · ★ external_aad defaults to a zero-length byte string when absent');
  eq(parts[3].toString('utf8'), 'This is the content.', 'C6 · the payload rides as an opaque bstr');
}
eq(cbor.encode(new cbor.Tagged(18, [])).toString('hex').slice(0, 2), 'd2',
   'C7 · ★ CBOR tag 18 (COSE_Sign1) encodes as 0xd2');

console.log('\n── D · PROTECTED HEADER ──────────────────────────────────────────────────────────────────────');

{ const p = cose.protectedHeader('cosmos-1');
  // a2 (map,2) · 01 (alg) 27 (-8 EdDSA) · 04 (kid) 48 (bstr,8) "cosmos-1"
  eq(p.toString('hex'), 'a2012704' + '48' + Buffer.from('cosmos-1').toString('hex'),
     'D1 · ★ protected = {1: -8, 4: h\'cosmos-1\'}, keys in bytewise order');
  const m = cbor.decode(p);
  eq(m.get(1), -8, 'D2 · alg label 1 = EdDSA (-8), IANA-confirmed');
  eq(m.get(4).toString('utf8'), 'cosmos-1', 'D3 · kid label 4 is a bstr');
  ok(Buffer.compare(cbor.encode(1), cbor.encode(4)) < 0, 'D4 · label 1 sorts before label 4');
}
throws(() => cose.protectedHeader(''), 'COSE_KID_REQUIRED', 'D5 · ★ a kid is mandatory — an unattributable receipt is not evidence');

console.log('\n── E · SIGN AND VERIFY, END TO END ───────────────────────────────────────────────────────────');

const KS = makeKeystore({ kid: 'cosmos-receipt-2026-09', privateKeyPkcs8B64:
  crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') });
const KID = KS.activeKid();
const pubOf = (kid) => {
  const spki = KS.publicSpkiOf(kid);
  return spki ? { publicKey: crypto.createPublicKey({ key: Buffer.from(spki, 'base64'), format: 'der', type: 'spki' }), status: KS.statusOf(kid) } : null;
};

const VERDICT = {
  cosmos_schema: 1, decision: 'DENY', reason: 'DAILY_LIMIT',
  grant_id: 'grn_35177b6d0e0e9c95d878', agent_id: 'a1', authorization_id: 'auth_895fe481de9bad669cb1',
  amount_minor: 1400, currency: 'USD', merchant: 'api.openai.com', category: 'api',
  decided_at: 1788666550633,
  checks: [{ name: 'Currency matches grant', pass: true }, { name: 'Under daily cap', pass: false }],
};

const receipt = cose.sign1(VERDICT, KID, (b) => KS.signBytes(b));
ok(Buffer.isBuffer(receipt) && receipt.length > 100, 'E1 · a receipt is produced (' + receipt.length + ' bytes)');
eq(receipt[0], 0xd2, 'E2 · ★ it is a tagged COSE_Sign1 (0xd2)');

{ const v = cose.verify1(receipt, pubOf);
  eq(v.ok, true, 'E3 · ★★ it verifies');
  eq(v.kid, KID, 'E4 · the kid is reported');
  const p = cbor.mapToObject(v.payload);
  eq(p.decision, 'DENY', 'E5 · ★ the verdict survives the round trip');
  eq(p.reason, 'DAILY_LIMIT', 'E6 · …with its reason');
  eq(p.amount_minor, 1400, 'E7 · …and the amount, as an integer');
  ok(Array.isArray(p.checks) && p.checks.length === 2, 'E8 · ★ the per-check breakdown survives — this is the audit trail AWS logs cannot give a third party');
}

// Determinism: the same verdict signed twice must produce identical bytes (Ed25519 is deterministic).
eq(cose.sign1(VERDICT, KID, (b) => KS.signBytes(b)).toString('hex'), receipt.toString('hex'),
   'E9 · ★ signing the same verdict twice is byte-identical');

console.log('\n── F · TAMPERING AND THE FAILURE TAXONOMY ────────────────────────────────────────────────────');

{ // Flip one byte inside the payload region and confirm it fails on the SIGNATURE, specifically.
  const t = Buffer.from(receipt); t[receipt.length - 80] ^= 0x01;
  const v = cose.verify1(t, pubOf);
  eq(v.ok, false, 'F1 · ★★ a one-byte tamper fails');
  eq(v.reason, 'SIGNATURE_INVALID', 'F2 · ★★ …with SIGNATURE_INVALID specifically, not a generic error'); }

{ const t = Buffer.from(receipt); t[t.length - 1] ^= 0xff;
  eq(cose.verify1(t, pubOf).reason, 'SIGNATURE_INVALID', 'F3 · ★ a mangled signature fails'); }

eq(cose.verify1(receipt, () => null).reason, 'KEY_UNKNOWN', 'F4 · ★ an unpublished kid → KEY_UNKNOWN');
eq(cose.verify1(receipt, (k) => Object.assign({}, pubOf(k), { status: 'revoked' })).reason, 'KEY_REVOKED',
   'F5 · ★★ a revoked key → KEY_REVOKED, distinct from unknown and from invalid');
eq(cose.verify1(Buffer.from('deadbeef', 'hex'), pubOf).ok, false, 'F6 · garbage bytes fail without throwing');
eq(cose.verify1(cbor.encode(new cbor.Tagged(98, [Buffer.alloc(0), new Map(), Buffer.alloc(0), Buffer.alloc(64)])), pubOf).reason,
   'COSE_WRONG_TAG', 'F7 · ★ tag 98 (COSE_Sign, multi-signer) is rejected — wrong structure');

{ // A retired key must still verify historical receipts; only revocation stops them.
  const v = cose.verify1(receipt, (k) => Object.assign({}, pubOf(k), { status: 'retired' }));
  eq(v.ok, true, 'F8 · ★★ a RETIRED key still verifies old receipts — rotation does not invalidate history');
  eq(v.keyStatus, 'retired', 'F9 · …and the verifier is told the key was retired'); }

{ // Signed by a different key under the same kid — the dev-key hazard, at the COSE layer.
  const other = makeKeystore({ kid: KID, privateKeyPkcs8B64:
    crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') });
  const foreign = cose.sign1(VERDICT, KID, (b) => other.signBytes(b));
  eq(cose.verify1(foreign, pubOf).reason, 'SIGNATURE_INVALID',
     'F10 · ★★ same kid, different key → rejected. A kid is a hint, never a proof.'); }

console.log('\n── G · keystore.signBytes ────────────────────────────────────────────────────────────────────');

ok(Buffer.isBuffer(KS.signBytes(Buffer.from('abc'))) && KS.signBytes(Buffer.from('abc')).length === 64,
   'G1 · signBytes returns a raw 64-byte Ed25519 signature');
eq(KS.signBytes(Buffer.from('abc')).toString('hex'), KS.signBytes(Buffer.from('abc')).toString('hex'),
   'G2 · ★ Ed25519 is deterministic — same message, same signature');
throws(() => KS.signBytes('a string'), 'INVALID_SIGN_INPUT', 'G3 · ★ a string is refused — the contract is bytes');
throws(() => makeKeystore({ allowDevKey: false }).signBytes(Buffer.from('x')), 'RECEIPT_SIGNER_UNAVAILABLE',
       'G4 · ★★ signBytes fails closed with no signer, exactly like sign()');
ok(KS.sign(crypto.createHash('sha256').update('x').digest('hex')).signature.length > 0,
   'G5 · ★ the original digest-based sign() still works — 78 existing vectors keep passing');

console.log('\ncose + cbor: ' + pass + ' passed, ' + fail + ' failed');
if (fail) process.exit(1);
