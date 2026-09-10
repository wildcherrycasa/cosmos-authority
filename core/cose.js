// ═══ COSE_Sign1 (RFC 9052) — the receipt envelope ══════════════════════════════════════════════════════
//
// WHY THIS REPLACED THE BESPOKE JCS+Ed25519 FORMAT (decision 2026-09-05, from that day's research):
// the differentiator IS the format. A format only Cosmos implements is not evidence, it is a private log.
// RFC 9943 (SCITT, Standards Track, June 2026) already standardises an offline-verifiable receipt as a
// COSE_Sign1 object and is explicitly content-agnostic — it leaves the payload to the implementer. Cosmos
// supplies the payload RFC 9943 deliberately leaves undefined: the authorization VERDICT.
//
// Verified against primary sources 2026-09-05:
//   RFC 9052 — COSE_Sign1 is CBOR tag 18 wrapping [protected, unprotected, payload, signature].
//              Sig_structure = ["Signature1", protected, external_aad, payload].
//              external_aad "defaults to a zero-length byte string" when absent.
//              protected is "obtained by CBOR encoding the protected map and wrapping it in a bstr".
//   IANA COSE registries — alg label 1, kid label 4 (bstr), EdDSA algorithm value -8.
//
// Ed25519 signs the ToBeSigned bytes DIRECTLY (it hashes internally). There is no separate digest step, so
// the ASCII-hex-vs-raw-bytes trap that bit the old format on 2026-09-01 cannot recur here.
'use strict';
const cbor = require('./cbor');

const TAG_COSE_SIGN1 = 18;
const LABEL_ALG = 1, LABEL_KID = 4;
const ALG_EDDSA = -8;
const CONTEXT_SIGN1 = 'Signature1';

// The protected bucket: a deterministic CBOR map, wrapped in a bstr by the outer structure.
function protectedHeader(kid) {
  if (typeof kid !== 'string' || !kid) throw new Error('COSE_KID_REQUIRED');
  return cbor.encode(new Map([[LABEL_ALG, ALG_EDDSA], [LABEL_KID, Buffer.from(kid, 'utf8')]]));
}

// RFC 9052 §4.4. This is the exact byte string that gets signed and re-derived by a verifier.
function toBeSigned(protectedBstr, payloadBstr, externalAad) {
  return cbor.encode([CONTEXT_SIGN1, protectedBstr, externalAad || Buffer.alloc(0), payloadBstr]);
}

// signFn(bytes) -> raw signature Buffer. Kept as a callback so this module never touches a private key.
function sign1(payload, kid, signFn, opts) {
  const prot = protectedHeader(kid);
  const payloadBstr = Buffer.isBuffer(payload) ? payload : cbor.encode(payload);
  const sig = signFn(toBeSigned(prot, payloadBstr, opts && opts.externalAad));
  if (!Buffer.isBuffer(sig) || sig.length !== 64) throw new Error('COSE_BAD_SIGNATURE_LENGTH');
  return cbor.encode(new cbor.Tagged(TAG_COSE_SIGN1, [prot, new Map(), payloadBstr, sig]));
}

// Structural parse only — NO signature check. Never treat a parsed object as verified.
function parse(bytes) {
  const item = cbor.decode(bytes);
  const tagged = item instanceof cbor.Tagged;
  if (tagged && item.tag !== TAG_COSE_SIGN1) throw new Error('COSE_WRONG_TAG:' + item.tag);
  const arr = tagged ? item.value : item;
  if (!Array.isArray(arr) || arr.length !== 4) throw new Error('COSE_MALFORMED');
  const [protectedBstr, unprotected, payloadBstr, signature] = arr;
  if (!Buffer.isBuffer(protectedBstr) || !Buffer.isBuffer(payloadBstr) || !Buffer.isBuffer(signature)) {
    throw new Error('COSE_MALFORMED');
  }
  const hdr = protectedBstr.length ? cbor.decode(protectedBstr) : new Map();
  if (!(hdr instanceof Map)) throw new Error('COSE_MALFORMED_PROTECTED');
  const kidBuf = hdr.get(LABEL_KID);
  return {
    tagged, protectedBstr, payloadBstr, signature, unprotected,
    alg: hdr.get(LABEL_ALG),
    kid: Buffer.isBuffer(kidBuf) ? kidBuf.toString('utf8') : null,
    payload: cbor.decode(payloadBstr),
  };
}

// resolveKey(kid) -> { publicKey: crypto.KeyObject, status: 'active'|'retired'|'revoked' } | null
// Returns a structured result rather than throwing, so a verifier can report the SPECIFIC failure. A
// generic "invalid" is useless to someone deciding whether a receipt was forged or their tooling is wrong.
function verify1(bytes, resolveKey, opts) {
  const crypto = require('crypto');
  let p;
  try { p = parse(bytes); }
  catch (e) { return { ok: false, reason: String(e.message).split(':')[0] || 'COSE_MALFORMED' }; }

  if (p.alg !== ALG_EDDSA) return { ok: false, reason: 'COSE_UNSUPPORTED_ALG', alg: p.alg, kid: p.kid };
  if (!p.kid) return { ok: false, reason: 'COSE_KID_MISSING' };

  const found = resolveKey(p.kid);
  if (!found || !found.publicKey) return { ok: false, reason: 'KEY_UNKNOWN', kid: p.kid };
  if (found.status === 'revoked') return { ok: false, reason: 'KEY_REVOKED', kid: p.kid };

  const tbs = toBeSigned(p.protectedBstr, p.payloadBstr, opts && opts.externalAad);
  let good = false;
  try { good = crypto.verify(null, tbs, found.publicKey, p.signature); } catch (_) { good = false; }
  if (!good) return { ok: false, reason: 'SIGNATURE_INVALID', kid: p.kid };

  return { ok: true, kid: p.kid, keyStatus: found.status || 'active', payload: p.payload, parsed: p };
}

module.exports = {
  sign1, verify1, parse, toBeSigned, protectedHeader,
  TAG_COSE_SIGN1, LABEL_ALG, LABEL_KID, ALG_EDDSA, CONTEXT_SIGN1,
};
