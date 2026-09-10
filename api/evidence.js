// ═══ GET /evidence/:id  and  GET /.well-known/jwks.json ════════════════════════════════════════════════
//
// The third call, and the key publication without which it is pointless. /evidence returns the receipt
// exactly as issued — the base64 COSE bytes are the canonical artifact; the decoded payload is a
// convenience and is labelled UNVERIFIED because a reader must verify the bytes themselves, not trust
// this server's rendering of them. That is the whole point of the product.
//
// Two representations of ONE artifact: JSON by default, and the raw COSE_Sign1 bytes under
// `Accept: application/cose`. They are byte-identical after base64-decoding — asserted, not assumed.
'use strict';
const receipt = require('../core/receipt');
const { HttpError } = require('./http');

function findReceipt(events, authId) {
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e && e.kind === 'receipt' && e.authId === authId) return e;
  }
  return null;
}

// `Accept: application/cose` (RFC 9052 §14.4.1) → the COSE_Sign1 bytes themselves, no JSON around them.
// Anything else, including a missing header and `*/*`, keeps the JSON envelope: the default must not
// change under a browser or a bare curl. A q=0 on the type is an explicit refusal and is honoured.
function wantsCose(accept) {
  for (const part of String(accept || '').split(',')) {
    const [type, ...params] = part.trim().split(';').map((s) => s.trim());
    if (type.toLowerCase() !== 'application/cose') continue;
    const q = params.map((p) => /^q=(.+)$/i.exec(p)).find(Boolean);
    return !(q && parseFloat(q[1]) === 0);
  }
  return false;
}

function makeEvidenceRoute(store, keystore) {
  return async function evidence(_body, params, req) {
    const id = String(params.id || '');
    // `stl_` is a SETTLEMENT report receipt (api/settlements.js) and is fetched exactly like an
    // authorization receipt. It gets its own id rather than reusing the authorization's on purpose: this
    // lookup walks backwards and returns the NEWEST match, so a shared id would let a settlement shadow
    // the ALLOW receipt it descends from — and the chain is the evidence, so losing either end loses it.
    if (!/^(?:auth|stl)_[0-9a-f]{20}$/.test(id)) throw new HttpError(400, 'INVALID_RECEIPT_ID');
    const e = findReceipt(store.events(), id);
    if (!e) throw new HttpError(404, 'RECEIPT_NOT_FOUND');
    const bytes = Buffer.from(e.cose, 'base64');
    if (wantsCose(req && req.headers && req.headers.accept)) {
      return { status: 200, raw: bytes, contentType: 'application/cose',
        // The key that verifies these bytes is not in them; a raw fetch would otherwise have nowhere to go.
        headers: { link: '</.well-known/jwks.json>; rel="jwks"', 'x-cosmos-kid': String(e.kid) } };
    }
    let opened = null;
    try { opened = receipt.open(bytes); } catch (_) { /* served verbatim regardless */ }
    // Self-check against our OWN published JWKS, so an operator sees a broken key immediately.
    const self = receipt.verify(bytes, keystore.jwks());
    return {
      status: 200,
      body: {
        receipt_id: id, kid: e.kid, issued_at: e.ts,
        format: 'COSE_Sign1 (RFC 9052), Ed25519, deterministic CBOR (RFC 8949 §4.2)',
        cose_base64: e.cose,
        payload_unverified: opened ? opened.payload : null,
        self_check: self.ok ? 'ok' : self.reason,
        jwks: '/.well-known/jwks.json',
        verify: 'python verifier/cosmos_verify.py <this json> <jwks json>',
      },
    };
  };
}

function makeJwksRoute(keystore) {
  return async function jwks() { return { status: 200, body: keystore.jwks() }; };
}

module.exports = { makeEvidenceRoute, makeJwksRoute, findReceipt, wantsCose };
