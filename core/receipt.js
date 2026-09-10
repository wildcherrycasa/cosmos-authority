// ═══ RECEIPT — the product ═════════════════════════════════════════════════════════════════════════════
//
// A signed, portable, cross-vendor statement that policy P, evaluated at time T, returned this VERDICT —
// verifiable offline by a party with no account anywhere. Per the 2026-09-05 research this is the one
// thing AWS AgentCore does not emit (its evidence is CloudWatch logs) and the one thing AP2 does not sign
// (it signs intent, not verdict). Everything else in core/ is table stakes; this file is the bet.
//
// Envelope: COSE_Sign1 (RFC 9052), SCITT-shaped (RFC 9943), Ed25519, deterministic CBOR payload. The kid
// lives in the PROTECTED header, which the signature covers — tampering with it fails as SIGNATURE_INVALID
// rather than as a misleading KEY_UNKNOWN.
//
// Payload rules: integers only (no floats — cbor.js refuses them), no undefined, strings/bools/null/arrays/
// maps. Everything a stranger needs to understand the decision is inside; nothing secret is.
'use strict';
const cose = require('./cose');
const cbor = require('./cbor');
const CC = require('./capability-commitment');
const { spkiFromRawB64url } = require('./receipt-keystore');

// SCHEMA 2 (2026-09-06): adds `approver_authenticated`. BUMPED RATHER THAN ADDED SILENTLY, on purpose.
// A field a reader may ignore is fine; this one is load-bearing for INTERPRETATION — a verifier that does
// not know it exists would print `approver_id=ops-1` with no qualifier, which is the exact misreading the
// field is there to prevent. Bumping makes an old verifier fail closed with UNSUPPORTED_SCHEMA instead of
// silently under-reporting. Free to do today: zero receipts exist outside `demo/`, which is regenerated
// from source (`npm run demo`). It will NOT be free once a receipt is in someone's audit file.
// SCHEMA 3 (2026-09-08): adds the six `rail_*` fields carrying a settlement report. Bumped for the SAME
// reason 2 was, and the reason is worth repeating because it is the one lesson this repo has paid for
// twice: `rail_reported_by` is load-bearing for INTERPRETATION. A verifier that does not know it exists
// would print `rail_tx_id=0xabc` beside a valid signature, and the only natural reading of that — "Cosmos
// saw this payment settle" — is FALSE. Cosmos cannot see a rail (decision (a)). It saw a report, from a
// holder of one of two credential classes, and the field says which. An old verifier must therefore fail
// closed with UNSUPPORTED_SCHEMA rather than under-report. Still free today: nothing is published, and
// `demo/` is regenerated from source by `npm run demo`.
// SCHEMA 4 (2026-09-09): adds `rail_state`, by the same rule as 2 and 3. `rail_outcome: 'failed'` used to
// mean only "did not execute"; with `rail_state` it can also carry a Writ `reversed` — executed, then
// undone. An old verifier would read the newer receipt as the older claim, and be wrong the costly way.
const SCHEMA = 4;

// ⛳ WHAT A VERIFIER ACCEPTS IS A DIFFERENT QUESTION FROM WHAT AN ISSUER WRITES, and conflating them cost
// nothing today only because nothing is published yet (review, Ramu, 2026-09-08). The two directions are
// not symmetric:
//   · an OLD verifier reading a NEW receipt MUST fail closed. It does, automatically and forever: every
//     released verifier hardcodes its own number, so a schema it has never heard of is UNSUPPORTED_SCHEMA.
//     That is the whole reason to bump, and it is the direction that protects a reader.
//   · a NEW verifier reading an OLD receipt has nothing to under-report — a schema-2 receipt carries no
//     `rail_*` fields, so there is no claim it could print without its qualifier. Rejecting it buys no
//     safety at all and destroys every receipt already in someone's audit file.
// So ACCEPTED is a SET and ISSUED is a single number. Publishing this rule now costs nothing; discovering
// it after a customer has archived a receipt costs them their evidence.
// ⚠ A schema may be added here ONLY if every field a reader could over-trust in it is still printed with
// its caveat. That is a judgement each addition has to re-make, not a licence to widen the set.
const ACCEPTED_SCHEMAS = [2, 3, 4];

// Build the verdict payload from an authorize decision. Every field is CBOR-safe by construction.
function buildPayload(d) {
  const checks = (d.checks || []).map((c) => ({ name: String(c.name), pass: !!c.pass }));
  let capability_proof = null;
  if (d.category && Array.isArray(d.allowed_categories) && d.allowed_categories.includes(d.category)) {
    const tree = CC.commitCapabilities(d.allowed_categories.map((c) => ({ type: 'category', value: c }))).tree;
    const p = CC.membershipProof(tree, { type: 'category', value: d.category });
    if (p) capability_proof = { cap: { type: p.cap.type, value: p.cap.value }, path: p.path.map((s) => ({ hash: s.hash, right: !!s.right })) };
  }
  return {
    cosmos_schema: SCHEMA,
    receipt_id: String(d.authorization_id),
    decision: String(d.decision),
    reason: d.reason == null ? null : String(d.reason),
    org_id: String(d.org_id), grant_id: String(d.grant_id), agent_id: String(d.agent_id),
    amount_minor: Math.trunc(+d.amount_minor), currency: String(d.currency),
    merchant: d.merchant == null ? null : String(d.merchant),
    category: d.category == null ? null : String(d.category),
    intent_hash: String(d.intent_hash), envelope_hash: String(d.envelope_hash),
    policy_version: Math.trunc(+d.policy_version), policy_hash: String(d.policy_hash),
    capability_root: String(d.capability_root),
    capability_proof,
    checks,
    idempotency_key: String(d.idempotency_key),
    decided_at: Math.trunc(+d.decided_at),
    expires_at: d.expires_at == null ? null : Math.trunc(+d.expires_at),
    // Approval chain (null on a first-pass decision). approver_id is client-asserted — the receipt records
    // who CLAIMED to approve and via which channel; it does not authenticate them.
    parent_receipt_id: d.parent_receipt_id == null ? null : String(d.parent_receipt_id),
    approver_id: d.approver_id == null ? null : String(d.approver_id),
    approval_channel: d.approval_channel == null ? null : String(d.approval_channel),
    // ★ THE DISCLAIMER BELONGS IN THE SIGNED BYTES, NOT IN A SOURCE COMMENT (2026-09-06, review finding).
    // The two lines above told the truth to anyone reading this file. Nobody reading a RECEIPT reads this
    // file. A verifier printed `approver_id=ops-1` next to a valid signature, and the only honest reading of
    // that — "the signature proves ops-1 approved" — was false: it proves the receipt was not tampered with,
    // and that SOMEBODY TOLD COSMOS ops-1 approved. For a product whose whole claim is evidence an auditor
    // relies on, shipping a signed field whose provenance lives in a comment is the defect, not the auth gap
    // itself. So the artifact now states its own epistemic limit, and a verifier must print it.
    // false = the identity was asserted by the caller and never checked. There is no authentication in the
    // API surface today, so this is false on every approval Cosmos has ever issued. When an authenticated
    // path exists it may be true — and then the field carries real information instead of a constant.
    approver_authenticated: d.approver_id == null ? null : (d.approver_authenticated === true),
    // ── RAIL REPORT (null on every receipt that is not a settlement report) ───────────────────────────
    // Cosmos never moves money and never observes a rail, so every one of these is a CLAIM. What the
    // signature proves is that the claim was made against this authorization, by a holder of the
    // credential class named in `rail_reported_by`, at `rail_reported_at`. It proves nothing about a
    // blockchain, a bank, or a balance. `rail_reported_by` is the honest half and is why the schema moved:
    //   'rail'         — the rail's own token PLUS the capability it was handed; the only class that may
    //                    report `failed`, because that is the one direction that returns budget
    //   'operator'     — the shared operator secret; may record a settlement, may not reverse one
    //   'allow_holder' — the token from the ALLOW response, held by the REQUESTER; `submitted` only
    // `rail_late` = true means the reservation had already auto-reversed when this settlement arrived: the
    // TTL guessed wrong, and the spend was re-reserved. See api/settlements.js.
    rail_outcome: d.rail_outcome == null ? null : String(d.rail_outcome),
    // The reporter's own state word, verbatim and unmapped — see core/rail.js validateReport for why a
    // `reversed` payment arrives as outcome `failed` with state `reversed`, and why collapsing the two
    // would lose the only fact an auditor cares about.
    rail_state: d.rail_state == null ? null : String(d.rail_state),
    rail_tx_id: d.rail_tx_id == null ? null : String(d.rail_tx_id),
    rail_provider: d.rail_provider == null ? null : String(d.rail_provider),
    rail_reported_by: d.rail_reported_by == null ? null : String(d.rail_reported_by),
    rail_reported_at: d.rail_reported_at == null ? null : Math.trunc(+d.rail_reported_at),
    rail_late: d.rail_outcome == null ? null : (d.rail_late === true),
  };
}

// Sign a payload with the keystore's ACTIVE key. Returns raw COSE bytes plus the kid used.
function issue(payload, keystore) {
  const kid = keystore.activeKid();
  if (!kid) throw new Error('RECEIPT_SIGNER_UNAVAILABLE');
  const bytes = cose.sign1(payload, kid, (b) => keystore.signBytes(b));
  return { cose: bytes, kid, receipt_id: payload.receipt_id };
}

// Structural open — NO verification. For display only.
function open(bytes) {
  const p = cose.parse(bytes);
  return { kid: p.kid, alg: p.alg, payload: cbor.mapToObject(p.payload) };
}

// Build a resolveKey(kid) from a published JWKS — exactly what a stranger does.
function resolverFromJwks(jwks) {
  const crypto = require('crypto');
  const keys = (jwks && Array.isArray(jwks.keys)) ? jwks.keys : [];
  return (kid) => {
    const k = keys.find((x) => x && x.kid === kid && x.kty === 'OKP' && x.crv === 'Ed25519' && typeof x.x === 'string');
    if (!k) return null;
    let spki;
    try { spki = spkiFromRawB64url(k.x); } catch (_) { return null; }
    return { publicKey: crypto.createPublicKey({ key: Buffer.from(spki, 'base64'), format: 'der', type: 'spki' }), status: k.status || 'active' };
  };
}

// Full offline verification: signature against the JWKS, then the capability proof against the root.
function verify(bytes, jwks) {
  const v = cose.verify1(bytes, resolverFromJwks(jwks));
  if (!v.ok) return v;
  const payload = cbor.mapToObject(v.payload);
  if (ACCEPTED_SCHEMAS.indexOf(payload.cosmos_schema) === -1) return { ok: false, reason: 'UNSUPPORTED_SCHEMA', schema: payload.cosmos_schema };
  if (payload.capability_proof) {
    const okCap = CC.verifyMembership(payload.capability_root, payload.capability_proof);
    if (!okCap) return { ok: false, reason: 'CAPABILITY_PROOF_INVALID', kid: v.kid };
  }
  return { ok: true, kid: v.kid, keyStatus: v.keyStatus, payload };
}

module.exports = { buildPayload, issue, open, verify, resolverFromJwks, SCHEMA, ACCEPTED_SCHEMAS };
