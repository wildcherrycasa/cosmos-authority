// ═══ POST /authorize — the decision ════════════════════════════════════════════════════════════════════
// Order of operations, and why each step sits where it does:
//   1. validate           — amount <= 0 is a 400, NOT a signed DENY (envelope.build throws, DESIGN Gap 4)
//   2. load grant         — 404
//   3. idempotency        — replay does not dedupe, so a replay must never reserve twice (replay E1)
//   4. LOCK the grant     — read-budget -> decide -> write-spend must be atomic per grant
//   5. sweep expirations  — real reversal events, so the audit stays clean (DESIGN §7)
//   6. decide             — currency check, then guardrails, then the approval line
//   7. envelope + append  — evidence bound BEFORE the answer leaves
'use strict';
const { jcs } = require('../core/jcs');
const replay = require('../core/replay');
const view = require('../core/agent-view');
const approvals = require('../core/approvals');
const envelope = require('../core/authorization-envelope');
const receipt = require('../core/receipt');
const rail = require('../core/rail');
const { loadGrants, newId, sha, isInt, need } = require('./grants');
const { HttpError } = require('./http');

// DESIGN §7 default: 5 minutes. NOT measured against any real rail — it is a guess, and it is the
// tradeoff between leaking budget on a failed payment and reversing a slow-but-successful one.
// Overridable so the sweep is testable without waiting five minutes.
const RESERVATION_TTL_MS = +process.env.COSMOS_RESERVATION_TTL_MS || 5 * 60 * 1000;

// Reservations whose TTL passed with no reversal. Cosmos cannot see the rail (decision (a)), so an ALLOW
// that never executed must give its budget back or the grant leaks. Returns REAL reversal events rather
// than computing a virtual balance: a virtual one would make the on-disk log disagree with live state and
// `npm run audit:ledger` would report drift forever.
// ⛳ THE RAIL SPEAKS HERE, and this is where the TTL stops being a guess (core/rail.js, DESIGN §7):
//   · `submission` PUSHES the deadline out — a rail that says "in flight" is no longer racing a timer it
//     was never told about, which was the failure mode the 5-minute default could not avoid.
//   · `settlement` REMOVES the row entirely — settled or failed, there is nothing left to auto-reverse,
//     and a settled spend must never be handed back.
// A rail that says nothing is unchanged: the TTL still reverses it, which is still every rail Cosmos has
// actually talked to. The handoff makes the guess unnecessary; it does not remove the fallback.
function expiredReservations(events, grantId, now) {
  const open = new Map();
  for (const e of events) {
    if (!e || e.agentId !== grantId || !e.authId) continue;
    if (e.kind === 'reservation') open.set(e.authId, { amount: e.amount, deadline: e.expiresAt || 0 });
    else if (e.kind === 'reversal') open.delete(e.authId);
    else if (e.kind === 'submission') { const r = open.get(e.authId); if (r && e.expiresAt > r.deadline) r.deadline = e.expiresAt; }
    else if (e.kind === 'settlement') open.delete(e.authId);
  }
  const out = [];
  for (const [authId, r] of open) {
    if (r.deadline && now > r.deadline) {
      out.push({ kind: 'reversal', ts: now, authId, agentId: grantId, amount: r.amount, reason: 'RESERVATION_EXPIRED' });
    }
  }
  return out;
}

// `railHint` is passed in, never read from the environment here — same rule as core/rail.js and
// core/receipt-keystore.js. { provider, endpoint }, both optional; a null provider still issues the
// capability, because a rail willing to report back is useful whether or not Cosmos was told its name.
function makeAuthorizeRoute(store, keystore, railHint, ttlMs) {
  if (!keystore) throw new Error('AUTHORIZE_REQUIRES_KEYSTORE');
  const hint = railHint || {};
  // Per-server override. The env default is read once at module load, which makes the expiry path
  // untestable in-process without waiting out the real TTL — and an untested expiry path is how the
  // LATE-settlement case (api/settlements.js, question 2) would have shipped on reasoning alone.
  const ttl = ttlMs > 0 ? ttlMs : RESERVATION_TTL_MS;
  return async function authorize(body) {
    need(typeof body.grant_id === 'string' && body.grant_id, 'GRANT_ID_REQUIRED');
    need(isInt(body.amount_minor) && body.amount_minor > 0, 'INVALID_AMOUNT_MINOR', 'a positive integer in minor units');
    need(typeof body.currency === 'string' && body.currency, 'CURRENCY_REQUIRED');
    need(typeof body.idempotency_key === 'string' && body.idempotency_key, 'IDEMPOTENCY_KEY_REQUIRED');
    if (body.category != null) need(typeof body.category === 'string', 'INVALID_CATEGORY');
    if (body.merchant != null) need(typeof body.merchant === 'string', 'INVALID_MERCHANT');
    if (body.description != null) need(typeof body.description === 'string', 'INVALID_DESCRIPTION');

    const grant = loadGrants(store.events())[body.grant_id];
    if (!grant) throw new HttpError(404, 'GRANT_NOT_FOUND');

    const cached = store.getIdem(grant.grant_id, body.idempotency_key);
    if (cached) return { status: 200, body: Object.assign({}, cached, { idempotent_replay: true }) };

    return store.withLock(grant.grant_id, async () => {
      // Re-check inside the lock: a concurrent caller with the same key may have just written it.
      const again = store.getIdem(grant.grant_id, body.idempotency_key);
      if (again) return { status: 200, body: Object.assign({}, again, { idempotent_replay: true }) };

      const now = Date.now();
      const sweep = expiredReservations(store.events(), grant.grant_id, now);
      if (sweep.length) await store.append(sweep);

      const events = store.events();
      const v = view.agentView(grant, replay.replay(events), events, now);
      const g = view.decide(grant, v, body.amount_minor, body.currency, body.category);

      let decision = g.approved ? 'ALLOW' : 'DENY';
      let reason = g.reason;
      // The approval line is checked only on a spend that would otherwise be allowed — a DENY does not
      // become an ESCALATE. A pending approval reserves nothing and moves nothing (approvals.js header).
      if (g.approved && approvals.needsApproval(v, body.amount_minor, null)) {
        decision = 'ESCALATE';
        reason = 'APPROVAL_REQUIRED';
      }

      const authId = newId('auth');                                    // 25 chars — replay G6 needs >= 13
      const intent = {
        grant_id: grant.grant_id, amount_minor: body.amount_minor, currency: body.currency,
        merchant: body.merchant || null, category: body.category || null,
        // The description is HASHED, never carried: the envelope's secret guard inspects key names only,
        // so free text in a value would pass straight through (test/authorization-envelope.test.js C17).
        description_hash: body.description == null ? null : sha(body.description),
      };
      const intentHash = sha(jcs(intent));
      const auditHash = sha(jcs(g.checks));
      const expiresAt = now + ttl;

      // asset and network are set EXPLICITLY. Omitted, '' and 'USDC' all collide on one hash because
      // canon() uses `String(e.asset || 'USDC')` (envelope F3-F5) — a default is not something to lean on.
      const env = envelope.build({
        orgId: grant.org_id, agentId: grant.agent_id, authId, intentHash,
        amountMinor: body.amount_minor, asset: grant.currency, network: 'none',
        category: body.category || null, merchant: body.merchant || null,
        credentialFingerprint: sha(grant.grant_id + '|' + grant.capability_root),
        policyVersion: grant.policy_version, policyHash: grant.policy_hash,
        budgetResult: decision, idempotencyKey: body.idempotency_key,
        authorizedAt: now, expiresAt, auditHash,
      });

      const decided = {
        decision, reason: reason || null,
        authorization_id: authId, org_id: grant.org_id, grant_id: grant.grant_id, agent_id: grant.agent_id,
        amount_minor: body.amount_minor, currency: grant.currency,
        merchant: body.merchant || null, category: body.category || null,
        expires_at: decision === 'ALLOW' ? expiresAt : null,
        intent_hash: intentHash, envelope_hash: env.hash,
        policy_version: grant.policy_version, policy_hash: grant.policy_hash,
        capability_root: grant.capability_root, allowed_categories: grant.allowed_categories,
        checks: g.checks.map((c) => ({ name: c.name, pass: c.pass })),   // cloned — replay aliases (A5)
        idempotency_key: body.idempotency_key, decided_at: now,
      };

      // THE RECEIPT is signed INSIDE the lock and appended in the SAME batch as the decision, so an
      // ALLOW is never acknowledged without its evidence being durable. Signing fails closed: no active
      // key -> no decision is recorded at all (RECEIPT_SIGNER_UNAVAILABLE -> 503).
      let issued;
      try { issued = receipt.issue(receipt.buildPayload(decided), keystore); }
      catch (e) { throw new HttpError(503, 'RECEIPT_SIGNER_UNAVAILABLE', String(e.message)); }

      const records = [{
        kind: 'decision', ts: now, authId, agentId: grant.grant_id,
        amount: body.amount_minor, category: body.category || null, merchant: body.merchant || null,
        approved: decision === 'ALLOW', checks: g.checks, reason,
        idempotencyKey: body.idempotency_key, decisionKind: decision,
        envelopeHash: env.hash, intentHash,
      }];
      // The settlement capability: minted here, its HASH written to the durable reservation, the raw token
      // returned exactly once below. Cosmos stores no copy it could hand out again — that is the property
      // that makes a leaked event log useless for forging a settlement, and its cost is stated in
      // rehydrateIdem() at the bottom of this file.
      const cap = decision === 'ALLOW' ? rail.mintCapability(authId) : null;
      if (decision === 'ALLOW') {
        records.push({ kind: 'reservation', ts: now, authId, agentId: grant.grant_id,
                       amount: body.amount_minor, merchant: body.merchant || null, expiresAt,
                       railTokenHash: cap.hash });
      }
      if (decision === 'ESCALATE') {
        records.push({ kind: 'approval_request', ts: now, commandId: authId, agentId: grant.grant_id,
                       amount: body.amount_minor, category: body.category || null, source: 'api',
                       idempotencyKey: body.idempotency_key });
      }
      // `receipt` is an UNKNOWN kind to replay.js and therefore inert there (test/replay.test.js B1-B7).
      records.push({ kind: 'receipt', ts: now, authId, agentId: grant.grant_id, kid: issued.kid,
                     cose: issued.cose.toString('base64') });
      await store.append(records);       // resolves only after fsync — never ack a spend that can vanish

      // The pending-approval map is a cache of the log. rehydrate() fills it at BOOT from approval_request
      // events; a fresh ESCALATE in a running process must be recorded here too, or it can never be
      // resolved until the next restart. (Found by the MCP elicitation test: /approvals returned 404.)
      if (decision === 'ESCALATE') {
        approvals.record({ command_id: authId, type: 'SPEND', source: 'api', agentId: grant.grant_id,
                           amount: body.amount_minor, category: body.category || null, idempotencyKey: body.idempotency_key, ts: now });
      }

      const resp = Object.assign({}, decided, {
        allowed_categories: undefined,   // grant-private; the receipt carries a membership PROOF instead
        signed: true, kid: issued.kid, receipt_id: authId,
        evidence: '/evidence/' + authId, jwks: '/.well-known/jwks.json',
        // ⛳ THE HANDOFF. An ALLOW used to be a decision with no ending: it said yes and then Cosmos went
        // blind. This tells the caller where to take it and how the rail reports back — and `handoff_token`
        // appears in this response and NOWHERE else, ever again. Cosmos never calls the endpoint; decision
        // (a) is that it does not touch the money and it does not talk to the rail either. It hands the
        // agent an address and waits to be told.
        rail: decision !== 'ALLOW' ? null : {
          provider: hint.provider || null,
          endpoint: hint.endpoint || null,
          report_to: '/settlements/' + authId,
          outcomes: rail.OUTCOMES,
          handoff_token: cap.token,
          reservation_deadline: expiresAt,
        },
      });
      delete resp.allowed_categories;
      store.putIdem(grant.grant_id, body.idempotency_key, resp);
      return { status: 200, body: resp };
    });
  };
}

// Rebuild the idempotency index from history at boot. Without this a restart lets a retried request
// reserve a SECOND time — replay does not dedupe (test/replay.test.js E1), so the double-count is
// permanent. The in-memory Map is a cache of the log, never the source of truth.
function rehydrateIdem(store) {
  const grants = loadGrants(store.events());
  const receipts = new Map();                       // authId -> kid, from durable receipt events
  for (const e of store.events()) if (e && e.kind === 'receipt' && e.authId) receipts.set(e.authId, e.kid || null);
  let n = 0;
  for (const e of store.events()) {
    if (!e || e.kind !== 'decision' || !e.idempotencyKey) continue;
    const grant = grants[e.agentId];
    if (!grant) continue;
    const signed = receipts.has(e.authId);
    store.putIdem(grant.grant_id, e.idempotencyKey, {
      decision: e.decisionKind || (e.approved ? 'ALLOW' : 'DENY'),
      reason: e.reason || null,
      authorization_id: e.authId, org_id: grant.org_id, grant_id: grant.grant_id, agent_id: grant.agent_id,
      amount_minor: e.amount, currency: grant.currency, merchant: e.merchant || null, category: e.category || null,
      expires_at: null, intent_hash: e.intentHash || null, envelope_hash: e.envelopeHash || null,
      policy_version: grant.policy_version, policy_hash: grant.policy_hash,
      capability_root: grant.capability_root,
      checks: (e.checks || []).map((c) => ({ name: c.name, pass: c.pass })),
      idempotency_key: e.idempotencyKey, decided_at: e.ts,
      signed, kid: signed ? receipts.get(e.authId) : null, receipt_id: signed ? e.authId : null,
      evidence: signed ? '/evidence/' + e.authId : null, jwks: '/.well-known/jwks.json',
      // ⚠ THE COST OF STORING ONLY THE HASH, stated where it bites rather than discovered later. The raw
      // settlement capability lived in the original ALLOW response and in no durable place, so a request
      // replayed after a restart gets the authorization back WITHOUT a usable token. That is deliberate:
      // a token Cosmos can re-serve is a token an attacker with the log can mint. A caller that lost it
      // has two ways forward — the operator token, or a fresh /authorize with a new idempotency key.
      rail: null,
      rehydrated: true,
    });
    n++;
  }
  return n;
}

module.exports = { makeAuthorizeRoute, expiredReservations, rehydrateIdem, RESERVATION_TTL_MS };
