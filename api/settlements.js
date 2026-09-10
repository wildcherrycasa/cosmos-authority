// ═══ POST /settlements/:authorization_id — the rail reports back ═══════════════════════════════════════
//
// THE FIFTH ROUTE, named as such, and recorded as a deliberate exception exactly like the fourth one
// (api/approvals.js). The three-calls rule says nothing else gets built unless it serves one of the three.
// This serves /authorize, and not loosely: DESIGN §7 calls the reservation lifecycle "the hardest thing in
// the product" and says the TTL that guards it is a guess nobody has measured. This is the route that
// makes the guess unnecessary. Without it an ALLOW is a decision with no ending.
//
// ⛳ IT DOES NOT BREAK "ZERO CODE CHANGE FOR THE AGENT", which is the objection DESIGN §7 raised against a
// fourth call and the reason it recommended the TTL instead. The report does not come from the agent. It
// comes from the RAIL — the party that already knows whether the money moved and already has to be told
// what to execute. The agent still makes one call and changes nothing.
//
// ── THE THREE QUESTIONS, ANSWERED BEFORE ANY OF THIS WAS WRITTEN ──────────────────────────────────────
//
// 1. WHO MAY REPORT. A per-authorization capability minted with the ALLOW, returned exactly once, and
//    stored only as a hash (core/rail.js). NOT the operator token by default: that token mints grants, and
//    a rail able to mint grants can raise its own ceiling. This credential does one thing to one
//    authorization. The operator token is accepted as a SECOND class because an operator reconciling by
//    hand is a real need and the operator can already mint authority anyway — but which class was used is
//    recorded in the signed receipt (`rail_reported_by`), because "an operator asserted this" and "the
//    party holding the rail handoff asserted this" are different facts and a receipt that blurs them is
//    the `approver_id` defect again.
//    ⛔ The capability is required in EVERY mode, including COSMOS_ALLOW_UNAUTHENTICATED_WRITES=true. An
//    open demo mint is a legitimate choice; an open path that can cancel a budget reversal is not.
//
// 2. A SETTLEMENT FOR AN ALREADY-REVERSED AUTHORIZATION. It is accepted, marked `rail_late`, and the spend
//    is RE-RESERVED. The rail was slower than the guess and the money moved; the budget was handed back on
//    an assumption that turned out false, and leaving it back would mean the ledger under-counts real
//    money. History is append-only, so nothing is undone — a second reservation is appended and the
//    receipt says why. This can push a grant past its own budget. It is allowed to: a cap that refuses to
//    record a spend that already happened makes the ledger lie about the world, which is worse than a
//    grant that reads over-committed and is visibly so.
//
// 3. IS THE REPORT ITSELF RECEIPTED. Yes, and it is the point. An ALLOW whose evidence stops at the
//    decision leaves an auditor unable to say whether anything happened next. The settlement receipt
//    carries `parent_receipt_id` back to the ALLOW, so the chain reads: policy allowed at T1, the rail
//    reported tx X at T2. Nobody else emits that pair.
//
// ⛔ AND THE CAVEAT THAT RIDES IN THE SIGNED BYTES: Cosmos does not observe the rail and never will
// (decision (a)). `rail_tx_id` is asserted by the reporter. The signature proves a report was made against
// this authorization by a holder of that credential class — not that money moved. Same shape, same reason,
// as `approver_authenticated`.
'use strict';
const { jcs } = require('../core/jcs');
const rail = require('../core/rail');
const envelope = require('../core/authorization-envelope');
const receipt = require('../core/receipt');
const { loadGrants, newId, sha, need } = require('./grants');
const { HttpError } = require('./http');
const { bearerFrom, tokenMatches } = require('./auth');

// ═══ WHO IS ALLOWED TO SAY A PAYMENT ENDED ════════════════════════════════════════════════════════════
//
// ⚠ REVIEW FINDING (Ramu, 2026-09-08) AND IT WAS RIGHT. The first version of this file accepted the
// handoff capability alone — and that capability is returned in the /authorize response, i.e. **to the
// requester**, the one party with a motive to lie about whether money moved. The reviewer named the
// `settled` direction. ⚠ **The severe one is the opposite, and it is worse than the finding said:**
//
//   · self-reported `settled` when nothing moved  → the agent's OWN budget is consumed. A false record,
//     bad for an evidence product, but it costs the liar and grants it nothing.
//   · self-reported `failed` when the money DID move → **the budget comes straight back.** Spend $10,
//     report `failed`, spend the same $10 again, repeat. That is an unbounded DOUBLE-SPEND performed with
//     a credential Cosmos handed to the attacker, defeating the one thing this product exists to prevent.
//
// So the capability is NECESSARY AND NOT SUFFICIENT. Three classes, and a TERMINAL outcome
// (`settled` / `failed`) requires one of the two the requester cannot hold:
//
//   'rail'       the rail token (COSMOS_RAIL_TOKEN — operator-set, delivered to the RAIL out of band and
//                never to the caller) PLUS the per-authorization capability in `x-cosmos-handoff`.
//                Two factors answering two different questions: the token proves WHO is reporting, the
//                capability proves WHICH authorization was actually routed to them. A compromised rail
//                still cannot settle an authorization it was never handed.
//   'operator'   the operator token alone — manual reconciliation. It can already mint grants, so this is
//                no new power; recorded as the weaker claim, because it is not the rail speaking.
//   'allow_holder' the handoff token alone → `submitted` ONLY. NAMED FOR WHO HOLDS IT, not for what it is
//                (review, round 2): the entire defect was that this credential reaches the /authorize
//                CALLER, and a class called `capability` described the mechanism while hiding the holder.
//
// ⛔ FAIL CLOSED, AND VISIBLY: with neither a rail token nor an operator token configured, NOTHING can
// report a terminal outcome. That is the correct default — a settlement path that works out of the box is
// a settlement path anyone can drive — and api/server.js says so at startup, not at the first refusal.
function authenticateReport(req, state, writePolicy, railCfg) {
  const presented = bearerFrom(req);
  const handoff = (req && req.headers && req.headers['x-cosmos-handoff']) || null;
  const unauthorized = (detail) => Object.assign(new HttpError(401, 'UNAUTHORIZED', detail),
    { headers: { 'www-authenticate': 'Bearer realm="cosmos-settlement", charset="UTF-8"' } });

  if (!presented) throw unauthorized('present the rail token with this authorization\'s capability in x-cosmos-handoff, or the operator token, or (for `submitted` only) the capability issued with the ALLOW');

  const railToken = railCfg && railCfg.token;
  if (railToken && tokenMatches(presented, railToken)) {
    // The rail secret is the operator's own, so its holder is told exactly what is missing. That is not a
    // hint to a prober; it is a message to someone who has already proved they hold it.
    if (!state.tokenHash) throw unauthorized('this authorization has no settlement capability to match');
    if (!rail.capabilityMatches(state.authId, String(handoff), state.tokenHash)) {
      throw unauthorized('rail token accepted, but x-cosmos-handoff is missing or is not this authorization\'s capability');
    }
    return 'rail';
  }
  if (writePolicy && writePolicy.mode === 'token' && tokenMatches(presented, writePolicy.token)) return 'operator';
  if (state.tokenHash && rail.capabilityMatches(state.authId, presented, state.tokenHash)) return 'allow_holder';
  // One error for the rest: telling a prober which class it got wrong tells it which one to work on.
  throw unauthorized('the presented token is not a credential for this authorization');
}

// Ordered by what each outcome can COST SOMEBODY ELSE, which is the only ordering that has held up here.
// `submitted` extends the holder's own reservation and moves nothing. `settled` is conservative — it can
// only fix or increase recorded spend, so an operator reconciling by hand is safe. `failed` RETURNS BUDGET,
// and every defect found in this file has pointed that way, so it is the narrowest: the rail, or the TTL.
// ⛔ NOT the operator either: the operator can mint a NEW grant but has no route that credits an existing
// one, so letting it report `failed` would hand it a power it does not otherwise have.
const MAY_REPORT = { submitted: ['allow_holder', 'operator', 'rail'], settled: ['operator', 'rail'], failed: ['rail'] };
function assertMayReport(reportedBy, outcome) {
  if ((MAY_REPORT[outcome] || []).indexOf(reportedBy) !== -1) return;
  throw new HttpError(403, 'REPORTER_MAY_NOT_' + String(outcome).toUpperCase(),
    'a `' + reportedBy + '` credential may not report `' + outcome + '`; allowed: ' + (MAY_REPORT[outcome] || []).join(', ') +
    '. Returning budget is the direction that buys a double-spend, so only the rail — or the TTL — may do it.');
}

function makeSettlementsRoute(store, keystore, writePolicy, opts) {
  if (!keystore) throw new Error('SETTLEMENTS_REQUIRES_KEYSTORE');
  const graceMs = (opts && opts.graceMs) || rail.DEFAULT_GRACE_MS;
  const providerHint = (opts && opts.provider) || null;

  return async function report(body, params, req) {
    const authId = String((params && params.id) || '');
    need(/^auth_[0-9a-f]{20}$/.test(authId), 'INVALID_AUTHORIZATION_ID');
    const v = rail.validateReport(body);
    if (!v.ok) throw new HttpError(400, v.code, v.detail);

    // Read state BEFORE the lock only to authenticate and 404 fast; every decision that writes is remade
    // inside the lock against fresh history.
    const pre = rail.railState(store.events(), authId);
    if (!pre.decision) throw new HttpError(404, 'AUTHORIZATION_NOT_FOUND');
    const reportedBy = authenticateReport(req, pre, writePolicy, opts);
    assertMayReport(reportedBy, v.outcome);
    if (pre.decision !== 'ALLOW') {
      throw new HttpError(409, 'NOT_AN_ALLOW', 'authorization ' + authId + ' was ' + pre.decision + '; there is nothing to settle');
    }

    const grant = loadGrants(store.events())[pre.grantId];
    if (!grant) throw new HttpError(404, 'GRANT_NOT_FOUND');

    return store.withLock(grant.grant_id, async () => {
      const state = rail.railState(store.events(), authId);

      // Terminal states are one-shot. The SAME outcome replays the original receipt rather than signing a
      // second contradictory one; a DIFFERENT outcome is refused, because "settled" and "failed" cannot
      // both be true of one payment and Cosmos has no way to adjudicate which report is honest.
      if (state.settled || state.failed) {
        if (state.outcome === v.outcome) {
          return { status: 200, body: replayBody(state, authId, grant, true) };
        }
        throw new HttpError(409, 'ALREADY_REPORTED',
          'authorization ' + authId + ' was already reported as ' + state.outcome + '; a rail may not report both');
      }

      const now = Date.now();
      const produced = rail.reportEvents(state, Object.assign({}, v, { reportedBy }), now, graceMs);

      // A `submitted` report is NOT idempotent, deliberately: each one is a distinct fact — "still in
      // flight as of T" — and each extends the deadline from its own timestamp. Collapsing them would
      // discard the only information they carry.
      const stlId = newId('stl');
      const intent = { parent: authId, outcome: v.outcome, tx_id: v.txId, provider: v.provider, reported_by: reportedBy, at: now };
      const intentHash = sha(jcs(intent));
      const auditHash = sha(jcs(produced.events.map((e) => e.kind)));

      const env = envelope.build({
        orgId: grant.org_id, agentId: grant.agent_id, authId: stlId, intentHash,
        amountMinor: state.amount, asset: grant.currency, network: v.provider || providerHint || 'none',
        credentialFingerprint: sha(grant.grant_id + '|' + grant.capability_root),
        policyVersion: grant.policy_version, policyHash: grant.policy_hash,
        budgetResult: 'REPORT', idempotencyKey: 'settlement:' + authId + ':' + v.outcome + ':' + now,
        ledgerAuthRef: v.txId, vendorRef: v.provider || providerHint,
        authorizedAt: now, expiresAt: produced.deadline || null, auditHash,
      });

      const decided = {
        decision: 'REPORT', reason: 'RAIL_' + v.outcome.toUpperCase(),
        authorization_id: stlId, org_id: grant.org_id, grant_id: grant.grant_id, agent_id: grant.agent_id,
        amount_minor: state.amount, currency: grant.currency,
        merchant: null, category: null,
        expires_at: produced.deadline || null,
        intent_hash: intentHash, envelope_hash: env.hash,
        policy_version: grant.policy_version, policy_hash: grant.policy_hash,
        capability_root: grant.capability_root,
        checks: [{ name: 'Rail report accepted', pass: true },
                 { name: 'Rail outcome observed by Cosmos', pass: false }],   // never true; see the header
        idempotency_key: env.idempotency_key, decided_at: now,
        parent_receipt_id: authId,
        rail_outcome: v.outcome, rail_state: v.state, rail_tx_id: v.txId, rail_provider: v.provider || providerHint,
        rail_reported_by: reportedBy, rail_reported_at: now, rail_late: produced.late,
      };

      let issued;
      try { issued = receipt.issue(receipt.buildPayload(decided), keystore); }
      catch (e) { throw new HttpError(503, 'RECEIPT_SIGNER_UNAVAILABLE', String(e.message)); }

      // The receipt id is stamped onto the rail events so a replayed report can find its own evidence
      // after a restart, when nothing but the log survives.
      for (const e of produced.events) if (e.kind === 'submission' || e.kind === 'settlement') e.receiptId = stlId;
      const records = produced.events.concat([
        { kind: 'receipt', ts: now, authId: stlId, agentId: grant.grant_id, kid: issued.kid,
          cose: issued.cose.toString('base64'), parentAuthId: authId },
      ]);
      await store.append(records);      // resolves only after fsync

      const resp = Object.assign({}, decided, {
        signed: true, kid: issued.kid, receipt_id: stlId,
        evidence: '/evidence/' + stlId, parent_evidence: '/evidence/' + authId,
        jwks: '/.well-known/jwks.json',
        re_reserved: produced.reReserved,
        reservation_deadline: produced.deadline || null,
      });
      return { status: 200, body: resp };
    });
  };
}

// A replay of an already-terminal report. Rebuilt from the fold rather than from a memory cache, so it
// survives a restart — the raw capability does not, but the RECORD of what was reported always does.
function replayBody(state, authId, grant, isReplay) {
  return {
    decision: 'REPORT', reason: 'RAIL_' + String(state.outcome).toUpperCase(),
    authorization_id: state.reportReceiptId || null,
    parent_receipt_id: authId,
    org_id: grant.org_id, grant_id: grant.grant_id, agent_id: grant.agent_id,
    amount_minor: state.amount, currency: grant.currency,
    rail_outcome: state.outcome, rail_tx_id: state.txId, rail_provider: state.provider,
    rail_reported_by: state.reportedBy, rail_reported_at: state.reportedAt, rail_late: state.late,
    receipt_id: state.reportReceiptId || null,
    evidence: state.reportReceiptId ? '/evidence/' + state.reportReceiptId : null,
    parent_evidence: '/evidence/' + authId,
    jwks: '/.well-known/jwks.json',
    idempotent_replay: !!isReplay,
  };
}

module.exports = { makeSettlementsRoute, authenticateReport, assertMayReport };
