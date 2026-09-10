// ═══ POST /approvals/:id  ·  GET /approvals — resolving an ESCALATE ════════════════════════════════════
//
// THE FOURTH ROUTE, named as such. The three-calls rule says nothing else gets built unless it serves one
// of the three. This serves /authorize: ESCALATE is one of its three outcomes, and without a way to resolve
// it, ESCALATE is a dead end — a decision that can never become a spend or a refusal. Recorded as a
// deliberate exception, like JWKS was for /evidence.
//
// Semantics, stated so nobody guesses:
//   - approving does NOT override policy. The spend is re-evaluated with the approval line removed; if the
//     budget or a cap no longer fits, the result is DENY with the guardrails reason, and the receipt says a
//     human approved AND the policy still refused. That is the honest record.
//   - the resolution is a NEW signed receipt whose parent_receipt_id is the ESCALATE receipt. The chain is
//     the evidence: "the policy escalated at T1; approver X approved at T2; policy allowed / still refused."
//   - approver may not equal the agent (the envelope's self-approval guard, enforced here at the boundary).
//   - one-shot: approvals.resolve() is called only after the batch is durable, inside the grant lock.
//   - approver_id is CLIENT-ASSERTED. The receipt records who claimed to approve and via which channel;
//     it does not authenticate them. Saying more would be a lie.
'use strict';
const { jcs } = require('../core/jcs');
const replay = require('../core/replay');
const view = require('../core/agent-view');
const approvals = require('../core/approvals');
const envelope = require('../core/authorization-envelope');
const receipt = require('../core/receipt');
const { loadGrants, newId, sha, need } = require('./grants');
const { HttpError } = require('./http');
const { RESERVATION_TTL_MS } = require('./authorize');

function findDecision(events, authId) {
  for (let i = events.length - 1; i >= 0; i--) { const e = events[i]; if (e && e.kind === 'decision' && e.authId === authId) return e; }
  return null;
}

function makeApprovalsListRoute() {
  return async function list() {
    return { status: 200, body: { pending: approvals.list().map((p) => ({ authorization_id: p.command_id, grant_id: p.agentId, amount_minor: p.amount, requested_at: p.requestedAt })) } };
  };
}

function makeApprovalsRoute(store, keystore) {
  return async function resolve(body, params) {
    const id = String(params.id || '');
    need(/^auth_[0-9a-f]{20}$/.test(id), 'INVALID_AUTHORIZATION_ID');
    need(body.decision === 'approve' || body.decision === 'deny', 'INVALID_DECISION', '"approve" or "deny"');
    need(typeof body.approver_id === 'string' && body.approver_id.trim(), 'APPROVER_ID_REQUIRED');
    if (body.channel != null) need(typeof body.channel === 'string', 'INVALID_CHANNEL');
    const approverId = body.approver_id.trim();
    const channel = body.channel || 'api';

    const pending = approvals.get(id);
    if (!pending) throw new HttpError(404, 'APPROVAL_NOT_PENDING', 'no pending approval for ' + id + ' (never escalated, or already resolved)');
    const grant = loadGrants(store.events())[pending.agentId];
    if (!grant) throw new HttpError(404, 'GRANT_NOT_FOUND');
    if (approverId === grant.agent_id) throw new HttpError(400, 'APPROVER_EQUALS_REQUESTER', 'an agent may not approve its own spend');

    return store.withLock(grant.grant_id, async () => {
      if (!approvals.get(id)) throw new HttpError(404, 'APPROVAL_NOT_PENDING', 'resolved concurrently');
      const orig = findDecision(store.events(), id);
      if (!orig) throw new HttpError(500, 'ESCALATION_RECORD_MISSING');
      const now = Date.now();
      const amount = orig.amount, category = orig.category || null, merchant = orig.merchant || null;

      let decision, reason, checks;
      if (body.decision === 'deny') {
        decision = 'DENY'; reason = 'DENIED_BY_APPROVER';
        checks = [{ name: 'Approver decision', pass: false }];
      } else {
        const events = store.events();
        const v = view.agentView(grant, replay.replay(events), events, now);
        v.approvalThreshold = null;                                    // the human answered the approval line…
        const g = view.decide(grant, v, amount, grant.currency, category);   // …policy still binds
        checks = [{ name: 'Approver decision', pass: true }].concat(g.checks);
        if (g.approved) { decision = 'ALLOW'; reason = 'APPROVED_BY_HUMAN'; }
        else { decision = 'DENY'; reason = g.reason; }
      }

      const authId = newId('auth');
      const intentHash = sha(jcs({ parent: id, decision: body.decision, approver_id: approverId, channel }));
      const auditHash = sha(jcs(checks));
      const expiresAt = now + RESERVATION_TTL_MS;
      const env = envelope.build({
        orgId: grant.org_id, agentId: grant.agent_id, authId, intentHash,
        amountMinor: amount, asset: grant.currency, network: 'none', category, merchant,
        credentialFingerprint: sha(grant.grant_id + '|' + grant.capability_root),
        policyVersion: grant.policy_version, policyHash: grant.policy_hash,
        budgetResult: decision, idempotencyKey: 'approval:' + id,
        approvalRequired: true, approvalRequestId: id, requesterId: grant.agent_id, approverId,
        authorizedAt: now, expiresAt, auditHash,
      });

      const decided = {
        decision, reason, authorization_id: authId, org_id: grant.org_id, grant_id: grant.grant_id, agent_id: grant.agent_id,
        amount_minor: amount, currency: grant.currency, merchant, category,
        expires_at: decision === 'ALLOW' ? expiresAt : null, intent_hash: intentHash, envelope_hash: env.hash,
        policy_version: grant.policy_version, policy_hash: grant.policy_hash,
        capability_root: grant.capability_root, allowed_categories: grant.allowed_categories,
        checks, idempotency_key: 'approval:' + id, decided_at: now,
        parent_receipt_id: id, approver_id: approverId, approval_channel: channel,
      };
      let issued;
      try { issued = receipt.issue(receipt.buildPayload(decided), keystore); }
      catch (e) { throw new HttpError(503, 'RECEIPT_SIGNER_UNAVAILABLE', String(e.message)); }

      const records = [
        { kind: 'approval_decision', ts: now, commandId: id, agentId: grant.grant_id, approved: body.decision === 'approve', approverId, channel, resolutionAuthId: authId },
        { kind: 'decision', ts: now, authId, agentId: grant.grant_id, amount, category, merchant, approved: decision === 'ALLOW',
          checks, reason, idempotencyKey: 'approval:' + id, decisionKind: decision, envelopeHash: env.hash, intentHash, parentAuthId: id },
      ];
      if (decision === 'ALLOW') records.push({ kind: 'reservation', ts: now, authId, agentId: grant.grant_id, amount, merchant, expiresAt });
      records.push({ kind: 'receipt', ts: now, authId, agentId: grant.grant_id, kid: issued.kid, cose: issued.cose.toString('base64') });
      await store.append(records);
      approvals.resolve(id);                                            // one-shot, only after durable

      const resp = Object.assign({}, decided, { signed: true, kid: issued.kid, receipt_id: authId, evidence: '/evidence/' + authId, jwks: '/.well-known/jwks.json' });
      delete resp.allowed_categories;
      return { status: 200, body: resp };
    });
  };
}

module.exports = { makeApprovalsRoute, makeApprovalsListRoute };
