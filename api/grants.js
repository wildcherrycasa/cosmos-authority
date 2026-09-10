// ═══ POST /grants — mint authority ═════════════════════════════════════════════════════════════════════
'use strict';
const crypto = require('crypto');
const { jcs } = require('../core/jcs');
const CC = require('../core/capability-commitment');
const { HttpError } = require('./http');

const POLICY_VERSION = 1;
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// 4 + 1 + 20 = 25 chars. replay.receipts() slices authId 5..13, so anything shorter than 13 collapses to
// the degenerate receipt id "rcpt_" and two authorizations collide (test/replay.test.js G6).
const newId = (prefix) => prefix + '_' + crypto.randomBytes(10).toString('hex');

const isInt = (v) => typeof v === 'number' && Number.isInteger(v);
const need = (cond, code, detail) => { if (!cond) throw new HttpError(400, code, detail); };

function policyHashOf(g) {
  return sha(jcs({
    policy_version: POLICY_VERSION,
    currency: g.currency,
    budget_minor: g.budget_minor,
    per_payment_cap_minor: g.per_payment_cap_minor,
    daily_cap_minor: g.daily_cap_minor,
    allowed_categories: g.allowed_categories.slice().sort(),
    approval_threshold_minor: g.approval_threshold_minor,
    expires_at: g.expires_at,
    free_rein: g.free_rein,
  }));
}

// `grant_meta` is an UNKNOWN kind to replay.js and therefore INERT there — proven by
// test/replay.test.js B1-B7. That is what lets the policy live in the same log as the balances.
function loadGrants(events) {
  const out = {};
  for (const e of events) if (e && e.kind === 'grant_meta' && e.grant && e.grant.grant_id) out[e.grant.grant_id] = e.grant;
  return out;
}

function makeGrantsRoute(store) {
  return async function createGrant(body) {
    need(typeof body.org_id === 'string' && body.org_id, 'ORG_ID_REQUIRED');
    need(typeof body.agent_id === 'string' && body.agent_id, 'AGENT_ID_REQUIRED');
    need(typeof body.currency === 'string' && /^[A-Z]{3}$/.test(body.currency), 'INVALID_CURRENCY', 'a 3-letter uppercase code');
    need(isInt(body.budget_minor) && body.budget_minor > 0, 'INVALID_BUDGET_MINOR', 'a positive integer in minor units');
    need(isInt(body.per_payment_cap_minor) && body.per_payment_cap_minor > 0, 'INVALID_PER_PAYMENT_CAP_MINOR');
    need(isInt(body.daily_cap_minor) && body.daily_cap_minor > 0, 'INVALID_DAILY_CAP_MINOR');
    need(Array.isArray(body.allowed_categories) && body.allowed_categories.length > 0 &&
         body.allowed_categories.every((c) => typeof c === 'string' && c), 'INVALID_ALLOWED_CATEGORIES');
    if (body.approval_threshold_minor != null)
      need(isInt(body.approval_threshold_minor) && body.approval_threshold_minor > 0, 'INVALID_APPROVAL_THRESHOLD_MINOR');
    if (body.expires_at != null) need(isInt(body.expires_at) && body.expires_at > 0, 'INVALID_EXPIRES_AT', 'epoch milliseconds');

    const categories = body.allowed_categories.slice();
    const commit = CC.commitCapabilities(categories.map((c) => ({ type: 'category', value: c })));

    const grant = {
      grant_id: newId('grn'),
      org_id: body.org_id,
      agent_id: body.agent_id,
      status: 'active',
      currency: body.currency,
      budget_minor: body.budget_minor,
      per_payment_cap_minor: body.per_payment_cap_minor,
      daily_cap_minor: body.daily_cap_minor,
      allowed_categories: categories,
      approval_threshold_minor: body.approval_threshold_minor == null ? null : body.approval_threshold_minor,
      expires_at: body.expires_at == null ? null : body.expires_at,
      free_rein: body.free_rein === true,
      capability_root: commit.root,          // lets a receipt prove ONE category without disclosing the set
      policy_version: POLICY_VERSION,
      created_at: Date.now(),
    };
    grant.policy_hash = policyHashOf(grant);

    // free_rein bypasses per-payment, daily AND category checks (guardrails.js:16-20). It is kept because
    // an operator sometimes wants it, and made safe by being impossible to use invisibly: loud here, and
    // guardrails already stamps "Free rein (caps bypassed)" into every signed receipt.
    if (grant.free_rein) console.warn('[cosmos] WARNING free_rein grant minted: ' + grant.grant_id + ' — ALL caps bypassed');

    // The `open` event carries the GRANT id in replay's `agentId` slot — the grant holds the budget.
    await store.append([
      { kind: 'grant_meta', ts: grant.created_at, grantId: grant.grant_id, grant },
      { kind: 'open', ts: grant.created_at, agentId: grant.grant_id, budget: grant.budget_minor },
    ]);

    return { status: 201, body: grant };
  };
}

module.exports = { makeGrantsRoute, loadGrants, policyHashOf, newId, sha, isInt, need, POLICY_VERSION };
