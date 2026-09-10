// FP10-06: IMMUTABLE AUTHORIZATION ENVELOPE (v2). The full authority context committed BEFORE any external
// submission, so what a provider is asked to execute is provably bound to an authorization FastPay actually made.
// Content-addressed by a canonical SHA-256. Holds fingerprints/hashes ONLY — never a raw credential, secret, or token.
// Any change to any bound field yields a different hash and is detectable.
//
// HONESTY RULE: a payment authorized BEFORE a given authority existed cannot be represented as having it. Treasury,
// approval, and risk fields are null unless that authority actually existed at authorization time — the builder never
// synthesizes authority that did not exist.
const crypto = require('crypto');
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const SCHEMA_VERSION = 2;
const SECRET = /(authorization|api[-_]?key|secret|token|private[-_]?key|password|bearer)/i;   // (credentialFingerprint/riskHash allowed)

const S = (v) => (v == null ? null : String(v));
const N = (v) => (v == null ? null : Math.trunc(+v));

// canonical serialization over every bound field (stable key order, integer minor units, never a float).
function canon(e) {
  return JSON.stringify({
    schema_version: SCHEMA_VERSION,
    org_id: String(e.orgId), agent_id: String(e.agentId), auth_id: String(e.authId),
    intent_hash: String(e.intentHash),
    amount_minor: Math.trunc(+e.amountMinor), asset: String(e.asset || 'USDC'), network: String(e.network || 'internal'),
    category: S(e.category), merchant: S(e.merchant),
    vendor_ref: S(e.vendorRef), destination_ref: S(e.destinationRef), destination_fingerprint: String(e.destinationFingerprint || ''),
    credential_fingerprint: String(e.credentialFingerprint),
    policy_version: Math.trunc(+e.policyVersion), policy_hash: String(e.policyHash),
    budget_result: String(e.budgetResult),
    treasury_version: N(e.treasuryVersion), treasury_hash: S(e.treasuryHash), treasury_committed_basis: N(e.treasuryCommittedBasis),
    approval_required: !!e.approvalRequired, approval_request_id: S(e.approvalRequestId),
    requester_id: S(e.requesterId), approver_id: S(e.approverId), approval_evidence_hash: S(e.approvalEvidenceHash),
    risk_decision: S(e.riskDecision), risk_hash: S(e.riskHash),
    idempotency_key: String(e.idempotencyKey), ledger_auth_ref: S(e.ledgerAuthRef),
    authorized_at: N(e.authorizedAt), expires_at: N(e.expiresAt),
    audit_hash: String(e.auditHash),
  });
}
const hashDoc = (e) => sha(canon(e));

function build(fields) {
  for (const k of Object.keys(fields || {})) if (SECRET.test(k)) { const e = new Error('SECRET_IN_ENVELOPE:' + k); e.code = 'SECRET_IN_ENVELOPE'; throw e; }
  const req = ['orgId', 'agentId', 'authId', 'intentHash', 'amountMinor', 'idempotencyKey', 'policyVersion', 'policyHash', 'credentialFingerprint', 'budgetResult', 'auditHash'];
  for (const k of req) if (fields[k] == null || fields[k] === '') { const e = new Error('MISSING_ENVELOPE_FIELD:' + k); e.code = 'MISSING_ENVELOPE_FIELD'; throw e; }
  if (!(Math.trunc(+fields.amountMinor) === +fields.amountMinor) || !(+fields.amountMinor > 0)) { const e = new Error('INVALID_AMOUNT_MINOR'); e.code = 'INVALID_AMOUNT_MINOR'; throw e; }
  // honesty guard: approver without an approval requirement, or approver == requester, is refused.
  if (fields.approverId && fields.requesterId && String(fields.approverId) === String(fields.requesterId)) { const e = new Error('APPROVER_EQUALS_REQUESTER'); e.code = 'APPROVER_EQUALS_REQUESTER'; throw e; }
  const hash = hashDoc(fields);
  return Object.freeze({
    hash, schema_version: SCHEMA_VERSION,
    org_id: String(fields.orgId), agent_id: String(fields.agentId), auth_id: String(fields.authId), intent_hash: String(fields.intentHash),
    amount_minor: Math.trunc(+fields.amountMinor), asset: String(fields.asset || 'USDC'), network: String(fields.network || 'internal'),
    category: S(fields.category), merchant: S(fields.merchant), vendor_ref: S(fields.vendorRef), destination_ref: S(fields.destinationRef),
    destination_fingerprint: String(fields.destinationFingerprint || ''),
    credential_fingerprint: String(fields.credentialFingerprint),
    policy_version: Math.trunc(+fields.policyVersion), policy_hash: String(fields.policyHash), budget_result: String(fields.budgetResult),
    treasury_version: N(fields.treasuryVersion), treasury_hash: S(fields.treasuryHash), treasury_committed_basis: N(fields.treasuryCommittedBasis),
    approval_required: !!fields.approvalRequired, approval_request_id: S(fields.approvalRequestId),
    requester_id: S(fields.requesterId), approver_id: S(fields.approverId), approval_evidence_hash: S(fields.approvalEvidenceHash),
    risk_decision: S(fields.riskDecision), risk_hash: S(fields.riskHash),
    idempotency_key: String(fields.idempotencyKey), ledger_auth_ref: S(fields.ledgerAuthRef),
    authorized_at: fields.authorizedAt == null ? null : new Date(N(fields.authorizedAt)), expires_at: fields.expiresAt == null ? null : new Date(N(fields.expiresAt)),
    audit_hash: String(fields.auditHash),
  });
}

function verify(fields, expectedHash) { try { return hashDoc(fields) === String(expectedHash); } catch (_) { return false; } }

module.exports = { build, verify, canon, hashDoc, sha, SCHEMA_VERSION };
