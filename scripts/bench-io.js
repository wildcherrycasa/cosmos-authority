// Cosmos I/O benchmark — measures the WHOLE authorization path in one run, so CPU and disk are directly
// comparable on the same box. This is the measurement that showed fsync (not signing) is the wall.
//
// Results live in the project memory's "Measured facts" and docs/DESIGN.md §8. Re-run before trusting them on new
// hardware: `npm run bench:io`. The scratch log is written to the OS temp dir, never into the repo.
'use strict';
const fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto');

const CORE = path.join(__dirname, '..', 'core');
const guardrails = require(path.join(CORE, 'guardrails'));
const envelope = require(path.join(CORE, 'authorization-envelope'));
const { jcs } = require(path.join(CORE, 'jcs'));
const { makeKeystore } = require(path.join(CORE, 'receipt-keystore'));

const OUT = path.join(os.tmpdir(), 'cosmos-bench-log.jsonl');
try { fs.unlinkSync(OUT); } catch (_) {}

// ── stats ─────────────────────────────────────────────────────────────────────
function stats(name, samplesNs, unitOpsPer = 1) {
  const s = samplesNs.slice().sort((a, b) => Number(a - b));
  const n = s.length;
  const at = (q) => Number(s[Math.min(n - 1, Math.floor(q * n))]) / 1000; // µs
  const mean = Number(samplesNs.reduce((a, b) => a + b, 0n)) / n / 1000;
  return { name, n, mean, median: at(0.5), p99: at(0.99), max: Number(s[n - 1]) / 1000,
           opsPerSec: 1e6 / (at(0.5) / unitOpsPer) };
}
function row(r) {
  const f = (x) => (x >= 1000 ? (x / 1000).toFixed(3) + ' ms' : x.toFixed(2) + ' µs');
  return [r.name.padEnd(38), ('n=' + r.n).padStart(8),
          ('med ' + f(r.median)).padStart(16), ('mean ' + f(r.mean)).padStart(17),
          ('p99 ' + f(r.p99)).padStart(16),
          (Math.round(r.opsPerSec).toLocaleString('en-US') + '/s').padStart(14)].join('  ');
}
function bench(name, iters, fn, warm = Math.min(200, Math.floor(iters / 10)), unitOpsPer = 1) {
  for (let i = 0; i < warm; i++) fn(i);
  const samples = new Array(iters);
  for (let i = 0; i < iters; i++) {
    const t0 = process.hrtime.bigint();
    fn(i);
    samples[i] = process.hrtime.bigint() - t0;
  }
  return stats(name, samples, unitOpsPer);
}

// ── fixtures ──────────────────────────────────────────────────────────────────
const grant = { status: 'active', expiry: null, budget: 5000000, spent: 0, spentToday: 0,
  perPaymentCap: 1700, dailyCap: 5000, allowedCategories: ['api', 'cloud', 'subscription'],
  freeRein: false, approvalThreshold: 2500 };

const envFields = {
  orgId: 'org_acme', agentId: 'agt_research_01', authId: 'auth_01J8ZK3QW',
  intentHash: crypto.createHash('sha256').update('intent').digest('hex'),
  amountMinor: 1200, asset: 'USD', network: 'none', category: 'api', merchant: 'api.openai.com',
  credentialFingerprint: crypto.createHash('sha256').update('grant').digest('hex'),
  policyVersion: 1, policyHash: crypto.createHash('sha256').update('policy').digest('hex'),
  budgetResult: 'ALLOW', idempotencyKey: 'agt_research_01:req_9931',
  authorizedAt: 1788134400000, expiresAt: 1788134700000,
  auditHash: crypto.createHash('sha256').update('checks').digest('hex'),
};

const receiptBody = {
  cosmos_schema: 1, receipt_id: 'rcp_01J8ZK3QW', kid: 'cosmos-receipt-2026-09',
  org_id: 'org_acme', grant_id: 'grn_01J8ZK', agent_id: 'agt_research_01',
  decision: 'ALLOW', reason: null,
  checks: [{ name: 'Currency matches grant', pass: true }, { name: 'Active', pass: true },
           { name: 'Not expired', pass: true }, { name: 'Sufficient balance', pass: true },
           { name: 'Under per-payment cap', pass: true }, { name: 'Under daily cap', pass: true },
           { name: 'Category allowed', pass: true }],
  amount_minor: 1200, currency: 'USD', merchant: 'api.openai.com', category: 'api',
  intent_hash: envFields.intentHash, envelope_hash: envelope.hashDoc(envFields),
  policy_version: 1, policy_hash: envFields.policyHash,
  capability_root: crypto.createHash('sha256').update('root').digest('hex'),
  idempotency_key: envFields.idempotencyKey,
  decided_at: 1788134400000, expires_at: 1788134700000,
};

const keystore = makeKeystore({ kid: 'cosmos-bench' });
const digest = crypto.createHash('sha256').update(jcs(receiptBody)).digest('hex');

// The two events one ALLOW appends: a decision + a reservation.
const eventPair = (i) =>
  JSON.stringify({ kind: 'decision', ts: 1788134400000 + i, authId: 'auth_' + i, agentId: 'agt_research_01',
    amount: 1200, category: 'api', merchant: 'api.openai.com', approved: true, checks: receiptBody.checks,
    idempotencyKey: 'k' + i }) + '\n' +
  JSON.stringify({ kind: 'reservation', ts: 1788134400000 + i, authId: 'auth_' + i,
    agentId: 'agt_research_01', amount: 1200, merchant: 'api.openai.com' }) + '\n';

// ── run ───────────────────────────────────────────────────────────────────────
console.log('Cosmos I/O benchmark');
console.log('node ' + process.version + '  ·  ' + os.cpus().length + ' cores  ·  ' + os.cpus()[0].model.trim());
console.log('append payload (decision+reservation) = ' + Buffer.byteLength(eventPair(0)) + ' bytes');
console.log('scratch log: ' + OUT + '\n');

const R = (r) => { console.log(row(r)); return r; };

console.log('── CPU ' + '─'.repeat(104));
const evalR = R(bench('guardrails.evaluate', 200000, () => guardrails.evaluate(grant, 1200, 'api')));
R(bench('authorization-envelope.hashDoc', 50000, () => envelope.hashDoc(envFields)));
R(bench('jcs(receipt body)', 50000, () => jcs(receiptBody)));
const signR = R(bench('Ed25519 sign', 20000, () => keystore.sign(digest)));

console.log('\n── DISK (the wall) ' + '─'.repeat(92));
const fd = fs.openSync(OUT, 'a');
R(bench('append only (no fsync)', 20000, (i) => { fs.writeSync(fd, eventPair(i)); }));
const fsyncR = R(bench('append + fsync  <- THE NUMBER', 1000, (i) => {
  fs.writeSync(fd, eventPair(i)); fs.fsyncSync(fd);
}));
for (const G of [8, 32, 128]) {
  R(bench('group commit: ' + String(G).padStart(3) + ' appends, 1 fsync', Math.max(60, Math.floor(2000 / G)),
    (i) => { for (let k = 0; k < G; k++) fs.writeSync(fd, eventPair(i * G + k)); fs.fsyncSync(fd); },
    10, G));
}

console.log('\n── FULL AUTHORIZATION PATH ' + '─'.repeat(84));
const step = (i) => {
  const d = guardrails.evaluate(grant, 1200, 'api');
  const body = Object.assign({}, receiptBody,
    { envelope_hash: envelope.hashDoc(envFields), decision: d.approved ? 'ALLOW' : 'DENY' });
  keystore.sign(crypto.createHash('sha256').update(jcs(body)).digest('hex'));
  fs.writeSync(fd, eventPair(i));
};
const fullR = R(bench('decide+hash+jcs+sign+append+fsync', 1000, (i) => { step(i); fs.fsyncSync(fd); }));
const groupR = R(bench('same, group-committed (/128 fsync)', 1000,
  (i) => { step(i); if (i % 128 === 127) fs.fsyncSync(fd); }));
fs.fsyncSync(fd); fs.closeSync(fd);

console.log('\n── RATIOS (median) ' + '─'.repeat(92));
const rr = (a, b) => (a.median / b.median).toFixed(0) + '×';
console.log('  fsync / evaluate            : ' + rr(fsyncR, evalR));
console.log('  fsync / Ed25519 sign        : ' + rr(fsyncR, signR));
console.log('  sign  / evaluate            : ' + rr(signR, evalR));
console.log('  full path / group-committed : ' + rr(fullR, groupR));
console.log('\n  serialised, fsync per authorization : ' +
  Math.round(fullR.opsPerSec).toLocaleString('en-US') + ' authorizations/sec');
console.log('  group-committed at 128              : ' +
  Math.round(groupR.opsPerSec).toLocaleString('en-US') + ' authorizations/sec');
console.log('\n⚠ NOT measured here: multi-core scaling, and whether this drive honours FlushFileBuffers');
console.log('  through its volatile cache. Do not carry these numbers to other hardware.');

try { fs.unlinkSync(OUT); } catch (_) {}
