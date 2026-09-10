// `npm run bench:evidence` — how bad is /evidence's linear scan, actually?
//
// `api/evidence.js` finds a receipt by walking `store.events()` BACKWARDS until it matches. The array is
// returned by reference (`core/store.js`: `events: () => events`), so there is no per-request copy — the
// whole cost is the walk. That makes the shape asymmetric and worth measuring rather than asserting:
//   · the NEWEST receipt is found in ~3 steps          → O(1) in practice
//   · the OLDEST receipt is found after ~N steps       → O(N)
//   · a MISS (404) walks the entire log every time     → O(N), and it is the cheapest request to send
//
// The last one is the interesting case. A miss costs the most and requires no authentication, so on a
// public host the linear scan is a load amplifier before it is a latency problem.
//
// Measured two ways, because they answer different questions:
//   PURE   findReceipt() alone — the algorithmic claim, no HTTP in the way.
//   WIRE   GET /evidence/:id over real HTTP — what a caller actually waits for.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path');
const { findReceipt } = require('../api/evidence');

const SIZES = (process.env.BENCH_SIZES || '1000,10000,50000,200000').split(',').map(Number);
const ITER = +(process.env.BENCH_ITER || 200);

const stats = (xs) => {
  const s = xs.slice().sort((a, b) => a - b);
  return { median: s[Math.floor(s.length / 2)], mean: s.reduce((a, b) => a + b, 0) / s.length, p99: s[Math.floor(s.length * 0.99)] };
};
const us = (n) => (n * 1000).toFixed(1) + ' µs';
const time = (fn) => { const t0 = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t0) / 1e6; };

// A log shaped like a real one: every ALLOW writes decision + reservation + receipt (api/authorize.js),
// so a third of the events are receipts. Faking the COSE payload is fine — findReceipt never decodes it,
// it only compares `kind` and `authId`.
function makeEvents(n) {
  const out = [];
  for (let i = 0; i < n; i++) {
    const authId = 'auth_' + String(i).padStart(20, '0');
    const k = i % 3;
    if (k === 0) out.push({ kind: 'decision', ts: i, authId, agentId: 'grn_x', amount: 100, approved: true });
    else if (k === 1) out.push({ kind: 'reservation', ts: i, authId, agentId: 'grn_x', amount: 100 });
    else out.push({ kind: 'receipt', ts: i, authId, agentId: 'grn_x', kid: 'k1', cose: 'AAAA' });
  }
  return out;
}

console.log('/evidence linear scan — ' + ITER + ' iterations per cell, node ' + process.version + '\n');
console.log('PURE findReceipt() — the walk itself, no HTTP');
console.log('  events    newest (best)        oldest (worst)       miss / 404 (full walk)');

const receiptIdAt = (i) => 'auth_' + String(i).padStart(20, '0');
for (const n of SIZES) {
  const ev = makeEvents(n);
  // indices where kind === 'receipt' are i % 3 === 2
  const newestId = receiptIdAt(n - 1 - ((n - 1) % 3 === 2 ? 0 : ((n - 1) % 3) + 1));
  const oldestId = receiptIdAt(2);
  const missId = 'auth_' + 'f'.repeat(20);
  if (!findReceipt(ev, newestId) || !findReceipt(ev, oldestId)) throw new Error('bench setup wrong: ids do not resolve at n=' + n);

  const cell = (id) => { const xs = []; for (let i = 0; i < ITER; i++) xs.push(time(() => findReceipt(ev, id))); return stats(xs); };
  const a = cell(newestId), b = cell(oldestId), c = cell(missId);
  const col = (s) => (us(s.median) + '  p99 ' + us(s.p99)).padEnd(26);
  console.log('  ' + String(n).padEnd(9) + col(a) + col(b) + col(c));
}

// ── WIRE: the same thing through the real server, so the number includes HTTP, JSON and the self-check ──
(async () => {
  const { start } = require('../api/server');
  const N = +(process.env.BENCH_WIRE_N || 50000);
  const LOG = path.join(os.tmpdir(), 'cosmos-bench-evidence-' + process.pid + '.jsonl');

  // One REAL authorization first, so there is a genuine signed receipt to fetch; then pad the log behind
  // it so that receipt sits at the far end of the walk.
  const h0 = await new Promise((r) => { const s = start({ port: 0, file: LOG, quiet: true, allowUnauthenticatedWrites: true }); s.server.on('listening', () => r(Object.assign(s, { port: s.server.address().port }))); });
  const B0 = 'http://localhost:' + h0.port;
  const post = (b, p, o) => fetch(b + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(o) }).then((r) => r.json());
  const g = await post(B0, '/grants', { org_id: 'o', agent_id: 'a', currency: 'USD', budget_minor: 100000000, per_payment_cap_minor: 5000, daily_cap_minor: 100000000, allowed_categories: ['api'] });
  const first = await post(B0, '/authorize', { grant_id: g.grant_id, amount_minor: 100, currency: 'USD', category: 'api', idempotency_key: 'first' });
  await new Promise((r) => { h0.store.close(); if (h0.server.closeAllConnections) h0.server.closeAllConnections(); h0.server.close(() => r()); });

  fs.appendFileSync(LOG, makeEvents(N).map((e) => JSON.stringify(e)).join('\n') + '\n');

  const h = await new Promise((r) => { const s = start({ port: 0, file: LOG, quiet: true, allowUnauthenticatedWrites: true }); s.server.on('listening', () => r(Object.assign(s, { port: s.server.address().port }))); });
  const B = 'http://localhost:' + h.port;
  const last = await post(B, '/authorize', { grant_id: g.grant_id, amount_minor: 100, currency: 'USD', category: 'api', idempotency_key: 'last' });

  const wire = async (p) => { const xs = []; for (let i = 0; i < Math.min(ITER, 100); i++) { const t0 = process.hrtime.bigint(); await fetch(B + p); xs.push(Number(process.hrtime.bigint() - t0) / 1e6); } return stats(xs); };
  // ★ THE CONTROL. /health touches no receipt and walks nothing. Without it there is no way to tell how
  // much of an /evidence timing is the scan and how much is just an HTTP round trip on this box — and the
  // first run of this benchmark reported the newest and oldest receipts at the SAME latency, which is only
  // interpretable once you know the floor.
  const baseline = await wire('/health');
  const deep = await wire('/evidence/' + first.receipt_id);
  const shallow = await wire('/evidence/' + last.receipt_id);
  const miss = await wire('/evidence/auth_' + 'f'.repeat(20));

  console.log('\nWIRE GET /evidence — real HTTP, ' + (N + 5) + ' events in the log');
  console.log('  /health CONTROL  ' + us(baseline.median) + '  p99 ' + us(baseline.p99) + '   ← no scan at all: this is the HTTP floor');
  console.log('  newest receipt   ' + us(shallow.median) + '  p99 ' + us(shallow.p99));
  console.log('  oldest receipt   ' + us(deep.median) + '  p99 ' + us(deep.p99) + '   ← full walk + signature self-check');
  console.log('  404 miss         ' + us(miss.median) + '  p99 ' + us(miss.p99) + '   ← full walk, unauthenticated, cheapest to send');
  const over = deep.median - baseline.median;
  console.log('\n  scan+verify above the floor: ' + us(over) + '  (' + (100 * over / deep.median).toFixed(1) + '% of the oldest-receipt request)');
  console.log('  → if that share is small, the linear scan is NOT the bottleneck at this log size and');
  console.log('    replacing it with an index would optimise the wrong thing. Compare against PURE above.');

  await new Promise((r) => { h.store.close(); if (h.server.closeAllConnections) h.server.closeAllConnections(); h.server.close(() => r()); });
  try { fs.unlinkSync(LOG); } catch (_) {}
})().catch((e) => { console.error('FATAL', e); process.exit(1); });
