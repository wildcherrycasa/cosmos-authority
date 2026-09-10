// Runs EVERY suite and aggregates. Never short-circuits.
// A `&&` chain stops at the first failure and still looks like a full run — a peer session watched a
// 193-command suite silently run 63 that way. Here every suite runs, every result is printed in one
// table, and the exit code is non-zero if ANY failed.
'use strict';
const { spawnSync } = require('child_process');
const path = require('path'), fs = require('fs');

const SUITES = [
  'smoke', 'guardrails', 'jcs', 'authorization-envelope', 'receipt-keystore', 'replay',
  'capability-commitment', 'cose', 'api', 'evidence', 'mcp', 'demo', 'writ-port', 'auth', 'packaging', 'x402-evc',
  'rail', 'reference-rail',
];

// A suite that never finishes is a failure, not a pass. Every suite here completes in seconds on the
// founder's box; a mutation that makes one wait forever (seen 2026-09-06 under "never escalate") must
// be reported as HUNG and the run must move on, not sit until someone notices.
const SUITE_TIMEOUT_MS = 120000;

const rows = [];
let anyFail = false;
// ⚠ SKIP A SUITE WHOSE FILE IS ABSENT, LOUDLY. The public export (npm run export:public) removes suites
// that reference a sibling project, so a hard-coded list would make `npm test` fail on a fresh clone of
// the published repo — a worse first impression than not publishing at all. Found by running the built
// export rather than by reasoning about it. SKIPPED is printed and counted; it is never silent, because a
// suite that vanishes without a word is how coverage quietly goes to zero.
const skipped = [];
for (const s of SUITES) {
  const file = path.join(__dirname, '..', 'test', s + '.test.js');
  if (!fs.existsSync(file)) { skipped.push(s); continue; }
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [file], { encoding: 'utf8', timeout: SUITE_TIMEOUT_MS });
  const out = (r.stdout || '') + (r.stderr || '');
  const m = /(\d+) passed, (\d+) failed/.exec(out);
  const passed = m ? +m[1] : 0, failed = m ? +m[2] : NaN;
  const hung = !!(r.error && r.error.code === 'ETIMEDOUT');
  const crashed = !hung && r.status !== 0 && !(m && failed > 0);
  const ok = !hung && r.status === 0 && m && failed === 0;
  if (!ok) anyFail = true;
  const status = ok ? 'ok' : hung ? 'HUNG' : crashed ? 'CRASH' : 'FAIL';
  rows.push({ suite: s, passed, failed: Number.isNaN(failed) ? '?' : failed, status, ms: Date.now() - t0 });
  if (!ok) console.log('\n──── ' + s + ' ' + (hung ? 'HUNG — killed after ' + SUITE_TIMEOUT_MS / 1000 + ' s; its last lines:' : crashed ? 'CRASHED' : 'FAILED') + ' ────\n'
    + (hung ? out.trim().split('\n').slice(-6).join('\n') : out.split('\n').filter((l) => /✗|expected|actual|FATAL|Error/.test(l)).join('\n')));
}

console.log('\nsuite                      passed  failed  status');
for (const r of rows) console.log(r.suite.padEnd(26) + String(r.passed).padStart(6) + String(r.failed).padStart(8) + '  ' + r.status);
const total = rows.reduce((a, r) => a + r.passed, 0);
if (skipped.length) console.log('\nSKIPPED (file absent, e.g. in the public export): ' + skipped.join(', '));
console.log('\n' + (anyFail ? 'SOME SUITES FAILED' : 'ALL SUITES PASSED') + ' — ' + total + ' assertions across ' + rows.length + ' suites');
process.exit(anyFail ? 1 : 0);
