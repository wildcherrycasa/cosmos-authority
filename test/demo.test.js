// ═══ THE COMMITTED DEMO VERIFIES — permanently ═════════════════════════════════════════════════════════
// demo/ is what a stranger downloads. If this ever fails, the demo folder and the verifier have diverged
// and the outreach link is a broken promise. Runs the SAME command the README tells the stranger to run.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path');
const { spawnSync } = require('child_process');
const receipt = require('../core/receipt');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (a, e, m) => { if (a === e) { pass++; console.log('  ✓ ' + m); return; } fail++; console.log('  ✗ ' + m); console.log('      expected: ' + JSON.stringify(e)); console.log('      actual:   ' + JSON.stringify(a)); };

const DEMO = path.join(__dirname, '..', 'demo'), PY = path.join(__dirname, '..', 'verifier', 'cosmos_verify.py');
// `python` DOES NOT EXIST on macOS 12.3+ or on a default Ubuntu — only `python3`. Hardcoding `python`
// made this suite pass on the founder's Windows box and fail everywhere else, including CI, and the same
// bug was published in the README as the stranger's first command. Probe, in order, so it works on all
// three platforms and an operator can override.
const PYBIN = (() => {
  for (const c of [process.env.COSMOS_PYTHON, 'python3', 'python'].filter(Boolean)) {
    if (spawnSync(c, ['--version'], { encoding: 'utf8' }).status === 0) return c;
  }
  return 'python3';   // report the failure against the name the docs tell people to use
})();
const py = (...a) => { const r = spawnSync(PYBIN, [PY, ...a], { encoding: 'utf8' }); return { code: r.status, out: (r.stdout || '') + (r.stderr || '') }; };
const jwks = JSON.parse(fs.readFileSync(path.join(DEMO, 'jwks.json'), 'utf8'));

for (const [name, decision, reason] of [['allow.json', 'ALLOW', null], ['deny.json', 'DENY', 'PER_PAYMENT_LIMIT']]) {
  const f = path.join(DEMO, name);
  const r = py(f, path.join(DEMO, 'jwks.json'));
  eq(r.code, 0, name + ' · python exits 0');
  ok(/^VALID/m.test(r.out) && r.out.includes('decision=' + decision), name + ' · VALID, decision=' + decision);
  if (reason) ok(r.out.includes('reason=' + reason) && /\[FAIL\] Under per-payment cap/.test(r.out), name + ' · ★ the refusal names the failing check, signed');
  const v = receipt.verify(Buffer.from(JSON.parse(fs.readFileSync(f, 'utf8')).cose_base64, 'base64'), jwks);
  ok(v.ok && v.payload.decision === decision, name + ' · the Node verifier agrees');
  ok(!('allowed_categories' in v.payload) && v.payload.capability_proof, name + ' · ★ proves the category without disclosing the grant\'s list');
}

// ── THE CHAIN, which is the pair that makes an ALLOW mean something ───────────────────────────────────
// allow.json says the policy permitted a spend. On its own it cannot tell a reader whether money moved.
// settled.json is the ending, signed by the same key and pointing back at the ALLOW. Asserted together,
// because either one alone is the artifact this repo already had.
{
  const f = path.join(DEMO, 'settled.json');
  const r = py(f, path.join(DEMO, 'jwks.json'));
  eq(r.code, 0, 'settled.json · python exits 0');
  ok(/^VALID/m.test(r.out) && r.out.includes('decision=REPORT'), 'settled.json · VALID, decision=REPORT');
  const stl = JSON.parse(fs.readFileSync(f, 'utf8'));
  const allowJson = JSON.parse(fs.readFileSync(path.join(DEMO, 'allow.json'), 'utf8'));
  const v = receipt.verify(Buffer.from(stl.cose_base64, 'base64'), jwks);
  ok(v.ok, 'settled.json · the Node verifier agrees');
  eq(v.payload.parent_receipt_id, allowJson.receipt_id, '★★ the settlement names the ALLOW it descends from — the chain is the evidence');
  eq(v.payload.rail_outcome, 'settled', 'settled.json · rail_outcome=settled');
  ok(typeof v.payload.rail_tx_id === 'string' && v.payload.rail_tx_id, 'settled.json · carries the reported transaction id');
  eq(v.payload.rail_reported_by, 'rail',
     '★★ reported by the RAIL — its own token plus the capability it was handed. NOT the operator secret, and NOT the capability alone: that one is returned to the requester, and a requester able to report `failed` gets its budget back and spends the same money twice');
  eq(v.payload.rail_late, false, 'settled.json · not late — it beat the TTL');
  // The whole reason the schema was bumped. A tx id beside a valid signature reads as "Cosmos saw this
  // settle"; Cosmos cannot see a rail. If this line ever stops printing, the demo starts lying.
  ok(/NOT OBSERVED/.test(r.out) && /does NOT prove that any money moved/.test(r.out),
     '★★ the verifier prints the gap: a valid signature does NOT mean the money moved');
  ok(v.payload.checks.some((c) => c.name === 'Rail outcome observed by Cosmos' && c.pass === false),
     '★ and the same caveat is a FAILING named check inside the signed bytes, not only in the print');
}

{ // one flipped byte → SIGNATURE_INVALID, specifically
  const j = JSON.parse(fs.readFileSync(path.join(DEMO, 'deny.json'), 'utf8'));
  const b = Buffer.from(j.cose_base64, 'base64'); b[b.length - 90] ^= 0x01; j.cose_base64 = b.toString('base64');
  const t = path.join(os.tmpdir(), 'cosmos-demo-tampered-' + process.pid + '.json'); fs.writeFileSync(t, JSON.stringify(j));
  const r = py(t, path.join(DEMO, 'jwks.json'));
  eq(r.code + '/' + /SIGNATURE_INVALID/.test(r.out), '1/true', '★★ one flipped byte → exit 1, SIGNATURE_INVALID');
  try { fs.unlinkSync(t); } catch (_) {}
}
ok(!JSON.stringify(jwks).includes('"d"') && jwks.keys.every((k) => k.kty === 'OKP' && k.crv === 'Ed25519'), 'jwks carries public OKP/Ed25519 keys only');
ok(!fs.existsSync(path.join(DEMO, 'key.txt')) && !fs.readdirSync(DEMO).some((f) => /key|secret|\.env/i.test(f)), '★ no key material in demo/');

// The committed demo is what a stranger reads first. If a receipt ever carries an approver, the demo must
// show the qualifier too — a demo that looks more certain than the product is a lie with a signature on it.
// ⚠ These MUST sit above the summary line: assertions after it still set the exit code but are not counted,
// so the runner would report a stale total and a failure would print below its own summary.
{ const dj = JSON.parse(fs.readFileSync(path.join(DEMO, 'allow.json'), 'utf8'));
  const p = dj.payload_unverified || {};
  ok(p.cosmos_schema === 4, 'the committed demo is schema 4 (regenerate with `npm run demo` after any payload change)');
  ok(p.approver_id === null && p.approver_authenticated === null, '★ the demo receipts carry no approver, so both approval fields are null');
  ok(p.rail_outcome === null && p.rail_reported_by === null && p.rail_late === null,
     '★ …and the ALLOW itself carries no rail claim: the report is a SEPARATE signed artifact, so a decision can never imply an outcome'); }

console.log('\ndemo (committed artifacts verify): ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
