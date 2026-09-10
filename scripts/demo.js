// `npm run demo` — regenerate demo/: a real Cosmos server, a real grant, one ALLOW and one DENY, their
// signed receipts and the JWKS that verifies them. The signing key is generated here and DISCARDED —
// receipts stay verifiable forever against the committed JWKS, and no private key ever touches disk.
// A stranger verifies with:   python3 verifier/cosmos_verify.py demo/deny.json demo/jwks.json
// `python3`, not `python`: the bare name does not exist on macOS 12.3+ or a default Ubuntu, so the
// command this repo publishes as its first impression has to be the one that actually runs there.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path');
const { start } = require('../api/server');

const OUT = path.join(__dirname, '..', 'demo');
fs.mkdirSync(OUT, { recursive: true });
const LOG = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cosmos-demo-')), 'log.jsonl');
// The RAIL's own credential. In a real deployment the operator sets COSMOS_RAIL_TOKEN and gives the same
// secret to the rail out of band — never to the agent. Generated per run and thrown away with the process:
// the demo must show the real two-credential flow, and a demo that hardcodes a secret teaches the wrong
// thing to everyone who copies it.
const DEMO_RAIL_TOKEN = require('crypto').randomBytes(24).toString('base64url');

(async () => {
  const h = await new Promise((r) => { const s = start({ port: 0, file: LOG, quiet: true, kid: 'cosmos-demo-2026-09', rail: { provider: 'demo-rail', token: DEMO_RAIL_TOKEN } }); s.server.on('listening', () => r(Object.assign(s, { port: s.server.address().port }))); });
  const B = 'http://localhost:' + h.port;
  const post = (p, o) => fetch(B + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(o) }).then((r) => r.json());
  const get = (p) => fetch(B + p).then((r) => r.json());

  const grant = await post('/grants', {
    org_id: 'org_demo', agent_id: 'agent_research_01', currency: 'USD',
    budget_minor: 50000, per_payment_cap_minor: 1700, daily_cap_minor: 5000,
    allowed_categories: ['api', 'cloud'], approval_threshold_minor: 1500,
  });
  const allow = await post('/authorize', { grant_id: grant.grant_id, amount_minor: 1200, currency: 'USD', category: 'api', merchant: 'api.openai.com', description: 'embeddings batch 4471', idempotency_key: 'demo-allow' });
  const deny = await post('/authorize', { grant_id: grant.grant_id, amount_minor: 3000, currency: 'USD', category: 'api', merchant: 'api.openai.com', description: 'oversized batch', idempotency_key: 'demo-deny' });
  if (allow.decision !== 'ALLOW' || deny.decision !== 'DENY') throw new Error('demo decisions unexpected: ' + allow.decision + '/' + deny.decision);

  // THE RAIL REPORTS BACK. Two credentials, answering two different questions: the rail's own token proves
  // WHO is speaking, and the one-shot capability from the ALLOW proves WHICH authorization was routed to
  // it. The capability ALONE cannot do this — it is returned to the requester, and a requester that can
  // report `failed` gets its budget back and spends the same money twice. Note what is still NOT here: no
  // call from Cosmos to any rail. Cosmos handed out an address and waited to be told.
  const settled = await fetch(B + allow.rail.report_to, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: 'Bearer ' + DEMO_RAIL_TOKEN,          // WHO is reporting — the rail's own secret
      'x-cosmos-handoff': allow.rail.handoff_token,        // WHICH authorization was routed to it
    },
    body: JSON.stringify({ outcome: 'settled', tx_id: '0x7f3a91c4e2b8', provider: 'demo-rail', explorer: 'https://example.invalid/tx/0x7f3a91c4e2b8' }),
  }).then((r) => r.json());
  if (settled.rail_outcome !== 'settled') throw new Error('demo settlement unexpected: ' + JSON.stringify(settled));

  const write = (name, obj) => fs.writeFileSync(path.join(OUT, name), JSON.stringify(obj, null, 2) + '\n');
  write('allow.json', await get(allow.evidence));
  write('deny.json', await get(deny.evidence));
  write('settled.json', await get(settled.evidence));
  write('jwks.json', await get('/.well-known/jwks.json'));
  write('grant.json', Object.assign({}, grant, { _note: 'the grant these receipts were decided under; the receipts carry a Merkle proof of the ONE category used, never this whole list' }));

  fs.writeFileSync(path.join(OUT, 'README.md'), [
    '# Cosmos demo — verify a receipt with nothing but this folder',
    '',
    'Three real, signed receipts and the public key that verifies them. No account, no network, no Cosmos code:',
    '',
    '```bash',
    'pip install cryptography',
    '# (on Windows the interpreter is `python`, not `python3`)',
    'python3 ../verifier/cosmos_verify.py deny.json jwks.json',
    'python3 ../verifier/cosmos_verify.py allow.json jwks.json',
    'python3 ../verifier/cosmos_verify.py settled.json jwks.json',
    '```',
    '',
    '`deny.json` is the receipt nobody else issues: a signed, offline-verifiable statement that **this spend was refused, under this policy, at this time** — with the failing check named inside. Flip one byte of `cose_base64` and the verifier exits 1 with `SIGNATURE_INVALID`, specifically.',
    '',
    '`settled.json` is the other half, and it is the part that makes an ALLOW mean something. `allow.json` says the policy permitted a spend; on its own it cannot tell you whether the money ever moved. `settled.json` is signed by the same key, points back at `allow.json` through `parent_receipt_id`, and carries the transaction id the rail reported. Together they read: **policy allowed this at T1, and the rail reported it settled at T2.**',
    '',
    '⛔ **And the verifier says out loud what that does NOT mean.** Cosmos never touches money and never sees a rail, so the transaction id is a CLAIM. Run the command and it prints `rail outcome: NOT OBSERVED` above it, naming which credential made the claim. A receipt that let a valid signature imply "Cosmos watched this settle" would be worth less than no receipt at all.',
    '',
    'Format: COSE_Sign1 (RFC 9052), Ed25519, deterministic CBOR (RFC 8949 §4.2), SCITT-shaped (RFC 9943). The signing key was generated for this demo and discarded; the receipts stay verifiable against `jwks.json` forever.',
    '',
    'Regenerate: `npm run demo` (new key, new ids, same shape).',
    '',
  ].join('\n'));

  await new Promise((r) => { h.store.close(); if (h.server.closeAllConnections) h.server.closeAllConnections(); h.server.close(() => r()); });
  try { fs.rmSync(path.dirname(LOG), { recursive: true, force: true }); } catch (_) {}
  console.log('demo/ written: allow.json (' + allow.receipt_id + '), deny.json (' + deny.receipt_id + '), settled.json (' + settled.receipt_id + ' -> ' + allow.receipt_id + '), jwks.json, grant.json, README.md');
  console.log('key discarded; kid ' + allow.kid);
})().catch((e) => { console.error('demo failed:', e); process.exit(1); });
