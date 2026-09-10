// `npm run quickstart` — zero to a working spend gate, in one command.
//
// WHY THIS EXISTS. Before it, adopting Cosmos meant: generate a key, generate a write token, start the
// server with the right four environment variables, mint a grant with a curl that needs the token, copy
// the grant id out of the JSON, and only then write an MCP config. Six steps, each with a way to get it
// subtly wrong, before you can see the thing work once. For an agent — or a human evaluating in the two
// minutes they have allotted — that is the whole adoption funnel, and every step in it is a place to
// give up. The product's own claim is "zero code change for the agent"; the setup should match.
//
// It generates EPHEMERAL credentials, prints the exact MCP block filled in, proves the gate works on a
// real allow and a real refusal, and leaves the server in the foreground so Ctrl-C ends it cleanly.
'use strict';
const crypto = require('crypto');
const { start } = require('../api/server');

const b64 = (n) => crypto.randomBytes(n).toString('base64url');
// Ephemeral by design: a quickstart that writes durable secrets to a developer's disk is a quickstart
// that leaks them. The signing key dies with this process, and every receipt it signs dies with it —
// which is exactly why it is fine here and NOT fine in production (`npm run keygen` there).
const WRITE_TOKEN = 'quickstart-' + b64(18);
const RAIL_TOKEN = 'quickstart-rail-' + b64(18);
const { privateKey } = crypto.generateKeyPairSync('ed25519');
const PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');

const PORT = +process.env.PORT || 8787;

(async () => {
  const h = start({
    port: PORT, quiet: true,
    writeToken: WRITE_TOKEN,
    privateKeyPkcs8B64: PRIVATE_KEY,
    kid: 'cosmos-quickstart',
    rail: { provider: process.env.COSMOS_RAIL_PROVIDER || null, token: RAIL_TOKEN },
    file: process.env.COSMOS_LOG || undefined,
  });
  await new Promise((r) => h.server.on('listening', r));
  const B = 'http://localhost:' + h.server.address().port;
  const post = (p, body, tok) => fetch(B + p, {
    method: 'POST',
    headers: Object.assign({ 'content-type': 'application/json' }, tok ? { authorization: 'Bearer ' + tok } : {}),
    body: JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, body: await r.json() }));

  const grant = (await post('/grants', {
    org_id: 'org_quickstart', agent_id: 'agent_quickstart', currency: 'USD',
    budget_minor: 50000, per_payment_cap_minor: 2000, daily_cap_minor: 20000,
    allowed_categories: ['api'],
  }, WRITE_TOKEN)).body;

  // Prove the gate before claiming it works — one spend under the cap, one over it.
  const ask = (amount, key) => post('/authorize', {
    grant_id: grant.grant_id, amount_minor: amount, currency: 'USD',
    category: 'api', merchant: 'quickstart.example', idempotency_key: key,
  });
  const allow = (await ask(1200, 'quickstart-allow')).body;
  const deny = (await ask(9000, 'quickstart-deny')).body;

  const line = (s) => console.log(s);
  line('');
  line('  COSMOS IS RUNNING     ' + B);
  line('  grant                 ' + grant.grant_id + '   ($500.00 budget, $20.00 per-payment cap)');
  line('');
  line('  proof, just now:');
  line('    $12.00  -> ' + allow.decision + '   receipt ' + allow.receipt_id);
  line('    $90.00  -> ' + deny.decision + '    ' + deny.reason + '   receipt ' + deny.receipt_id);
  line('');
  line('  verify the refusal yourself — no account, no network:');
  line('    curl -s ' + B + '/evidence/' + deny.receipt_id + ' > receipt.json');
  line('    curl -s ' + B + '/.well-known/jwks.json > jwks.json');
  line('    python3 verifier/cosmos_verify.py receipt.json jwks.json');
  line('');
  line('  put it in front of a paid MCP tool — your agent changes nothing:');
  line('');
  line(JSON.stringify({ mcpServers: { cosmos: {
    command: 'node', args: ['mcp/server.js'],
    env: {
      COSMOS_URL: B,
      COSMOS_GRANT_ID: grant.grant_id,
      COSMOS_MCP_UPSTREAM: 'npx some-paid-tool-server',
      COSMOS_MCP_RULES: JSON.stringify([{ tool: 'web_search', amount_minor: 50, currency: 'USD', category: 'api', merchant: 'search.example' }]),
    } } } }, null, 2).split('\n').map((l) => '    ' + l).join('\n'));
  line('');
  line('  operator token (this run only):  ' + WRITE_TOKEN);
  line('  rail token      (this run only):  ' + RAIL_TOKEN);
  line('');
  line('  ⚠ EVERYTHING HERE IS EPHEMERAL. The signing key was generated in this process and is not on');
  line('    disk, so every receipt above stops verifying when you stop this server. That is deliberate:');
  line('    a quickstart that writes durable secrets is a quickstart that leaks them. For anything real,');
  line('    run `npm run keygen` and set COSMOS_RECEIPT_PRIVATE_KEY.');
  line('');
  line('  Ctrl-C to stop.');
})().catch((e) => { console.error('quickstart failed:', e && e.message ? e.message : e); process.exit(1); });
