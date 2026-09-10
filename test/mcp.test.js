// ═══ MCP END-TO-END — an agent calls a paid tool through Cosmos with zero code change ══════════════════
//
// The distribution claim, tested literally. A real Cosmos server, a real (fake) upstream MCP server, and
// the Cosmos MCP proxy between them, driven over stdio JSON-RPC exactly as a client would. The upstream
// counts the paid calls that actually reach it, so "a DENIED call never executed" is a measured fact.
'use strict';
const fs = require('fs'), os = require('os'), path = require('path');
const { spawn } = require('child_process');
const readline = require('readline');
const { start } = require('../api/server');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };
const eq = (a, e, m) => {
  if (a === e) { pass++; console.log('  ✓ ' + m); return; }
  fail++; console.log('  ✗ ' + m);
  console.log('      expected: ' + JSON.stringify(e)); console.log('      actual:   ' + JSON.stringify(a));
};

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'cosmos-mcp-'));
const UPSTREAM = path.join(__dirname, 'fixtures', 'fake-upstream-mcp.js');
const SERVER = path.join(__dirname, '..', 'mcp', 'server.js');

// A raw MCP client over stdio — deliberately NOT reusing mcp/proxy.js, so the server is exercised by an
// independent implementation of the framing.
function client(cmd, args, env) {
  const child = spawn(cmd, args, { env: Object.assign({}, process.env, env), stdio: ['pipe', 'pipe', 'pipe'] });
  const pending = new Map(); let id = 0; const stderr = [];
  const api = { stderr, elicitations: [], onServerRequest: null };
  child.stderr.on('data', (d) => stderr.push(String(d)));
  readline.createInterface({ input: child.stdout, crlfDelay: Infinity }).on('line', async (line) => {
    if (!line.trim()) return;
    let m; try { m = JSON.parse(line); } catch (_) { fail++; console.log('  ✗ non-JSON on stdout: ' + line); return; }
    if (m.method && m.id !== undefined) {                              // a SERVER-initiated request (elicitation)
      api.elicitations.push(m);
      const result = api.onServerRequest ? await api.onServerRequest(m.method, m.params) : { action: 'cancel' };
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result }) + '\n');
      return;
    }
    const p = pending.get(m.id); if (!p) return; pending.delete(m.id); p(m);
  });
  api.call = (method, params) => new Promise((resolve) => { const i = ++id; pending.set(i, resolve); child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: i, method, params }) + '\n'); });
  api.notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  api.close = () => { try { child.stdin.end(); } catch (_) {} try { child.kill(); } catch (_) {} };
  return api;
}

(async () => {
  const h = await new Promise((r) => { const s = start({ port: 0, file: path.join(TMP, 'log.jsonl'), quiet: true }); s.server.on('listening', () => r(Object.assign(s, { port: s.server.address().port }))); });
  const URL = 'http://localhost:' + h.port;
  const post = (p, o) => fetch(URL + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(o) }).then((r) => r.json());
  const grant = await post('/grants', { org_id: 'o1', agent_id: 'agent-x', currency: 'USD', budget_minor: 10000, per_payment_cap_minor: 1700, daily_cap_minor: 100000, allowed_categories: ['api'], approval_threshold_minor: 1500 });

  const c = client('node', [SERVER], {
    COSMOS_URL: URL, COSMOS_GRANT_ID: grant.grant_id,
    COSMOS_MCP_UPSTREAM: 'node "' + UPSTREAM + '"',                 // a path WITH SPACES, quoted — real-world case
    COSMOS_MCP_RULES: JSON.stringify([{ tool: 'paid_search', amount_arg: 'cost', currency: 'USD', category: 'api', merchant: 'search.example' }]),
  });

  console.log('\n── A · HANDSHAKE ──────────────────────────────────────────────────────────────────────────');
  const init = await c.call('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '0' } });
  eq(init.result && init.result.protocolVersion, '2025-11-25', 'A1 · negotiates protocol 2025-11-25');
  ok(init.result && init.result.capabilities && init.result.capabilities.tools, 'A2 · declares the tools capability');
  eq(init.result && init.result.serverInfo.name, 'cosmos', 'A3 · serverInfo.name = cosmos');
  c.notify('notifications/initialized', {});
  eq(JSON.stringify((await c.call('ping', {})).result), '{}', 'A4 · ping');
  eq((await c.call('nope/method', {})).error.code, -32601, 'A5 · unknown method → -32601');

  console.log('\n── B · tools/list — upstream tools re-exported VERBATIM, plus cosmos_authorize ─────────────');
  const list = (await c.call('tools/list', {})).result.tools;
  const names = list.map((t) => t.name).sort().join(',');
  eq(names, 'cosmos_authorize,free_echo,paid_search', 'B1 · ★ the agent sees the upstream tools unchanged, plus one');
  ok(list.find((t) => t.name === 'paid_search').inputSchema.properties.q, 'B2 · the upstream schema keeps its own properties (see §S: a PRICED tool also GAINS the amount_arg the gate reads, because a conformant host drops undeclared properties)');
  ok(list.find((t) => t.name === 'cosmos_authorize').inputSchema.required.includes('amount_minor'), 'B3 · cosmos_authorize has an input schema');

  const callTool = async (name, args) => (await c.call('tools/call', { name, arguments: args })).result;
  const cosmosOf = (r) => r.structuredContent && (r.structuredContent._cosmos || r.structuredContent);

  console.log('\n── C · THE GATE: ALLOW forwards, DENY and ESCALATE never reach the upstream ─────────────');
  let r = await callTool('cosmos_authorize', { amount_minor: 500, currency: 'USD', category: 'api', merchant: 'direct.example' });
  eq(r.isError, false, 'C1 · explicit cosmos_authorize $5 → ALLOW');
  ok(/^auth_/.test(cosmosOf(r).receipt_id), 'C2 · ★ a receipt id comes back (' + cosmosOf(r).receipt_id + ')');
  ok(/\/evidence\/auth_/.test(cosmosOf(r).evidence), 'C3 · …with a full evidence URL');

  r = await callTool('paid_search', { q: 'alpha', cost: 1200 });
  ok(!r.isError, 'C4 · ★★ paid_search $12 → ALLOW → FORWARDED');
  ok(/results for alpha \(call #1\)/.test(r.content[0].text), 'C5 · ★ the upstream\'s own result is returned verbatim');
  eq(r.structuredContent.hits, 3, 'C6 · the upstream\'s structuredContent survives…');
  eq(cosmosOf(r).decision, 'ALLOW', 'C7 · ★ …with the Cosmos receipt attached under _cosmos');
  const RECEIPT = cosmosOf(r).receipt_id;
  // ⛔ THE SETTLEMENT CAPABILITY MUST NOT REACH THE MODEL. An ALLOW carries `rail.handoff_token`, the
  // one-shot credential that can cancel a budget reversal. `structuredContent` goes into an LLM's context,
  // which is transcribed, logged and shipped to a provider — the single worst place to put a bearer token.
  // `summarize()` is an explicit field allow-list, so this holds BY CONSTRUCTION; asserted anyway, because
  // one edit replacing that list with a spread would leak it silently and nothing else would notice.
  ok(!('rail' in cosmosOf(r)), 'C7a · ★★ the ALLOW summary handed to the model carries NO rail block');
  ok(!/handoff|_token"/.test(JSON.stringify(r)), 'C7b · ★★ …and no settlement capability appears anywhere in the tool result');

  r = await callTool('paid_search', { q: 'beta', cost: 1600 });
  eq(r.isError, true, 'C8 · ★★ $16 is over the $15 approval line → ESCALATE → isError');
  eq(cosmosOf(r).decision + '/' + cosmosOf(r).reason, 'ESCALATE/APPROVAL_REQUIRED', 'C9 · the decision and reason are structured');
  ok(/human approval/i.test(r.content[0].text) && /Not executed/.test(r.content[0].text), 'C10 · ★ the text says NOT EXECUTED and why');

  r = await callTool('paid_search', { q: 'gamma', cost: 3000 });
  eq(r.isError, true, 'C11 · ★★ $30 over the $17 cap → DENY → isError');
  eq(cosmosOf(r).reason, 'PER_PAYMENT_LIMIT', 'C12 · with the specific reason');
  ok(/DENIED/.test(r.content[0].text) && /auth_/.test(r.content[0].text), 'C13 · ★ the model is told it was denied AND given the receipt id to cite');

  r = await callTool('paid_search', { q: 'delta', cost: 1200 });
  ok(!r.isError && /call #2/.test(r.content[0].text), 'C14 · a later valid call still goes through (call #2)');

  r = await callTool('free_echo', {});
  eq(r.structuredContent.paid_calls, 2, 'C15 · ★★★ THE UPSTREAM SAW EXACTLY 2 PAID CALLS — the ESCALATE and the DENY never executed');
  ok(!r.structuredContent._cosmos, 'C16 · ★ an unpriced tool passes straight through with no Cosmos involvement');

  console.log('\n── D · FAIL CLOSED, and validation errors are TOOL errors not protocol errors ─────────────');
  r = await callTool('paid_search', { q: 'no-cost' });
  eq(r.isError, true, 'D1 · ★ a priced tool called without its amount arg fails CLOSED');
  ok(/failed closed/.test(r.content[0].text), 'D2 · …and says so');
  r = await callTool('paid_search', { q: 'str', cost: '1200' });
  eq(r.isError, true, 'D3 · ★ a string amount fails closed — Cosmos rejected it with 400');
  eq((await callTool('free_echo', {})).structuredContent.paid_calls, 2, 'D4 · ★★ neither reached the upstream');
  r = await callTool('cosmos_authorize', { amount_minor: 'twelve', currency: 'USD' });
  eq(r.isError, true, 'D5 · ★ bad input → isError:true (SEP-1303: tool error, so the model can self-correct)');
  const unk = await c.call('tools/call', { name: 'does_not_exist', arguments: {} });
  eq(unk.error && unk.error.code, -32602, 'D6 · ★ an UNKNOWN tool is a protocol error (-32602), per spec');

  console.log('\n── E · IDEMPOTENCY AND EVIDENCE THROUGH THE MCP PATH ────────────────────────────────────');
  const a1 = cosmosOf(await callTool('cosmos_authorize', { amount_minor: 100, currency: 'USD', category: 'api', idempotency_key: 'mcp-k1' }));
  const a2 = cosmosOf(await callTool('cosmos_authorize', { amount_minor: 100, currency: 'USD', category: 'api', idempotency_key: 'mcp-k1' }));
  eq(a1.receipt_id, a2.receipt_id, 'E1 · ★ a reused idempotency key returns the SAME receipt');
  const ev = await fetch(URL + '/evidence/' + RECEIPT).then((x) => x.json());
  eq(ev.self_check, 'ok', 'E2 · ★★ the receipt issued via MCP is a real signed receipt served by /evidence');
  eq(ev.payload_unverified.merchant, 'search.example', 'E3 · the pricing rule\'s merchant is in the signed payload');
  ok(!c.stderr.join('').includes('fatal'), 'E4 · no fatal errors on the server\'s stderr');

  console.log('\n── F · ESCALATE via ELICITATION — a client that declared the capability ─────────────────');
  const c2 = client('node', [SERVER], {
    COSMOS_URL: URL, COSMOS_GRANT_ID: grant.grant_id, COSMOS_MCP_UPSTREAM: 'node "' + UPSTREAM + '"',
    COSMOS_MCP_RULES: JSON.stringify([{ tool: 'paid_search', amount_arg: 'cost', currency: 'USD', category: 'api', merchant: 'search.example' }]),
  });
  await c2.call('initialize', { protocolVersion: '2025-11-25', capabilities: { elicitation: { form: {} } }, clientInfo: { name: 'test-elicit', version: '0' } });
  c2.notify('notifications/initialized', {});
  const call2 = async (name, args) => (await c2.call('tools/call', { name, arguments: args })).result;
  const before = (await call2('free_echo', {})).structuredContent.paid_calls;

  // The human APPROVES.
  c2.onServerRequest = async (method, p) => (method === 'elicitation/create' ? { action: 'accept', content: { approve: true, approver_id: 'ops-1' } } : { action: 'cancel' });
  r = await call2('paid_search', { q: 'needs-approval', cost: 1600 });
  const el = c2.elicitations[c2.elicitations.length - 1];
  eq(el && el.method, 'elicitation/create', 'F1 · ★★ the server sent elicitation/create — because the client declared the capability');
  eq(el.params.mode, 'form', 'F2 · form mode');
  ok(/16\.00 USD/.test(el.params.message) && /auth_/.test(el.params.message), 'F3 · ★ the human sees the amount and the receipt id');
  ok(el.params.requestedSchema.required.includes('approve') && el.params.requestedSchema.properties.approver_id, 'F4 · ★ the form asks for a decision and an approver id — never a credential');
  ok(!r.isError, 'F5 · ★★ approved → the tool call is FORWARDED');
  eq(cosmosOf(r).decision + '/' + cosmosOf(r).reason, 'ALLOW/APPROVED_BY_HUMAN', 'F6 · ★ the approval receipt says ALLOW / APPROVED_BY_HUMAN');
  eq(cosmosOf(r).approver_id, 'ops-1', 'F7 · ★ …with the approver recorded');
  eq(cosmosOf(r).escalation && cosmosOf(r).escalation.decision, 'ESCALATE', 'F8 · ★ the ESCALATE receipt is chained under `escalation`');
  eq(cosmosOf(r).parent_receipt_id, (cosmosOf(r).escalation || {}).receipt_id, 'F9 · ★★ parent_receipt_id links the approval to the escalation — the chain IS the evidence');
  eq((await call2('free_echo', {})).structuredContent.paid_calls, before + 1, 'F10 · ★★ the upstream saw exactly one more call');

  // The human DECLINES.
  c2.onServerRequest = async () => ({ action: 'decline' });
  r = await call2('paid_search', { q: 'declined', cost: 1600 });
  eq(r.isError, true, 'F11 · ★★ declined → isError');
  eq(cosmosOf(r).decision + '/' + cosmosOf(r).reason, 'DENY/DENIED_BY_APPROVER', 'F12 · ★ a signed DENY with DENIED_BY_APPROVER');
  eq((await call2('free_echo', {})).structuredContent.paid_calls, before + 1, 'F13 · ★★ …and the upstream was NOT called');

  // The human accepts the form but answers approve:false.
  c2.onServerRequest = async () => ({ action: 'accept', content: { approve: false, approver_id: 'ops-2' } });
  r = await call2('paid_search', { q: 'no', cost: 1600 });
  eq(cosmosOf(r).decision + '/' + cosmosOf(r).approver_id, 'DENY/ops-2', 'F14 · ★ accept-with-approve:false is a DENY attributed to ops-2');

  // A client WITHOUT the capability (the original `c`) gets the honest refusal with the out-of-band URL.
  r = await callTool('paid_search', { q: 'no-elicit', cost: 1600 });
  ok(r.isError && /POST .*\/approvals\/auth_/.test(r.content[0].text), 'F15 · ★★ without elicitation: refused, and told exactly where to approve out of band');
  eq(c.elicitations.length, 0, 'F16 · ★ the server never sent an elicitation to a client that did not declare it (spec MUST NOT)');
  c2.close();

  c.close();
  await new Promise((r2) => { h.store.close(); if (h.server.closeAllConnections) h.server.closeAllConnections(); h.server.close(() => r2()); });
  // ── ★★ S · A PRICED ARGUMENT MUST BE DECLARED, OR A REAL HOST STRIPS IT ─────────────────────────────
  // Found by pointing actual Claude Code at this server through --mcp-config. It validates tool arguments
  // against the published inputSchema and DROPS unknown properties, so the `cost` the pricing rule prices
  // on never arrived and every call died as INVALID_AMOUNT_MINOR before policy ever ran. The hand-written
  // test client in this repo passed `cost` through happily, which is precisely why a client you wrote
  // yourself proves your server speaks the spec as YOU read it — not that a host can use it.
  {
    const S = client('node', [SERVER], {
      COSMOS_URL: URL, COSMOS_GRANT_ID: grant.grant_id,
      COSMOS_MCP_UPSTREAM: 'node "' + UPSTREAM + '"',
      COSMOS_MCP_RULES: JSON.stringify([{ tool: 'paid_search', amount_arg: 'cost', currency: 'USD', category: 'api', merchant: 'm' }]),
    });
    await S.call('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'schema', version: '0' } });
    S.notify('notifications/initialized');
    const tools = (await S.call('tools/list', {})).result.tools;
    const t = tools.find((x) => x.name === 'paid_search');
    ok(!!(t && t.inputSchema && t.inputSchema.properties && t.inputSchema.properties.cost),
      '★★ S1 · the re-exported tool DECLARES the amount_arg the gate prices on — a conformant host drops undeclared properties, so an undeclared one is never sent and every priced call fails before policy');
    ok(!!(t && (t.inputSchema.required || []).includes('cost')),
      '★ S2 · …and marks it required, so a host that omits it is told at validation rather than by a 400 from Cosmos');
    const q = t && t.inputSchema.properties && t.inputSchema.properties.q;
    ok(!!q, '★ S3 · the upstream\'s own properties survive — we add to the schema, never replace it');
    const free = tools.find((x) => x.name === 'free_echo');
    ok(!!(free && !(free.inputSchema.properties || {}).cost),
      '★ S4 · a tool with NO pricing rule is re-exported untouched — the wrapper adds nothing it does not read');
    S.close();
  }

  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch (_) {}
  console.log('\nmcp (end-to-end): ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('\nFATAL', e); process.exit(1); });
