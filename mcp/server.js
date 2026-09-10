#!/usr/bin/env node
// ═══ COSMOS MCP SERVER — the distribution wedge ════════════════════════════════════════════════════════
//
// Agents do not "make payments". They call tools, and some tools cost money. This server sits between an
// MCP client and an upstream MCP server, re-exports the upstream's tools verbatim, and for any tool that
// matches a pricing rule asks Cosmos "may this agent spend $X at Y for Z?" FIRST. ALLOW → the call is
// forwarded and the signed receipt id rides back with the result. DENY → the call never reaches the
// upstream; the agent gets isError:true with the reason and the receipt. Zero code change on the agent:
// point the client at this server instead of the upstream.
//
// Verified against the MCP spec 2025-11-25 (docs/DESIGN.md §10):
//   - stdio transport: newline-delimited JSON-RPC 2.0 on stdout; stderr is for logs
//   - `tools` capability, `tools/list`, `tools/call`; results carry content[], structuredContent, isError
//   - input-validation errors are TOOL EXECUTION errors (isError:true), not protocol errors (SEP-1303)
//   - elicitation is a CLIENT capability: a server MUST NOT send `elicitation/create` unless the client
//     declared it. So ESCALATE has TWO paths — a form-mode elicitation when the client supports it, and an
//     honest refusal (with the out-of-band approval URL) when it does not. Form mode must not request
//     credentials; Cosmos asks for an approval DECISION and an approver id, which is client-asserted and
//     recorded as such in the receipt.
'use strict';
const crypto = require('crypto');
const readline = require('readline');
const { connectUpstream, loadRules, matchRule } = require('./proxy');

const PROTOCOL = '2025-11-25';
const SUPPORTED = new Set(['2025-11-25', '2025-06-18', '2025-03-26']);
const log = (...a) => process.stderr.write('[cosmos-mcp] ' + a.join(' ') + '\n');

const COSMOS_URL = (process.env.COSMOS_URL || 'http://localhost:8787').replace(/\/$/, '');
const GRANT_ID = process.env.COSMOS_GRANT_ID || '';

// ── Cosmos client ───────────────────────────────────────────────────────────────────────────────────────
async function cosmos(path, body) {
  let r;
  try { r = await fetch(COSMOS_URL + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); }
  catch (e) { return { error: 'Cosmos unreachable at ' + COSMOS_URL + ': ' + e.message }; }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) return { error: 'Cosmos ' + r.status + ' ' + (j.error || '') + (j.detail ? ': ' + j.detail : '') };
  return { decision: j };
}
async function authorize(req) {
  if (!GRANT_ID) return { error: 'COSMOS_GRANT_ID is not set' };
  return cosmos('/authorize', {
    grant_id: GRANT_ID, amount_minor: req.amount_minor, currency: req.currency,
    category: req.category || undefined, merchant: req.merchant || undefined, description: req.description || undefined,
    idempotency_key: req.idempotency_key || ('mcp_' + crypto.randomBytes(10).toString('hex')),
  });
}

const text = (s) => ({ type: 'text', text: s });
const summarize = (d) => ({
  decision: d.decision, reason: d.reason, receipt_id: d.receipt_id, kid: d.kid,
  amount_minor: d.amount_minor, currency: d.currency, parent_receipt_id: d.parent_receipt_id || undefined,
  approver_id: d.approver_id || undefined, evidence: COSMOS_URL + d.evidence, jwks: COSMOS_URL + d.jwks,
});
const money = (s) => (s.amount_minor / 100).toFixed(2) + ' ' + s.currency;

const COSMOS_TOOL = {
  name: 'cosmos_authorize',
  title: 'Cosmos spend authorization',
  description: 'Ask whether this agent may spend amount_minor of currency at merchant for category. Returns ALLOW, DENY or ESCALATE plus a signed, offline-verifiable receipt id. Does NOT move money.',
  inputSchema: {
    type: 'object',
    properties: {
      amount_minor: { type: 'integer', description: 'Amount in minor units (cents). Positive integer.' },
      currency: { type: 'string', description: '3-letter code, e.g. USD' },
      category: { type: 'string' }, merchant: { type: 'string' }, description: { type: 'string' },
      idempotency_key: { type: 'string', description: 'Reuse to retry safely; omit for a fresh authorization' },
    },
    required: ['amount_minor', 'currency'],
  },
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
};

// ── JSON-RPC over stdio, both directions ───────────────────────────────────────────────────────────────
function send(msg) { process.stdout.write(JSON.stringify(msg) + '\n'); }
const ok = (id, result) => send({ jsonrpc: '2.0', id, result });
const err = (id, code, message, data) => send({ jsonrpc: '2.0', id, error: Object.assign({ code, message }, data ? { data } : {}) });
const serverPending = new Map();                 // server-initiated requests (elicitation) awaiting the client
let serverReqN = 0;
function requestClient(method, params, timeoutMs) {
  return new Promise((resolve, reject) => {
    const id = 'cosmos-' + (++serverReqN);
    serverPending.set(id, { resolve, reject });
    send({ jsonrpc: '2.0', id, method, params });
    setTimeout(() => { if (serverPending.has(id)) { serverPending.delete(id); reject(new Error('client did not answer ' + method)); } }, timeoutMs || 300000).unref();
  });
}

async function main() {
  const rules = loadRules();
  const upstream = process.env.COSMOS_MCP_UPSTREAM ? await connectUpstream(process.env.COSMOS_MCP_UPSTREAM) : null;
  // Add the pricing rule's `amount_arg` to a re-exported tool's schema, so a host that validates
  // arguments against it will actually send the value the gate prices on. Never mutates the upstream
  // object, and never overwrites a property the upstream already declares — if the upstream has its own
  // `cost`, that one wins and its type is the contract.
  const declareAmountArg = (tool, rules) => {
    const rule = rules.find((r) => r.tool === tool.name && r.amount_arg);
    if (!rule) return tool;
    const schema = tool.inputSchema && tool.inputSchema.type === 'object' ? tool.inputSchema : null;
    if (!schema) return tool;                       // not an object schema: nothing safe to add
    if (schema.properties && schema.properties[rule.amount_arg]) return tool;
    return Object.assign({}, tool, {
      inputSchema: Object.assign({}, schema, {
        properties: Object.assign({}, schema.properties, {
          [rule.amount_arg]: { type: 'integer', minimum: 1,
            description: 'Amount to authorize for this call, in ' + (rule.currency || 'the grant currency') +
                         ' minor units. Read by the Cosmos spend gate; the call is refused without it.' },
        }),
        required: [...new Set([...(schema.required || []), rule.amount_arg])],
      }),
    });
  };

  let upstreamTools = [];
  if (upstream) {
    upstreamTools = await upstream.listTools();
    log('upstream:', process.env.COSMOS_MCP_UPSTREAM, '→', upstreamTools.length, 'tools;', rules.length, 'pricing rule(s)');
  }
  let clientCaps = {};
  // Spec: an empty `elicitation: {}` means form mode; otherwise `form` must be present.
  const formElicitation = () => !!clientCaps.elicitation && (clientCaps.elicitation.form !== undefined || Object.keys(clientCaps.elicitation).length === 0);

  // ESCALATE → ask the human through the client, then resolve with Cosmos. Returns the resolution summary
  // or null if the client cannot be asked.
  async function escalateViaClient(s, toolName) {
    if (!formElicitation()) return null;
    let answer;
    try {
      answer = await requestClient('elicitation/create', {
        mode: 'form',
        message: 'Cosmos: the policy escalated a spend of ' + money(s) + ' by tool "' + toolName + '" (' + (s.reason || 'approval required') +
                 '). Approve it? Receipt ' + s.receipt_id + '. Your id is recorded on the signed receipt as the approver.',
        requestedSchema: {
          type: 'object',
          properties: {
            approve: { type: 'boolean', title: 'Approve this spend?', default: false },
            approver_id: { type: 'string', title: 'Your approver id (name or handle)', minLength: 1 },
          },
          required: ['approve', 'approver_id'],
        },
      });
    } catch (e) { log('elicitation failed:', e.message); return null; }
    const accepted = answer && answer.action === 'accept' && answer.content && answer.content.approve === true;
    const approver = (answer && answer.content && typeof answer.content.approver_id === 'string' && answer.content.approver_id.trim()) || 'mcp-client';
    const r = await cosmos('/approvals/' + s.receipt_id, { decision: accepted ? 'approve' : 'deny', approver_id: approver, channel: 'mcp-elicitation' });
    if (r.error) return { error: r.error };
    return summarize(r.decision);
  }

  const handlers = {
    initialize: async (p) => {
      clientCaps = (p && p.capabilities) || {};
      const v = p && SUPPORTED.has(p.protocolVersion) ? p.protocolVersion : PROTOCOL;
      return { protocolVersion: v, capabilities: { tools: { listChanged: false } },
               serverInfo: { name: 'cosmos', version: '0.1.0', description: 'Spend authorization with signed, offline-verifiable receipts. Never moves money.' } };
    },
    ping: async () => ({}),
    // ⚠ A RULE USING `amount_arg` MUST DECLARE THAT ARGUMENT, or a conformant host strips it.
    // Found by pointing real Claude Code at this server: it validates tool arguments against the published
    // inputSchema and drops unknown properties, so `cost` never arrived and every call died as
    // INVALID_AMOUNT_MINOR before policy ran. My own hand-written test client passed it through happily,
    // which is exactly why a client you wrote yourself proves nothing about a real host.
    // Re-exporting the upstream schema verbatim is wrong when the GATE needs an argument the upstream
    // never declared. The wrapper must publish what the wrapper reads.
    'tools/list': async () => ({ tools: [COSMOS_TOOL, ...upstreamTools.map((t) => declareAmountArg(t, rules))] }),
    'tools/call': async (p) => {
      const name = p && p.name, args = (p && p.arguments) || {};
      if (name === 'cosmos_authorize') {
        if (!Number.isInteger(args.amount_minor) || args.amount_minor <= 0 || typeof args.currency !== 'string') {
          return { content: [text('amount_minor must be a positive integer and currency a string')], isError: true };
        }
        const a = await authorize(args);
        if (a.error) return { content: [text(a.error)], isError: true };
        const s = summarize(a.decision);
        return { content: [text(s.decision + (s.reason ? ' (' + s.reason + ')' : '') + ' — receipt ' + s.receipt_id + ' — verify at ' + s.evidence)],
                 structuredContent: s, isError: s.decision !== 'ALLOW' };
      }
      const tool = upstreamTools.find((t) => t.name === name);
      if (!tool) throw Object.assign(new Error('Unknown tool: ' + name), { code: -32602 });
      const rule = matchRule(rules, name, args);
      if (!rule) return upstream.callTool(name, args);            // unpriced: pass straight through

      const a = await authorize({ amount_minor: rule.amount_minor, currency: rule.currency, category: rule.category,
                                  merchant: rule.merchant, description: name + ' ' + JSON.stringify(args).slice(0, 200) });
      if (a.error) return { content: [text('Cosmos authorization failed closed: ' + a.error)], isError: true };
      let s = summarize(a.decision);
      let chain = null;

      if (s.decision === 'ESCALATE') {
        const resolved = await escalateViaClient(s, name);
        if (!resolved) {
          return { content: [text('Cosmos requires human approval for this call (' + s.reason + '). Not executed. Receipt ' + s.receipt_id +
                              ' — ' + s.evidence + '. Approve out of band: POST ' + COSMOS_URL + '/approvals/' + s.receipt_id +
                              ' {"decision":"approve","approver_id":"…"}')],
                   structuredContent: { _cosmos: s }, isError: true };
        }
        if (resolved.error) return { content: [text('Cosmos approval failed closed: ' + resolved.error)], structuredContent: { _cosmos: s }, isError: true };
        chain = Object.assign({}, resolved, { escalation: s });
        s = chain;
      }
      if (s.decision !== 'ALLOW') {
        const why = s.decision === 'DENY' ? 'DENIED this call: ' + s.reason : s.decision + ' (' + s.reason + ')';
        return { content: [text('Cosmos ' + why + '. Not executed. Receipt ' + s.receipt_id + ' — ' + s.evidence)],
                 structuredContent: { _cosmos: s }, isError: true };
      }
      const result = await upstream.callTool(name, args);           // ALLOW → forward, attach the receipt (chain)
      return Object.assign({}, result, { structuredContent: Object.assign({}, result.structuredContent || {}, { _cosmos: s }) });
    },
  };

  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch (_) { return err(null, -32700, 'Parse error'); }
    if (!msg.method && msg.id !== undefined && serverPending.has(msg.id)) {   // a reply to OUR request
      const p = serverPending.get(msg.id); serverPending.delete(msg.id);
      return msg.error ? p.reject(new Error(msg.error.message || 'client error')) : p.resolve(msg.result);
    }
    if (msg.method && msg.id === undefined) return;                  // notification (e.g. notifications/initialized)
    const h = handlers[msg.method];
    if (!h) return err(msg.id, -32601, 'Method not found: ' + msg.method);
    try { ok(msg.id, await h(msg.params)); }
    catch (e) { err(msg.id, e.code || -32603, e.message || 'Internal error'); }
  });
  rl.on('close', () => { if (upstream) upstream.close(); process.exit(0); });
  log('ready; cosmos at', COSMOS_URL, GRANT_ID ? '(grant ' + GRANT_ID + ')' : '(NO GRANT — set COSMOS_GRANT_ID)');
}

if (require.main === module) main().catch((e) => { log('fatal', e.stack || e); process.exit(1); });
module.exports = { COSMOS_TOOL, PROTOCOL };
