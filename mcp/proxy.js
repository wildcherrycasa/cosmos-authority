// ═══ UPSTREAM MCP CLIENT + PRICING RULES ═══════════════════════════════════════════════════════════════
// Spawns the upstream MCP server as a child process, speaks JSON-RPC to it over stdio, and exposes
// listTools()/callTool(). Pricing rules decide which upstream tools cost money and how much.
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const readline = require('readline');

// COSMOS_MCP_RULES is inline JSON or a path to a JSON file:
//   [{ "tool": "web_search", "amount_minor": 50, "currency": "USD", "category": "api", "merchant": "search.example" }]
// Optional "amount_arg": read the amount from that tool argument instead of a fixed amount_minor.
function loadRules() {
  const raw = process.env.COSMOS_MCP_RULES;
  if (!raw) return [];
  let txt = raw.trim();
  if (!txt.startsWith('[') && fs.existsSync(txt)) txt = fs.readFileSync(txt, 'utf8');
  let rules;
  try { rules = JSON.parse(txt); } catch (e) { throw new Error('COSMOS_MCP_RULES is not valid JSON: ' + e.message); }
  if (!Array.isArray(rules)) throw new Error('COSMOS_MCP_RULES must be a JSON array');
  for (const r of rules) {
    if (typeof r.tool !== 'string' || typeof r.currency !== 'string') throw new Error('rule needs tool + currency: ' + JSON.stringify(r));
    if (!r.amount_arg && !(Number.isInteger(r.amount_minor) && r.amount_minor > 0)) throw new Error('rule needs a positive integer amount_minor or an amount_arg: ' + JSON.stringify(r));
  }
  return rules;
}

function matchRule(rules, toolName, args) {
  const r = rules.find((x) => x.tool === toolName);
  if (!r) return null;
  if (r.amount_arg) {
    const v = args && args[r.amount_arg];
    if (!Number.isInteger(v) || v <= 0) return Object.assign({}, r, { amount_minor: -1 });   // will be refused by Cosmos → 400 → fails closed
    return Object.assign({}, r, { amount_minor: v });
  }
  return r;
}

// Minimal MCP client over stdio. `spec` is a shell-style command line, e.g. "node upstream.js --flag".
async function connectUpstream(spec) {
  const parts = spec.match(/(?:[^\s"]+|"[^"]*")+/g).map((s) => s.replace(/^"|"$/g, ''));
  const child = spawn(parts[0], parts.slice(1), { stdio: ['pipe', 'pipe', 'inherit'] });
  const pending = new Map();
  let nextId = 1;
  const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let m; try { m = JSON.parse(line); } catch (_) { return; }
    if (m.id === undefined || !pending.has(m.id)) return;
    const { resolve, reject } = pending.get(m.id); pending.delete(m.id);
    if (m.error) reject(Object.assign(new Error(m.error.message || 'upstream error'), { code: m.error.code }));
    else resolve(m.result);
  });
  const request = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    setTimeout(() => { if (pending.has(id)) { pending.delete(id); reject(new Error('upstream timeout: ' + method)); } }, 30000).unref();
  });
  const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');

  await request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'cosmos-mcp-proxy', version: '0.1.0' } });
  notify('notifications/initialized', {});

  return {
    listTools: async () => { const r = await request('tools/list', {}); return (r && r.tools) || []; },
    callTool: (name, args) => request('tools/call', { name, arguments: args || {} }),
    close: () => { try { child.stdin.end(); } catch (_) {} try { child.kill(); } catch (_) {} },
    pid: child.pid,
  };
}

module.exports = { loadRules, matchRule, connectUpstream };
