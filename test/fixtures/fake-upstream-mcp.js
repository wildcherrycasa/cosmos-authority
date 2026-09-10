// A minimal upstream MCP server for tests: one PAID tool and one free one. `paid_search` counts its calls
// and `free_echo` reports the count, so a test can prove a DENIED call never reached the upstream.
'use strict';
const readline = require('readline');
let paidCalls = 0;
const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
const TOOLS = [
  { name: 'paid_search', description: 'A search that costs money per call', inputSchema: { type: 'object', properties: { q: { type: 'string' } }, required: ['q'] } },
  { name: 'free_echo', description: 'Free; returns how many paid_search calls reached this server', inputSchema: { type: 'object', properties: {} } },
];
readline.createInterface({ input: process.stdin, crlfDelay: Infinity }).on('line', (line) => {
  if (!line.trim()) return;
  const m = JSON.parse(line);
  if (m.id === undefined) return;
  if (m.method === 'initialize') return send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'fake-upstream', version: '0' } } });
  if (m.method === 'tools/list') return send({ jsonrpc: '2.0', id: m.id, result: { tools: TOOLS } });
  if (m.method === 'tools/call') {
    const { name, arguments: a } = m.params;
    if (name === 'paid_search') { paidCalls++; return send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'results for ' + a.q + ' (call #' + paidCalls + ')' }], structuredContent: { hits: 3 } } }); }
    if (name === 'free_echo') return send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: String(paidCalls) }], structuredContent: { paid_calls: paidCalls } } });
    return send({ jsonrpc: '2.0', id: m.id, error: { code: -32602, message: 'Unknown tool: ' + name } });
  }
  send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } });
});
