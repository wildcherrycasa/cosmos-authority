// Replay engine — rebuild the WHOLE system from the append-only ledger (its own history).
// Deterministic event → state reconstruction: "we can rerun reality and verify it."
// Every transition appended evidence (open / fund / decision / reservation / reversal / status / submission /
// settlement), so balances, authorization statuses, AND the policy-check breakdown are all rebuildable from events.
function replay(entries) {
  const agents = {}, authorizations = {}, _opened = new Set();
  const A = (id) => agents[id] || (agents[id] = { budget: 0, spent: 0, status: 'active' });
  const T = (id) => authorizations[id] || (authorizations[id] = { id, agentId: null, amount: 0, category: null, merchant: null, approved: null, reason: null, checks: null, status: null, txId: null, provider: null, explorer: null, idempotencyKey: null });
  for (const e of entries) {
    switch (e.kind) {
      case 'open': if (!_opened.has(e.agentId)) { _opened.add(e.agentId); A(e.agentId).budget = e.budget || 0; } break; // first open wins → restart re-opens don't wipe funds
      case 'fund': A(e.agentId).budget = +(A(e.agentId).budget + (e.amount || 0)).toFixed(6); break;
      case 'decision': { const t = T(e.authId); t.agentId = e.agentId; t.amount = e.amount; t.category = e.category; t.merchant = e.merchant; t.approved = e.approved; t.checks = e.checks || null; if (e.reason) t.reason = e.reason; if (e.idempotencyKey) t.idempotencyKey = e.idempotencyKey; break; }
      case 'reservation': A(e.agentId).spent = +(A(e.agentId).spent + (e.amount || 0)).toFixed(6); { const t = T(e.authId); if (e.authId) { t.merchant = t.merchant || e.merchant; if (!t.amount) t.amount = e.amount; } } break;
      case 'reversal': A(e.agentId).spent = +(A(e.agentId).spent - (e.amount || 0)).toFixed(6); if (e.authId) T(e.authId).reason = e.reason || T(e.authId).reason; break;
      case 'status': if (e.authId) T(e.authId).status = e.status; break;
      case 'freeze': A(e.agentId).status = 'frozen'; break;    // operational control (kill switch) — last event wins
      case 'unfreeze': A(e.agentId).status = 'active'; break;  // … so freeze/unfreeze are durable across restart
      case 'submission': if (e.authId) { const t = T(e.authId); t.txId = e.txId || t.txId; t.provider = e.provider || t.provider; t.explorer = e.explorer || t.explorer; } break; // submitted to an external rail; txId in flight, NOT yet final
      case 'settlement': if (e.authId) { const t = T(e.authId); t.txId = e.txId; t.provider = e.provider || t.provider; t.explorer = e.explorer || t.explorer; } break;
    }
  }
  return { agents, authorizations };
}

// Receipts reconstructed purely from history.
function receipts(entries) {
  return Object.values(replay(entries).authorizations).map(a => ({
    receipt: 'rcpt_' + (a.txId ? a.txId.slice(0, 8) : a.id.slice(5, 13)).toUpperCase(),
    authorizationId: a.id, agentId: a.agentId, merchant: a.merchant, amount: a.amount, category: a.category,
    status: a.status, txId: a.txId, provider: a.provider, explorer: a.explorer, reason: a.reason, checks: a.checks,
  }));
}

// verify(entries, live): live = { agents:{id:{budget,spent}}, authorizations:{id:{status,...}} }
function verify(entries, live) {
  const r = replay(entries), diffs = [];
  for (const id in (live.agents || {})) { const a = live.agents[id], b = r.agents[id] || { budget: 0, spent: 0 };
    if (Math.abs((a.budget || 0) - b.budget) > 1e-9) diffs.push({ agentId: id, field: 'budget', live: a.budget, replay: b.budget });
    if (Math.abs((a.spent || 0) - b.spent) > 1e-9) diffs.push({ agentId: id, field: 'spent', live: a.spent, replay: b.spent }); }
  for (const id in (live.authorizations || {})) { const a = live.authorizations[id], b = r.authorizations[id] || {};
    if (a.status !== b.status) diffs.push({ authId: id, field: 'status', live: a.status, replay: b.status }); }
  return { ok: diffs.length === 0, diffs, replay: r };
}

// determinism: same history → byte-identical reconstruction
function isDeterministic(entries) { return JSON.stringify(replay(entries)) === JSON.stringify(replay(entries)); }

module.exports = { replay, receipts, verify, isDeterministic };
