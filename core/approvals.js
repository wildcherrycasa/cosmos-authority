// APPROVAL WORKFLOW — human oversight WITHOUT a human bottleneck. This is the line between "an agent
// with a budget" and "an agent with financial authority AND accountability." Spends at or below an
// agent's approvalThreshold flow autonomously (the policy engine governs them); spends ABOVE it pause
// as 'pending_approval' until the owner approves. So the loop runs end-to-end with no human in it —
// except oversight on the decisions that warrant it. The gate is UPSTREAM of policy/money (like the
// signing + rate-limit gates): a pending command reserves nothing and moves nothing.
//
// State note: `pending` is in-memory, but it is RECONSTRUCTABLE from the ledger — every pause is an
// `approval_request` event and every decision an `approval_decision` event, so rehydrate() rebuilds the
// queue on boot (a pending approval survives a restart). In a multi-replica future the same reconstruction
// makes the queue shared truth; today it is per-process and ledger-backed.
const pending = new Map(); // command_id -> { cmd, agentId, amount, requestedAt }

// Threshold resolution: per-agent override → env default → OFF (Infinity). OFF by default so nothing
// changes until an operator opts in (per agent via agents.json approvalThreshold, or APPROVAL_THRESHOLD).
function thresholdFor(agent) {
  if (agent && agent.approvalThreshold != null) return +agent.approvalThreshold;
  if (process.env.APPROVAL_THRESHOLD != null && process.env.APPROVAL_THRESHOLD !== '') return +process.env.APPROVAL_THRESHOLD;
  return Infinity;
}
function needsApproval(agent, amount, cmd) {
  if (cmd && cmd.approved) return false;          // already approved → let it through
  return +amount > thresholdFor(agent);
}
function record(cmd) { pending.set(cmd.command_id, { cmd, agentId: cmd.agentId, amount: cmd.amount, requestedAt: Date.now() }); return pending.get(cmd.command_id); }
function get(id) { return pending.get(id); }
function list() { return [...pending.values()].map(p => ({ command_id: p.cmd.command_id, agentId: p.agentId, amount: p.amount, requestedAt: p.requestedAt })); }
function resolve(id) { const p = pending.get(id); pending.delete(id); return p; } // one-shot: prevents double-approve double-spend

// Rebuild the pending queue from the ledger on boot. A spend is still pending iff it has an
// `approval_request` but NO `approval_decision` and NO `command` event (i.e. it was never resolved or
// executed). The reconstructed command carries enough to re-run on approval (incl. its idempotency key).
function rehydrate(events) {
  events = events || [];
  const decided = new Set(), executed = new Set();
  for (const e of events) { if (e.kind === 'approval_decision') decided.add(e.commandId); else if (e.kind === 'command') executed.add(e.commandId); }
  let n = 0;
  for (const e of events) {
    if (e.kind !== 'approval_request') continue;
    if (decided.has(e.commandId) || executed.has(e.commandId) || pending.has(e.commandId)) continue;
    const cmd = { command_id: e.commandId, type: 'SPEND', source: e.source || 'api', agentId: e.agentId,
      amount: e.amount, category: e.category || null, idempotencyKey: e.idempotencyKey || null, ts: e.ts };
    pending.set(e.commandId, { cmd, agentId: e.agentId, amount: e.amount, requestedAt: e.ts || Date.now() });
    n++;
  }
  return { rehydrated: n };
}
module.exports = { thresholdFor, needsApproval, record, get, list, resolve, rehydrate, pending };
