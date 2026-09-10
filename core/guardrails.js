// Policy Engine (v1) — structured reason codes + a per-check breakdown for receipts.
// A spend is evaluated here BEFORE any ledger reservation or settlement.
const REASONS = ['NOT_ACTIVE', 'EXPIRED', 'INVALID_AMOUNT', 'INSUFFICIENT_BALANCE', 'PER_PAYMENT_LIMIT', 'DAILY_LIMIT', 'CATEGORY_NOT_ALLOWED'];

function evaluate(agent, amount, category) {
  amount = +amount || 0;
  if (!agent) return { approved: false, reason: 'NO_AGENT', checks: [] };
  const remaining = +(agent.budget - agent.spent).toFixed(6);
  const checks = []; const add = (name, pass) => checks.push({ name, pass });
  let reason = null;

  const active = agent.status === 'active'; add('Active', active); if (!reason && !active) reason = 'NOT_ACTIVE';
  const notExpired = !(agent.expiry && Date.now() > agent.expiry); add('Not expired', notExpired); if (!reason && !notExpired) reason = 'EXPIRED';
  if (!reason && !(amount > 0)) reason = 'INVALID_AMOUNT';
  const funded = amount <= remaining; add('Sufficient balance', funded); if (!reason && !funded) reason = 'INSUFFICIENT_BALANCE';
  if (!agent.freeRein) {
    const perTx = amount <= agent.perPaymentCap; add('Under per-payment cap', perTx); if (!reason && !perTx) reason = 'PER_PAYMENT_LIMIT';
    const daily = (agent.spentToday || 0) + amount <= agent.dailyCap; add('Under daily cap', daily); if (!reason && !daily) reason = 'DAILY_LIMIT';
    const cat = !(category && Array.isArray(agent.allowedCategories) && !agent.allowedCategories.includes(category)); add('Category allowed', cat); if (!reason && !cat) reason = 'CATEGORY_NOT_ALLOWED';
  } else add('Free rein (caps bypassed)', true);

  return reason ? { approved: false, reason, checks } : { approved: true, checks };
}
module.exports = { evaluate, REASONS };

if (require.main === module) {
  const a = () => ({ status: 'active', expiry: null, budget: 50, spent: 0, spentToday: 0, perPaymentCap: 17, dailyCap: 50, allowedCategories: ['api', 'cloud', 'subscription'], freeRein: false });
  const out = [], ok = (c, m) => { out.push((c ? 'PASS' : 'FAIL') + ' · ' + m); if (!c) process.exitCode = 1; };
  ok(evaluate(a(), 5, 'api').approved, '$5 api → approved');
  ok(evaluate(a(), 5, 'api').checks.every(c => c.pass), 'approved → all checks pass');
  ok(evaluate(a(), 30, 'api').reason === 'PER_PAYMENT_LIMIT', '$30 → PER_PAYMENT_LIMIT');
  ok(evaluate(a(), 5, 'gambling').reason === 'CATEGORY_NOT_ALLOWED', 'bad category → CATEGORY_NOT_ALLOWED');
  let f = a(); f.status = 'frozen'; ok(evaluate(f, 1, 'api').reason === 'NOT_ACTIVE', 'frozen → NOT_ACTIVE');
  let b = a(); b.spent = 48; ok(evaluate(b, 5, 'api').reason === 'INSUFFICIENT_BALANCE', 'over balance → INSUFFICIENT_BALANCE');
  let d = a(); d.spentToday = 48; ok(evaluate(d, 5, 'api').reason === 'DAILY_LIMIT', 'over daily → DAILY_LIMIT');
  let e = a(); e.expiry = Date.now() - 1; ok(evaluate(e, 1, 'api').reason === 'EXPIRED', 'expired → EXPIRED');
  console.log(out.join('\n'));
}
