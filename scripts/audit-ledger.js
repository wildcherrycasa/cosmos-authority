// ═══ audit:ledger — does the running server agree with what is actually on disk? ═══════════════════════
//
// This is the day-3 acceptance check, and it is deliberately CROSS-PROCESS. It folds the JSONL file from
// disk with replay.js, fetches the server's incrementally-maintained live projection from GET /audit, and
// diffs them with replay.verify(). Two different code paths, two different processes, one answer.
//
// A divergence means one of:
//   - an event was acknowledged in memory but never durably written  (the group-commit durability bug)
//   - the incremental applier and the fold disagree                  (a logic bug in one of them)
//   - something wrote to the log out of band
'use strict';
const fs = require('fs'), path = require('path');
const replay = require('../core/replay');

const PORT = +process.env.PORT || 8787;
const FILE = process.env.COSMOS_LOG || path.join(process.cwd(), 'data', 'cosmos.jsonl');

function loadFromDisk(file) {
  if (!fs.existsSync(file)) return { events: [], skipped: 0 };
  const events = []; let skipped = 0;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const s = line.trim(); if (!s) continue;
    let e;
    try { e = JSON.parse(s); } catch (_) { skipped++; continue; }
    if (!e || typeof e !== 'object' || Array.isArray(e)) { skipped++; continue; }
    events.push(e);
  }
  return { events, skipped };
}

// /audit is an operator path (PR #3): it discloses every grant, so it needs the same bearer token the
// server was started with. This tool runs on the box beside the server, so reading COSMOS_WRITE_TOKEN from
// the environment is the same trust boundary the server already sits behind — it is not a new secret.
const TOKEN = process.env.COSMOS_WRITE_TOKEN || null;
const getJson = (url) => fetch(url, TOKEN ? { headers: { authorization: 'Bearer ' + TOKEN } } : undefined).then((r) => {
  if (r.status === 401) {
    throw answered(new Error('401 from ' + url + ' — /audit now requires the operator token. Run this with the same ' +
      'COSMOS_WRITE_TOKEN the server was started with:  COSMOS_WRITE_TOKEN=… npm run audit:ledger'));
  }
  if (!r.ok) throw answered(new Error('HTTP ' + r.status + ' from ' + url));
  return r.json();
});

// Any HTTP status — 401 included — is PROOF the server is up. Only a transport failure means unreachable.
function answered(err) { err.serverAnswered = true; return err; }

(async () => {
  const { events, skipped } = loadFromDisk(FILE);
  console.log('log:     ' + FILE);
  console.log('events:  ' + events.length + (skipped ? '  (' + skipped + ' malformed lines skipped)' : ''));

  let live;
  try { live = await getJson('http://localhost:' + PORT + '/audit'); }
  catch (e) {
    // Found running this against a live container: a 401 printed "CANNOT REACH THE SERVER — start it with
    // `npm start`", which sends the operator to restart the one thing that is demonstrably working. The
    // server answered; it just refused. Only say unreachable when nothing answered at all.
    if (!e.serverAnswered) console.error('\nCANNOT REACH THE SERVER on port ' + PORT + ' — start it with `npm start`.');
    console.error(String(e.message || e));
    process.exit(2);
  }

  const v = replay.verify(events, live);
  const agents = Object.keys(v.replay.agents).length;
  const auths = Object.keys(v.replay.authorizations).length;
  console.log('grants:  ' + agents + '   authorizations: ' + auths);

  for (const id of Object.keys(v.replay.agents)) {
    const a = v.replay.agents[id];
    console.log('  ' + id + '  budget=' + a.budget + '  spent=' + a.spent +
                '  available=' + (a.budget - a.spent) + '  status=' + a.status);
  }

  // ⚠ SAY WHAT WAS ACTUALLY COMPARED. `replay.verify` loops over the keys of `live`, so a field the live
  // projection never populates contributes ZERO comparisons and still reports "zero diffs". That is the
  // house failure mode: a control that cannot match is indistinguishable from one that is working.
  // Authorization status is exactly that today — `status` is set only by a `status` event, and Cosmos
  // emits none (they are a rail-side concept it inherited and never uses), so `/audit` returns an empty
  // authorizations map and this tool reconciles agent budgets ONLY. Printing "authorizations: 24" one line
  // above a bare "zero diffs" invites the reader to believe those 24 were checked. They were not.
  const liveAuths = Object.keys(live.authorizations || {}).length;
  const scope = 'agent budget + spend across ' + agents + ' grant(s)';
  if (v.ok) {
    console.log('\nOK — ' + scope + ' matches a fresh fold of the log on disk. Zero diffs.');
    if (auths > 0 && liveAuths === 0) {
      console.log('NOT RECONCILED: authorization status, for all ' + auths + ' of them. /audit exposes no');
      console.log('  authorization state (nothing emits a `status` event), so there was nothing to compare');
      console.log('  against and this half of the check could not have failed. Do not read it as passing.');
    }
    process.exit(0);
  }
  console.error('\nDRIFT DETECTED — ' + v.diffs.length + ' diff(s):');
  for (const d of v.diffs) console.error('  ' + JSON.stringify(d));
  process.exit(1);
})();
