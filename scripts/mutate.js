// `node scripts/mutate.js <spec.json>` — rule 4 made repeatable: every test needs teeth.
//
// For each mutation in the spec: apply it to the module ON DISK, run the FULL aggregating suite, record
// which suites failed and the first NAMED assertion that caught it, restore the file BYTE-IDENTICAL, and
// verify the restore against git's blob (not the working tree — Klutch's CRLF lesson). A mutation that
// SURVIVES the whole suite is the finding; the run exits non-zero if any does.
//
// Spec: [{ "file": "core/guardrails.js", "name": "…", "from": "<exact substring>", "to": "<replacement>" }]
// `from` must occur exactly once, so a mutation cannot silently apply to the wrong line.
'use strict';
const { spawnSync, execFileSync } = require('child_process');
const crypto = require('crypto'), fs = require('fs'), path = require('path');

const root = path.join(__dirname, '..');
// A spec entry with no `file` is documentation, not a mutation — it lets a spec carry the reasoning for
// why it exists (or why it is expected to survive) next to the mutation instead of in a commit message
// nobody re-reads. Skipped silently here; the count printed below is of real mutations only.
const rawSpec = JSON.parse(fs.readFileSync(path.resolve(process.argv[2]), 'utf8'));
const spec = rawSpec.filter((m) => m && m.file && m.from != null && m.to != null);
if (!spec.length) { console.log('no mutations in ' + process.argv[2] + ' (' + rawSpec.length + ' entries, all documentation?)'); process.exit(2); }
const sha = (b) => crypto.createHash('sha256').update(Buffer.from(b.toString('utf8').replace(/\r\n/g, '\n'))).digest('hex');
const blob = (p) => execFileSync('git', ['-C', root, 'show', 'HEAD:' + p]);

// PRE-FLIGHT: every target must be COMMITTED. The restore check verifies the file against its git blob, so
// a target with uncommitted edits fails that check AFTER the first mutation has already run — which reads as
// "RESTORE FAILED" (corruption) when it is really "you never committed" (2026-09-06, the raw-COSE path).
// Refuse up front instead: fail fast, and never weaken the blob check, which is the thing that would catch a
// real botched restore.
{
  const dirty = [...new Set(spec.map((m) => m.file))].filter((f) => {
    const abs = path.join(root, f);
    if (!fs.existsSync(abs)) return true;
    let b = null; try { b = blob(f); } catch (_) { return true; }
    return sha(fs.readFileSync(abs)) !== sha(b);
  });
  if (dirty.length) {
    console.log('REFUSING TO START — these targets differ from their git blob (uncommitted, or untracked):\n' +
      dirty.map((f) => '  - ' + f).join('\n') +
      '\nCommit them first. The restore check compares disk against `git show HEAD:<file>`, so a dirty target\n' +
      'cannot be verified as restored — and an unverifiable restore is worse than no mutation run.');
    process.exit(2);
  }
}

let survived = 0;
const unnamed = [];
for (const m of spec) {
  const abs = path.join(root, m.file);
  const orig = fs.readFileSync(abs);
  const text = orig.toString('utf8');
  const n = text.split(m.from).length - 1;
  if (n !== 1) { console.log('!! ' + m.name + ': `from` occurs ' + n + ' times (must be exactly 1) — mutation NOT applied'); survived++; continue; }
  fs.writeFileSync(abs, text.replace(m.from, m.to));
  let out = '';
  try { out = spawnSync(process.execPath, [path.join(root, 'scripts', 'test-all.js')], { encoding: 'utf8', cwd: root }).stdout || ''; }
  finally {
    fs.writeFileSync(abs, orig);
    const restored = sha(fs.readFileSync(abs)) === sha(orig) && sha(fs.readFileSync(abs)) === sha(blob(m.file));
    if (!restored) { console.log('!! RESTORE FAILED for ' + m.file + ' — STOP'); process.exit(2); }
  }
  // HUNG counts as caught (the suite did not pass) but is reported as such — a hang is never a named assertion.
  const failedSuites = out.split('\n').filter((l) => /\s(FAIL|CRASH|HUNG)$/.test(l))
    .map((l) => l.trim().split(/\s+/)[0] + (/HUNG$/.test(l) ? '(HUNG)' : /CRASH$/.test(l) ? '(CRASH)' : ''));
  const named = out.split('\n').filter((l) => /✗/.test(l)).slice(0, 3).map((l) => l.trim());
  if (failedSuites.length) {
    // A mutation that only CRASHES or HANGS the suite is caught, but not by an assertion that says what
    // broke — and rule 4 asks for a NAMED assertion with printed values. Label it, so a run cannot report
    // "caught by a named assertion" for something no assertion actually named (2026-09-06, mutation E5).
    if (!named.length) unnamed.push(m.name);
    console.log((named.length ? 'CAUGHT   ' : 'CAUGHT*  ') + m.name.padEnd(58) + ' → ' + failedSuites.join(', ') +
      (named.length ? '\n' + named.map((l) => '           ' + l).join('\n')
                    : '\n           * no ✗ assertion named it — the suite died instead. Caught, but blind.'));
  } else { survived++; console.log('SURVIVED ' + m.name.padEnd(58) + ' → NO suite failed. ★ THIS IS THE FINDING.'); }
}
console.log('\n' + (survived ? survived + ' mutation(s) SURVIVED — the suite has no teeth there.'
  : 'every mutation was caught; all files restored byte-identical to their blobs.') +
  (unnamed.length ? '\n⚠ ' + unnamed.length + ' caught only by a CRASH/HANG, with no assertion naming the defect:\n' +
    unnamed.map((n) => '   - ' + n).join('\n') + '\n  Caught is not the same as diagnosed. Add an assertion that names it, or record why not.' : ''));
process.exit(survived ? 1 : 0);
