// `npm run backup` — bundle the full history INTO THIS FOLDER (founder's instruction 2026-09-06: here, not
// OneDrive), then prove two things `git bundle verify` does NOT prove:
//   1. the bundle's tip IS the current HEAD — a stale bundle verifies "okay" because it is complete up to a
//      tip that is no longer yours. A backup that verifies is not a backup that is current.
//   2. it RESTORES — clone it into a temp dir and compare HEADs. Existence is not restorability.
// Exits non-zero if either fails. Bundles are gitignored (*.bundle) so they never get committed into the
// repo they back up.
'use strict';
const { execSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');

const root = path.join(__dirname, '..');
const sh = (cmd, opts) => execSync(cmd, Object.assign({ cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }, opts || {})).trim();

const dirty = sh('git status --porcelain');
if (dirty) console.warn('WARNING: working tree has uncommitted changes — they are NOT in this bundle:\n' + dirty + '\n');

const head = sh('git rev-parse HEAD');
const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').replace('T', '-');
const file = path.join(root, 'cosmos-' + stamp + '.bundle');
sh('git bundle create "' + file + '" --all');

// 1. currency
const tip = sh('git bundle list-heads "' + file + '" refs/heads/master').split(/\s+/)[0];
const current = tip === head;

// 2. restorability
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cosmos-restore-'));
let restored = null;
try { sh('git clone -q "' + file + '" "' + tmp + '"'); restored = sh('git rev-parse HEAD', { cwd: tmp }); }
catch (e) { restored = 'CLONE FAILED: ' + (e.stderr || e.message); }
try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}

console.log('bundle:   ' + file + '  (' + Math.round(fs.statSync(file).size / 1024) + ' KB)');
console.log('HEAD:     ' + head.slice(0, 7));
console.log('tip:      ' + tip.slice(0, 7) + (current ? '  == HEAD  (current)' : '  != HEAD  (STALE)'));
console.log('restores: ' + (restored === head ? 'yes — clone HEAD matches' : 'NO — ' + restored));
const ok = current && restored === head;
console.log(ok ? '\nOK — current and restorable.' : '\nFAILED — do not trust this bundle.');
process.exit(ok ? 0 : 1);
