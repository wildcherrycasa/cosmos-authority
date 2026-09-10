// `npm run audit:repo` — the ways this repo was nearly hurt on 2026-09-06, as standing checks WITH TEETH.
//
//   A. CONTROL. A temp repo with a deliberately broken .gitignore (a pattern line carrying a trailing `#`)
//      that the detectors MUST flag, and a fixed one they MUST pass. If the control ever stops going red,
//      the audit is broken and you find out from the control rather than from a leak. (QuickPay: "a test
//      that has never failed is a green light with no demonstrated ability to turn red.")
//   B. SYNTAX. .gitignore lines with a mid-line `#` — gitignore has no trailing comments; the `#` and
//      everything after it is part of the pattern, which then matches nothing.
//   C. BEHAVIOUR. `git check-ignore -q <path>` on a table of representative paths with EXPECTED verdicts,
//      read from the EXIT CODE (0 ignored, 1 allowed) — never from -v output, which also prints matching
//      NEGATION rules. This tests what git does, not what the file appears to say, so it catches breakage
//      modes nobody has thought of yet (wrong slash, missing leading /, negation order, trailing space).
//   D. TRACKED AT HEAD: bundles, env files, keys, the event log — must never be.
//   E. ACROSS ALL REFS: the same patterns in history. "Clean now" and "never leaked" are different claims;
//      only the second matters once a repo is pushed. Informational — leave-or-purge is the founder's.
// Exits non-zero on A, B, C or D. E is reported, not failed.
'use strict';
const { execSync, spawnSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');

const root = path.join(__dirname, '..');
const sh = (c, cwd) => execSync(c, { cwd: cwd || root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
// exit code of `git check-ignore -q`: 0 = ignored, 1 = not ignored, other = error
const ignored = (p, cwd) => { const r = spawnSync('git', ['check-ignore', '-q', '--', p], { cwd: cwd || root }); if (r.status !== 0 && r.status !== 1) throw new Error('check-ignore failed for ' + p + ': ' + r.stderr); return r.status === 0; };
const midlineHash = (text) => text.split(/\r?\n/).map((l, i) => ({ l, n: i + 1 })).filter(({ l }) => { const t = l.trim(); return t && !t.startsWith('#') && /\S\s*#/.test(t); });

// Batched verdicts: `git check-ignore -v -n -z --stdin`, NUL-separated quadruples <source> <line> <pattern>
// <pathname>. -z is the only unambiguous form. Without it a pathname with a space, a tab or a non-ASCII
// byte comes back C-quoted ("caf\303\251.bundle") and never matches the name we asked about, and a source
// path containing ':' (a Windows core.excludesFile, C:/…) shifts a colon-split so a NEGATION rule reads as
// a positive match — i.e. ALLOWED reported as IGNORED. (QuickPay's adversarial cases, 2026-09-06; the
// control below feeds every one of them through the real git.) -n prints an empty source/line/pattern for
// a path that matches nothing; -v prints negation rules too, so "matched" != "ignored".
function parseCheckIgnoreZ(stdout) {
  const f = stdout.split('\0'); if (f[f.length - 1] === '') f.pop();
  if (f.length % 4 !== 0) throw new Error('check-ignore -z: ' + f.length + ' fields is not a multiple of 4');
  const verdict = new Map();
  for (let i = 0; i < f.length; i += 4) verdict.set(f[i + 3], f[i] !== '' && !f[i + 2].startsWith('!'));
  return verdict;
}
function verdicts(paths, cwd) {
  const r = spawnSync('git', ['check-ignore', '-v', '-n', '-z', '--stdin'], { cwd: cwd || root, input: paths.join('\0') + '\0', encoding: 'utf8' });
  if (r.status !== 0 && r.status !== 1) throw new Error('check-ignore failed: ' + r.stderr);
  return parseCheckIgnoreZ(r.stdout || '');
}

const NEVER = /(\.bundle$|(^|\/)\.env(\.|$)|\.pem$|\.key$|\.p12$|\.pfx$|keypair|secret|credential|\.jsonl$)/i;
const fail = [], info = [];

// ── A. control — the detectors must be able to go red ──────────────────────────────────────────────────
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cosmos-audit-control-'));
  try {
    sh('git init -q', tmp);
    fs.writeFileSync(path.join(tmp, 'a.bundle'), 'x');
    fs.writeFileSync(path.join(tmp, '.gitignore'), '*.bundle       # a trailing comment\n');
    const brokenSyntax = midlineHash(fs.readFileSync(path.join(tmp, '.gitignore'), 'utf8')).length === 1;
    const brokenBehaviour = ignored('a.bundle', tmp) === false;          // the broken rule must NOT ignore it
    fs.writeFileSync(path.join(tmp, '.gitignore'), '# a comment on its own line\n*.bundle\n');
    const fixedSyntax = midlineHash(fs.readFileSync(path.join(tmp, '.gitignore'), 'utf8')).length === 0;
    const fixedBehaviour = ignored('a.bundle', tmp) === true;             // the fixed rule MUST ignore it
    if (!(brokenSyntax && brokenBehaviour && fixedSyntax && fixedBehaviour)) {
      fail.push('CONTROL FAILED — the audit cannot tell a broken .gitignore from a working one: ' +
        JSON.stringify({ brokenSyntax, brokenBehaviour, fixedSyntax, fixedBehaviour }));
    }
    // Adversarial pathnames through the BATCHED path, judged by the real git. A pathname need not exist to
    // be judged, so the tab case is testable on NTFS.
    fs.writeFileSync(path.join(tmp, '.gitignore'), '# comment\n*.bundle\n!keep.bundle\ndata/\n');
    // NOTE: a colon in the PATHNAME is not testable here — Windows git reads `x:y` as a drive spec and
    // refuses the whole batch ("is outside repository"). The colon that actually broke the old parser was in
    // the SOURCE path (a global excludesFile at C:/…), and that is covered by the pure-parser control below.
    const ADV = [
      ['café.bundle', true],           // non-ASCII: C-quoted without -z → no verdict would come back
      ['a b.bundle', true],            // a space
      ['tab\there.bundle', true],      // a tab: quoted as \t without -z
      ['keep.bundle', false],          // NEGATION: -v prints the matching rule, and it means ALLOWED
      ['data/x', true], ['data', false],   // `data/` matches the directory's contents, not a file named data
      ['README.md', false],
    ];
    let advBad;
    try {
      const v = verdicts(ADV.map(([p]) => p), tmp);
      advBad = ADV.filter(([p, want]) => v.get(p) !== want).map(([p, want]) => JSON.stringify(p) + ' → ' + v.get(p) + ', want ' + want);
    } catch (e) { advBad = ['threw: ' + e.message]; }
    if (advBad.length) fail.push('CONTROL FAILED — batched check-ignore misjudges: ' + advBad.join('; '));
    // And the parser alone against the shape that broke the colon-split: a Windows source path + a negation.
    const pv = parseCheckIgnoreZ('C:/Users/x/.gitignore_global\x003\x00!keep.bundle\x00keep.bundle\x00\x00\x00\x00free.txt\x00.gitignore\x002\x00*.bundle\x00a.bundle\x00');
    if (!(pv.get('keep.bundle') === false && pv.get('free.txt') === false && pv.get('a.bundle') === true && pv.size === 3)) {
      fail.push('CONTROL FAILED — the -z parser misreads a negation under a colon-bearing source: ' + JSON.stringify([...pv]));
    }
  } finally { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {} }
}

// ── B. syntax ──────────────────────────────────────────────────────────────────────────────────────────
const igPath = path.join(root, '.gitignore');
const igText = fs.existsSync(igPath) ? fs.readFileSync(igPath, 'utf8') : '';
for (const { l, n } of midlineHash(igText)) fail.push('.gitignore:' + n + ' mid-line "#" is part of the pattern: ' + JSON.stringify(l));

// ── C. behaviour — what git actually does with representative paths ────────────────────────────────────
const EXPECT = [
  ['cosmos-20260906-0026.bundle', true], ['anything.bundle', true], ['data/cosmos.jsonl', true], ['data/x.txt', true],
  ['.env', true], ['.env.production', true], ['keys/receipt.pem', true], ['secrets/k', true], ['secrets.json', true], ['node_modules/x/index.js', true],
  // .env.example MUST be allowed — a template that cannot commit makes a fresh clone un-setup-able (Writ, 2026-09-06; caught here by Klutch)
  ['.env.example', false],
  ['README.md', false], ['core/guardrails.js', false], ['docs/DESIGN.md', false], ['verifier/cosmos_verify.py', false], ['server.json', false],
];
// One batched call (each check-ignore costs ~2.4 s on this box), in -z form — see parseCheckIgnoreZ.
{
  let verdict = new Map();
  try { verdict = verdicts(EXPECT.map(([p]) => p), root); } catch (e) { fail.push('BEHAVIOUR: ' + e.message); }
  for (const [p, want] of EXPECT) {
    const got = verdict.get(p);
    if (got === undefined) fail.push('BEHAVIOUR: no verdict returned for ' + p);
    else if (got !== want) fail.push('BEHAVIOUR: ' + p + ' is ' + (got ? 'IGNORED' : 'ALLOWED') + ', expected ' + (want ? 'IGNORED' : 'ALLOWED'));
  }
}

// ── D. tracked at HEAD ─────────────────────────────────────────────────────────────────────────────────
const tracked = sh('git ls-files').split('\n').filter(Boolean);
for (const f of tracked) if (NEVER.test(f)) fail.push('TRACKED at HEAD: ' + f);

// ── E. across all refs ─────────────────────────────────────────────────────────────────────────────────
const ever = new Set(sh('git rev-list --objects --all').split('\n').map((l) => l.split(' ').slice(1).join(' ')).filter(Boolean));
for (const f of ever) if (NEVER.test(f) && !tracked.includes(f)) info.push('IN HISTORY (not at HEAD): ' + f + ' — leave or purge is the founder\'s call');

console.log('control: ' + (fail.some((f) => f.startsWith('CONTROL')) ? 'FAILED' : 'red on broken, green on fixed') +
  '   gitignore lines: ' + igText.split(/\r?\n/).length + '   behaviour table: ' + EXPECT.length + ' paths   tracked: ' + tracked.length + '   ever: ' + ever.size);
for (const i of info) console.log('  info: ' + i);
if (!fail.length) { console.log('OK — control works, no ignore defects, every representative path behaves as expected, nothing sensitive tracked.'); process.exit(0); }
console.log('\n' + fail.length + ' FAILURE(S):'); for (const f of fail) console.log('  - ' + f);
process.exit(1);
