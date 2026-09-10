// Guards the one number that killed Writ: uncontrolled growth.
// Writ reached 369 modules / ~39,000 lines with zero customers. Cosmos states a ceiling and fails the
// build when it is crossed, so growth is a decision someone makes on purpose rather than a drift.
const fs = require('fs'), path = require('path');
const CEILING_FILES = 25, CEILING_LINES = 3000;
// x402/ is counted for the same reason DESIGN flagged a hypothetical verify/: this script is
// non-recursive and reads a fixed list, so a NEW TOP-LEVEL DIRECTORY is invisible to the ceiling. Adding
// one without adding it here is how the guard against Writ's 369 modules gets quietly defeated.
// ⛳ `examples/` IS DELIBERATELY NOT COUNTED, and this comment exists so that is a decision rather than
// the loophole above. The reviewer's ruling on 2026-09-09, adopted: at 2998/3000 the core is FINISHED,
// and new capability belongs in a second package. examples/reference-rail is not product — it is the
// other side of the handoff, written so an integrator copies a file instead of interpreting prose, and
// it ships to nobody as a dependency. If something in examples/ ever becomes load-bearing for the
// product, it moves into a root below and starts counting that day.
const roots = ['core', 'api', 'mcp', 'x402'];
let files = 0, lines = 0;
for (const r of roots) {
  if (!fs.existsSync(r)) continue;
  for (const f of fs.readdirSync(r)) {
    if (!f.endsWith('.js')) continue;
    files++;
    lines += fs.readFileSync(path.join(r, f), 'utf8').split(/\r?\n/).length;
  }
}
console.log('product modules: ' + files + '/' + CEILING_FILES + '   lines: ' + lines + '/' + CEILING_LINES);
if (files > CEILING_FILES || lines > CEILING_LINES) {
  console.error('CEILING EXCEEDED — raise it deliberately in scripts/size.js, or delete something.');
  process.exit(1);
}
console.log('within ceiling');
