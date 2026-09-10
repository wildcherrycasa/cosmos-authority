# A caller that is not Cosmos reported a settlement — lab phone, 2026-09-08

**28 assertions, 28 passed, exit 0.** Samsung A15, Android 13 (kernel 5.15.189), Termux: Node 26.3.1,
Python 3.13.13, curl 8.18.0. Commit under test: `2c95dbf` (payload built with `git archive HEAD`, so the
working tree could not leak into it).

---

## Why this run exists

Every one of the 134 assertions in `test/rail.test.js` is Cosmos talking to Cosmos through a client this
repository wrote. That is **one side of a two-sided protocol**, and this project already knows what that
costs: on 2026-09-08 the x402 verifier and the MCP tool schema were both green and both broken against a
real caller — twice in one day, for exactly this reason. `docs/AGENT-TOOLS-2026-09-08.md` states the lesson
in one line: *a client you wrote proves the server speaks the spec as you read it.*

So the caller here is **`curl`** — a program this project did not write, on an OS this code has never been
developed on, speaking only the HTTP the documents describe. It cannot see a JavaScript object, cannot be
handed a stub, and cannot be accidentally passed a field the wire format does not carry.

## ⛳ The centre of the run is the attack, not the happy path

This morning's first rail commit shipped an unbounded double-spend: the settlement capability is returned in
the `/authorize` response, so the **requester** held a credential that could report `failed`, take its own
budget back, and spend the same money again. A happy path proves a feature works. Only the attack proves
the fix does — and it is run here by a real HTTP client rather than by the test that was written alongside
the fix.

```
=== 3 · ATTACK — the requester tries to end its own payment ===========================
  PASS  the ALLOW holder is REFUSED on `failed`
  PASS  and the refusal names class and outcome        (REPORTER_MAY_NOT_FAILED)
  PASS  THE BUDGET DID NOT COME BACK
  PASS  nor may it certify its own payment as settled
  PASS  the rail token WITHOUT x-cosmos-handoff is refused
```

## The whole run was offline, not just the verification

Wi-Fi and mobile data were disabled from the workstation **before the script started** (Termux is not
privileged enough to call `svc`), so the server, `curl` and the verifier all spoke over loopback with no
route off the device. That is a stronger claim than verifying offline at the end: nothing in this run could
have reached anything, at any point.

```
=== is this device actually offline? (the control the rest of the run rests on) ===
  curl https://pypi.org -> exit 6
  PASS  the device has no route off itself, BEFORE anything else runs
...
  PASS  still offline at verification time
```

## What the phone printed, at the point that matters

```
VALID  kid=cosmos-phone-rail-2026-09  key_status=active
  decision=REPORT reason=RAIL_SETTLED
    [pass] Rail report accepted
    [FAIL] Rail outcome observed by Cosmos
  rail report: outcome=settled tx=0xphone_final provider=writ
    reported_by=rail at 1788893983429
    !! rail outcome: NOT OBSERVED - asserted by the reporter and never checked by Cosmos.
      This signature proves a report was made against this authorization by a holder of the
      'rail' credential. It does NOT prove that any money moved.
  parent receipt: auth_9dcfcb35fe410660a4ef
```

The startup line the operator sees, which is the other half of failing closed *visibly*:

```
[cosmos] settlement reports: rail token set — the rail may report settled/failed (with x-cosmos-handoff)
```

## Cross-machine: signed on Android, verified on Windows

`test/fixtures/phone-rail-settled-2026-09-08.json` and its JWKS are **the actual bytes that phone issued**,
committed. Re-verified on the workstation under `PYTHONIOENCODING=ascii` (the pin that reproduces the
Windows cp1252 crash of 2026-09-06 on any OS): **VALID, exit 0.** The Node verifier agrees independently.

The signing key was generated inside that phone process and never written to disk. The receipt stays
verifiable forever against the committed JWKS, and nothing secret was committed.

## ⚠ The first run failed, and the failure was mine and VACUOUS

First pass: **27 passed, 1 failed.** `curl -o /tmp/attack.json` — **Termux has no `/tmp`** (its temp dir is
`$PREFIX/tmp`), so the body was never written and the assertion that reads the error code back could not
compare anything. It did not fail because the code was wrong. **It failed because the file was missing** —
a check that could not match, which is the same defect shape this repo has now hit four separate times
(the vendored gate that went green while vacuous, the PyPI link check against the wrong tarball, the T1
approver assertion that passed while the field did not exist, and this). Fixed to write into the working
directory; second run **28/28**, and the error code `REPORTER_MAY_NOT_FAILED` is now genuinely compared.

Three more things cost real time and belong in the runbook:

- **`adb push` needs `MSYS_NO_PATHCONV=1` on the DESTINATION too**, not only on `adb shell`. Without it the
  push reports `rc=0` and pushes nothing — a silent success, which is worse than an error.
- **Android blocks app UIDs from writing to `/data/local/tmp`**, and `chmod 777` does not change that
  (SELinux, not mode bits). Termux can *read* the staged payload but not write beside it. The working shape
  is: stage in `/data/local/tmp`, copy into Termux's `$HOME`, run there, write output to `/sdcard`.
- **Android also blocks *exec* from `/data/local/tmp`** — `./script.sh` gives `bad interpreter: Permission
  denied`. `bash script.sh` works, because bash reads the file rather than exec'ing it.
- **`input text` mangles spaces.** The first attempt typed a single `h`. Type the words separately and send
  the space as `input keyevent 62`.

## ⛔ What this still does NOT prove

- **`curl` is not a rail.** It proves the wire protocol is usable by a standard client on a foreign OS, and
  it proves the attack is refused in the real world. It does **not** prove that a third party can implement
  the handoff proposal §3 from the document alone. **Nobody outside this repository has
  implemented that spec, and until somebody does, §3 is unvalidated.**
- One device, one Android version, one Termux install.
- The rail token and the operator token were both generated by this script. A real deployment has the
  operator hand the rail token to the rail out of band, and that hand-off has never been exercised.
- Neither package is published, so **no registry install has ever been tested.**
