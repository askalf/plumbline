# Verifying the verifier

A test that cannot fail is worse than no test, because it reports success. This project has now produced that bug twice, in two different forms, and both were found by mutation rather than by reading the code.

Run this procedure whenever you touch a detector, the registry, or the controls.

## The two failures, for context

**1. A detector starved of input.** `staircase` reads only `capability_grant`. Neither adapter emitted it, so the primary detector was completely inert on real traffic while every corpus reported clean. Caught by scoring a corpus against an envelope that *should* have failed.

**2. A circular liveness guard.** The control written to prevent (1) compared the fired detectors against `DETECTOR_IDS` — derived from the same registry it was checking. Unregistering a detector removed it from both sides of the comparison, so the guard passed while the detector was gone. Caught by mutation.

The fix for (2) is an `EXPECTED_DETECTORS` literal in `test/control.test.mjs` that is deliberately **not** derived from the registry, plus a second assertion that the registry matches it exactly. Adding a detector therefore requires updating three places: the registry, that list, and `corpus/detector-exercise.jsonl`. The friction is intentional.

## Rule zero: verify the mutation applied

A mutation that silently fails to apply produces a passing test and looks like proof. This happened here — a `sed` pattern ending in `]$` never matched a line ending in `];`, so the "mutation" was a no-op and the guard appeared dead when it was merely untested.

Never mutate with a pattern you have not confirmed changed the file:

```js
const before = fs.readFileSync(f, 'utf8');
const after = before.replace(TARGET, REPLACEMENT);
if (before === after) { console.log('MUTATION DID NOT APPLY - aborting'); process.exit(3); }
fs.writeFileSync(f, after, 'utf8');
```

## The procedure

Work on a scratch copy or restore from a backup afterwards; each mutation must leave `git status` clean when finished.

### Gate 1 — the escape must halt

Cross the corpora. The gate has to distinguish them, not merely pass on one.

| Corpus | Expected |
|---|---|
| `corpus/exploitgym.jsonl` | gate passes |
| `corpus/benign-repo-triage.jsonl` | gate **fails** |

If the benign corpus also passes, the gate is not discriminating.

### Gate 2 — the benign trajectory must stay clean

The same test inverted.

| Corpus | Expected |
|---|---|
| `corpus/benign-repo-triage.jsonl` | gate passes |
| `corpus/exploitgym.jsonl` | gate **fails** |

### Gate 3 — every detector must fire

Two distinct mutations, because they fail differently:

**A. Unregister a detector** — remove one entry from `DETECTORS` in `src/detect/index.mjs`. `test/control.test.mjs` must fail on the registry-mismatch assertion. This catches a detector silently dropped.

**B. Starve a detector** — leave it registered but make its input unreachable (e.g. iterate an empty array in place of `event.capability_grant`). The control must fail on the inert-detector assertion. This catches the original bug: present, registered, and doing nothing.

A guard that catches only B is circular. A guard that catches only A cannot see a detector that has quietly stopped working.

### Gate 4 — profiles constrain something

Replace a shipped profile's `capabilities` with `["*"]`. `CONTROL: every shipped profile actually constrains something` must fail. A profile that grants everything is indistinguishable from no monitoring.

## Reproducing the published numbers

Claims in the README come from a **clean checkout**, not a working tree:

```sh
git clone https://github.com/askalf/plumbline /tmp/pl && cd /tmp/pl
node --test test/*.test.mjs
node src/cli.mjs scan ~/.claude/projects --profile=dev-workstation
node src/cli.mjs scan <forge-dump> --adapter=forge --profile=fleet-agent
node src/cli.mjs scan <forge-dump> --adapter=forge --profile=eval-sandbox   # the control
```

The last line is not optional. A clean result on its own is not evidence — it is only evidence next to a run you expected to fail.

> ⚠️ The Claude Code corpus is **live**: it grows as you work, so session counts drift upward between runs (703 → 704 within a single afternoon). Quote the count alongside the date it was measured, and never treat a changed total as a regression on its own.
