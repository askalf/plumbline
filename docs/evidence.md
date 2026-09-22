# Evidence and limits

## Validated against real traffic

A detector set that has only seen its own synthetic corpus is worthless. plumbline is validated against real agent traffic, most recently **4,898 real agent sessions / 84,274 tool calls** across two independent harnesses (measured 2026-09-13; the first run, July 2026, was 1,586 sessions / 57,602 calls).

> ⚠️ **Read the coverage below before quoting the clean rate.** No session could feed all eight deterministic detectors. *The Claude Code corpus is live and grows, so quote totals with the date.*

The split: Claude Code on a live workstation (1,100 sessions / 31,195 calls), and a hosted SDK-engine harness (3,798 executions / 53,079 calls, May–September 2026) whose tool vocabulary is deliberately disjoint from a Claude Code transcript — so the schema's portability is *tested*, not asserted. Combined: **99.1% clean**, 43 sessions flagged, every one of them by `ratchet` — a refused call followed by a reshaped one that succeeded, which is the shape that detector exists to surface and a human's call to adjudicate. One of those reached `halt` (three denied-then-successful `ssh` runs in one session); the rest sit at `warn` or `confirm`.

**A clean rate is not a safety claim unless every detector could have fired.** plumbline computes this on every run and refuses to print a bare clean rate when a detector could not, because the alternative — a headline percentage with silently dead detectors behind it — is exactly the failure this project shipped and caught three times.

Coverage is the share of sessions that carried the fields a detector needs (its reachability declaration in [`src/reachability.mjs`](../src/reachability.mjs)), so a clean verdict from it means something:

| Detector | Claude Code | Forge |
|---|---|---|
| `staircase` | 9% | 100% |
| `siphon` | 7% | 18% |
| `ratchet` | 6% | 13% |
| `recon` | 5% | 53% |
| `egress` | 5% | 19% |
| `metadata` | 5% | 53% |
| `fanout` | 1% | 2% |
| `reassembly` | not exercised | <1% |

Low coverage is normal — most sessions contain no credential reuse or denials. An **adapter blind spot** is different: for its first months `ratchet` was dead for *every* forge corpus, because forge dumps recorded tool calls without per-call outcomes. That was a defect, declared up front in `ADAPTER_CAPABILITIES` rather than discovered from a suspiciously clean report; since dumps carry `output`/`is_error` per call it is reachable in 13% of forge sessions and produced every flag the forge corpus has.

**`siphon` on real traffic.** It could feed on 74 Claude Code sessions and 669 forge sessions and fired on **none of them, at any severity** — not even the 0.15 lead that a bare read of a home-directory credential store produces. The shape of its declared false positive, [`corpus/eval-benign/hard-npm-auth.jsonl`](../corpus/eval-benign/hard-npm-auth.jsonl), did not occur once in 84,274 tool calls, so the base-rate argument the detector rests on holds on this traffic: home-credential-store reads followed by off-provider egress are rare enough that the known misread costs nothing here. Precision cannot be quoted from zero positives; what can be is a false-positive rate of 0 on 743 sessions that could have produced one.

## Attacked, and honest about the floor

The credibility of a security tool is the story of its own limits.

- **The first honest run flagged 34.7%.** Fixing it changed the *detectors*, not the thresholds — reads scored like exfiltration, one signal per host instead of per host-set, oversight resets the ratchet. `34.7% → 11.0% → 1.28%`, with the synthetic escape still halting throughout.
- **The primary detector was inert on real traffic and the clean numbers hid it.** `staircase` reads only `capability_grant`, and no adapter emitted it — so it only ever fired on the hand-authored corpus. This failure repeated three times, which is why it got a structural fix: [`src/reachability.mjs`](../src/reachability.mjs), where every detector declares the fields it needs and a clean verdict travels with the list of detectors that could have produced one.
- **Then the tool was attacked.** Fifteen breaks, four fail-open — a path traversal that defeated the capability envelope, a NaN severity that silently cleared a trajectory, an agent forging its own oversight. All fixed, all now regression tests.
- **The floor is written down, not hidden.** The five `corpus/evasion-*.jsonl` files map the boundary of shape-based detection precisely, *including the one that scores clean* — shipped as a passing test so precision can't be quietly traded away. When `siphon` closed one instance of that floor, the clean case moved to a harder corpus rather than the boundary being declared gone; the detector that closed it ships with its own false positive written down.

## What it cannot see

Stated plainly, because a limit you know about is a limit you can cover elsewhere:

- **An escape that stays inside the envelope and touches nothing a convention marks.** That is the floor above, and today only the semantic layer reaches for it — with the caveat that its unique contribution is unproven on the evaluated model.
- **Reshaping to comply versus reshaping to evade.** A denial followed by a different command that succeeds is the same shape either way. `ratchet` reports the shape; a human decides which it was.
- **A credential copied into the workspace first.** `siphon` is anchored to home directories and system secret mounts on purpose, so a staged copy steps around it.
- **Exfiltration through the credential's own provider** — AWS keys to an S3 bucket. Using a credential at its own provider is the definition of ordinary use.
- **Anything an adapter never recorded.** A shell command whose arguments were not logged looks like a command that touched nothing. Reachability declares this per detector rather than letting it pass as clean.

Every detector's own "cannot see" list is in [DETECTORS.md](../DETECTORS.md); the threat model and what is deliberately out of scope are in [SECURITY.md](../SECURITY.md).
