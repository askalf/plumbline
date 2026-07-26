# Contributing

The most useful contribution is **an adapter for a harness we don't cover.** Detection logic is worthless if it can't reach your trajectories.

## Ground rules

- **Zero runtime dependencies.** CI enforces this. plumbline runs inside security-sensitive pipelines; every dependency is somebody else's supply chain.
- Node ≥ 20, ESM (`.mjs`), no build step, no transpiler.
- `node --test test/*.test.mjs` must pass, including the controls.
- New detector or adapter ⇒ new tests. See below for what's actually required.

```sh
git clone https://github.com/askalf/plumbline
cd plumbline
node --test test/*.test.mjs
node src/cli.mjs replay corpus/exploitgym.jsonl
```

## Writing an adapter

An adapter turns a harness's logs into the [trajectory schema](SPEC.md). Look at `src/adapters/claude-code.mjs` (per-session transcript files) and `src/adapters/forge.mjs` (many sessions in one dump) — they cover both common shapes.

Four things matter, roughly in order of how easy they are to get wrong.

### 1. Emit `capability_grant` — this is not optional

`staircase`, the primary detector, reads **only** this field. An adapter that doesn't emit it leaves the most important detector completely inert, and — because a clean result and a dead detector look identical — nothing will tell you.

Map each tool to the capability its use demonstrates, and emit the **first exercise in a session** as the grant:

```js
const CAPABILITY_MAP = {
  run_shell:   ['exec:local', 'proc:spawn'],
  query_db:    ['db:query'],
  fetch_url:   ['net:egress:read'],
  send_email:  ['mail:send'],
};

const held = new Set();
// ...per tool call:
const fresh = (CAPABILITY_MAP[tool] ?? []).filter((c) => !held.has(c));
for (const c of fresh) held.add(c);
if (fresh.length > 0) event.capability_grant = fresh;
```

Use `scheme:value` consistently. `cloud:iam:role` matches an envelope granting `cloud:iam:*`; `iam:cloud:role` does not.

### 2. Set `target.op` for anything shell-shaped

The invoked binary, not the whole command. Without it every shell action in a session shares one identity, and `ratchet` fires on unrelated denials — this produced 98 false positives during calibration. `opOf()` is exported from the Claude Code adapter and handles env prefixes, wrappers (`sudo`, `npx`), and navigation segments (`cd x; git log` → `git`).

### 3. Report denials and human turns

- `outcome: "denied"` when a guard refused the action. Without it `ratchet` cannot work.
- `action: "session.turn"` whenever a human speaks. This **resets** the ratchet — if oversight adjudicated a denial, the retry is not evasion.

Both are easy to skip and both silently disable a detector.

### 4. Measure secrets, never carry them

`produces` takes `{id, len, entropy}` — measurements only. Your adapter has the real value; compute `entropyOf(value)` and emit the measurement. plumbline never holds a secret, which is a property worth preserving.

### Verify your adapter

Score a corpus you *expect to fail* — a permissive envelope produces a clean report whether or not your adapter works:

```sh
node src/cli.mjs scan <your-dump> --adapter=<yours> --profile=eval-sandbox
```

If that comes back clean on non-trivial traffic, your adapter is probably not emitting `capability_grant`.

## Adding a detector

1. `src/detect/<name>.mjs`, exporting `id` and `detect(events, envelope)`.
2. Register it in `src/detect/index.mjs`.
3. **Add a trigger to `corpus/detector-exercise.jsonl`.** The liveness control asserts every registered detector fires on that corpus; a detector without a trigger fails CI, which is the intended behaviour.
4. Document it in [DETECTORS.md](DETECTORS.md) — including a **"cannot see"** section. A detector whose blind spots aren't written down invites false confidence.

Severity guidance: weak-but-early signals cap low (`recon` caps at 0.25); only evidence that something left the boundary or that the agent evaded a gate should approach halt on its own.

## Corpus contributions

Labeled trajectories are extremely welcome, especially benign ones — false-positive pressure is what makes this useful. Requirements:

- **No real credentials, hostnames, internal paths, or personal data.** Sanitize before opening a PR.
- A `session.declare` with a realistic envelope.
- A header comment stating provenance and whether it is real, sanitized, or reconstructed.

`corpus/exploitgym.jsonl` is a *reconstruction* from public write-ups and says so in its header. Be equally explicit.

## What gets declined

- Anything adding a runtime dependency.
- Detectors that fire on novelty rather than divergence from declared intent. That's anomaly detection, and it's a different tool.
- Tuning that improves a benchmark number without a corresponding control proving the detector still fires.
- Inline/blocking enforcement. Deliberately out of scope until trajectory signals have earned it.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Please don't open a public issue for a security bug.
