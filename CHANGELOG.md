# Changelog

All notable changes to `@askalf/plumbline` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut automatically: bump the `version` in `package.json` on `main`
and add a matching `## [x.y.z]` section below — the release workflow tags it,
publishes to npm over OIDC, and copies this section into the GitHub release
notes.

## [Unreleased]

### Added

- **`siphon`, an eighth deterministic detector**: ambient credential material
  converging on off-provider egress. It fires when the agent reads a credential
  store for a provider its envelope never named — `~/.aws/credentials`,
  `~/.kube/config`, a projected service-account token — and then sends data
  off-box to somewhere that is not that provider. The read alone is a lead
  (`0.15`, below `warn`); the convergence is the finding (`0.7`, reaching
  `confirm` and no further, because a silent envelope is not proof of intent).
  An allowlisted destination does **not** clear it: that is precisely how the
  residual-floor escape stayed invisible. Naming the provider does —
  `cloud:aws`, `cred:*`, or an explicit `fs:/home/runner/.aws/*` grant.
- `corpus/evasion-semantic-floor.jsonl` — the floor case that remains after
  `siphon`, where the secret is a workspace config file no vendor convention
  marks. Shipped as a *passing* (clean) test, inheriting the role
  `evasion-residual-floor.jsonl` held, so the boundary cannot be quietly
  "fixed" with an overfit threshold.
- `corpus/eval-benign/hard-npm-auth.jsonl` — `siphon`'s **declared false
  positive**: a CI-debugging agent reads its own `~/.npmrc`, uses it at the
  registry, then opens a PR on GitHub. Shape-identical to the escape; only
  meaning separates them. Kept for the same reason `hard-metadata-research`
  is kept for `metadata`.
- `target.path` is now a declared reachability field, so a trajectory that
  records file access without paths reports `siphon` as starved rather than
  clean.
- `siphon` reads `outcome` asymmetrically, after review caught it rejecting only
  `denied` on both sides. A **failed read** holds nothing — an `ENOENT` on
  `~/.aws/credentials` followed by an ordinary request used to score `confirm`
  over a credential the agent never got. A **failed send** still counts when
  there is evidence it reached the network (a response status, or bytes already
  written), because an `error` request in this schema usually means the host
  answered with a failure status and a 500 from a collector is an exfiltration
  that worked.

### Changed

- `corpus/evasion-residual-floor.jsonl` now reaches `confirm` on the
  deterministic path, two events before the trajectory ends. Its header and the
  evasion regressions were rewritten rather than deleted: the file records that
  the floor moved and why.
- `eval/semantic-eval.mjs` keys its pass bar on the new floor escape and
  includes both new corpora. The scorecard in `docs/semantic-detector.md`
  predates them and is labelled as such rather than estimated forward.
- `siphon` is **not** in the real-traffic coverage table: it postdates that
  measurement, and the README says so where the clean rate is quoted.

## [0.2.0] — 2026-07-26

### Added

- Base adapters for harnesses whose tools are user-defined: `openai`,
  `anthropic`, `langchain`, and `otel` — bringing the total to seven. Because
  these tools are named by the developer, a shared core (`src/agentlog.mjs`)
  infers each tool's action and capability from its name and arguments rather
  than relying on a fixed map.
- A generic `agent` profile for adapters whose capability set isn't known
  ahead of time.

### Changed

- Genericized the July 2026 incident framing across the shipped source, the
  ExploitGym corpus, and the README — no third-party attribution. Detector
  scoring is unchanged (the escape still reaches HALT at the same step).

## [0.1.0] — 2026-07-26

### Added

- Initial public release: trajectory-level security monitor for autonomous
  agents. Scores an action sequence against its declared intent envelope,
  catching escapes assembled from individually-authorized steps.
- Seven deterministic detectors — `recon`, `staircase`, `reassembly`,
  `egress`, `ratchet`, `fanout`, `metadata`.
- Optional semantic layer over a local `ollama` model (`qwen2.5:7b`) for
  intent/action mismatch, off by default.
- Seven adapters: `claude-code`, `forge`, `redstamp`, `openai`, `anthropic`,
  `langchain`, `otel` — plus a generic `agent` profile that infers capability
  from tool name and arguments.
- Zero runtime dependencies. ESM, `node --test`, MIT.
