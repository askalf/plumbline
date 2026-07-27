# Changelog

All notable changes to `@askalf/plumbline` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are cut automatically: bump the `version` in `package.json` on `main`
and add a matching `## [x.y.z]` section below — the release workflow tags it,
publishes to npm over OIDC, and copies this section into the GitHub release
notes.

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
