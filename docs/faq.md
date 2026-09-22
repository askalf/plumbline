# FAQ, the open schema and design properties

## FAQ

**Does it block anything?** No. It is read-only and out of band; it scores trajectories after the fact and hands you evidence. Pair it with a per-call guard for the real-time layer.

**Does anything leave my machine?** No. Scans read local logs and print local output. The optional semantic layer talks to a local ollama at `127.0.0.1:11434`; there is no telemetry and nothing phones home.

**Do I need a model?** No. The eight detectors are deterministic and run with zero dependencies. The semantic layer is opt-in (`--semantic`) and needs a ~7B local model; 3B over-flags.

**Which harnesses?** Claude Code out of the box; OpenAI, Anthropic Messages, LangChain/LangGraph, OpenTelemetry GenAI spans, redstamp audit logs and server-side SDK-engine dumps through adapters. Anything instrumented with OpenInference or OpenLLMetry comes in through `otel`.

**Will it hold my secrets?** It never sees them as values in its own output: adapters emit `{id, len, entropy}` measurements. The HTML report does contain your paths, hosts and task text, and says so when written.

**What is a good clean rate?** One printed next to its coverage. plumbline refuses to print a bare one.

## Why an open schema

There is no portable trajectory format for agent security. Every harness invents its own log shape, so detection logic can't move between them. plumbline publishes the schema ([`schema/trajectory.schema.json`](../schema/trajectory.schema.json)), a reference detector set, and a labeled corpus so results are comparable across implementations. **Adopt the schema even if you never run this code.**

## Security & design properties

- **plumbline never holds a secret.** Adapters see real values and emit only measurements — `{id, len, entropy}` — which is what lets it reason about credential movement without becoming a place credentials accumulate.
- **Read-only and out-of-band.** It scores trajectories after the fact; it does not sit in the tool-call path and cannot block an action. Treat its output as evidence for a human or an enforcement layer, never as an enforcement decision.
- **Zero runtime dependencies**, enforced in CI. It runs inside security-sensitive pipelines; every dependency would be someone else's supply chain inside yours.
- **Every release is attested.** Published over OIDC with SLSA provenance; actions are SHA-pinned; CodeQL, OpenSSF Scorecard and ClusterFuzzLite run on the repo.

Threat model, and what is deliberately out of scope: [SECURITY.md](../SECURITY.md).
