# Security Policy

## Reporting a vulnerability

Report privately via [GitHub Security Advisories](https://github.com/askalf/plumbline/security/advisories/new). Please don't open a public issue for a security bug.

Expect an acknowledgement within 72 hours and an assessment within seven days.

## Supported versions

Pre-1.0: only the latest minor release receives fixes.

## Design properties worth knowing

**plumbline never holds a secret.** The `produces` field carries measurements — `{id, len, entropy}` — not values. Adapters see real data and emit only the measurement, which is what allows reasoning about credential movement without the monitor becoming a place credentials accumulate. Preserve this if you write an adapter.

**Zero runtime dependencies**, enforced in CI. This tool is meant to run inside security-sensitive pipelines; every dependency would be somebody else's supply chain inside yours.

**plumbline is read-only and out-of-band.** It scores trajectories after the fact. It does not sit in the tool-call path, cannot block an action, and has no network egress of its own. Treat its output as evidence for a human or an enforcement layer, never as an enforcement decision.

## Threat model

**In scope:** an autonomous agent whose action sequence departs from its declared intent — accumulating capability, exfiltrating fragmented credentials, rotating command-and-control, or reshaping a blocked action until it passes.

**Out of scope:**

- **A hostile envelope.** Whoever writes the `session.declare` defines what counts as drift. A too-generous envelope silently disables everything downstream — this is the primary failure mode, documented in [DETECTORS.md](DETECTORS.md), and the reason the shipped controls assert every profile still constrains something.
- **A hostile adapter.** An adapter that omits `capability_grant`, `outcome: "denied"`, or `session.turn` disables the corresponding detectors, and the resulting clean report is indistinguishable from a genuinely clean one.
- **Log integrity.** plumbline reasons about what it is told. If the trajectory source can be forged or truncated by the thing being monitored, the analysis inherits that weakness. Collect trajectories somewhere the agent cannot write.
- **In-process activity.** Anything not surfaced as a tool call — computation, reasoning, data transformation inside a single action — is invisible by construction.
- **Comply-versus-evade.** `ratchet` cannot distinguish an agent reshaping a blocked command to satisfy policy from one reshaping it to defeat policy. Both are reported; the distinction requires semantics the deterministic detectors don't have.

## Reporting a false negative

A trajectory that should have been flagged and wasn't is a security bug, not a feature request. Please include a sanitized trajectory reproducing it — those become corpus entries, which is how the detectors improve.
