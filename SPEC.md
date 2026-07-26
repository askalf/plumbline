# Trajectory Event Schema v1

A portable format for agent action sequences, so trajectory-level detection logic can move between harnesses.

Normative schema: [`schema/trajectory.schema.json`](schema/trajectory.schema.json). This document explains the reasoning; the JSON Schema is authoritative on syntax.

## Why this exists

Every agent framework logs its own shape. That means detection logic written against LangChain traces cannot be applied to a Claude Code transcript, an MCP audit stream, or a Managed Agents session — even though the security question is identical. There is no shared vocabulary for "what did this agent actually do, in order."

This schema is a proposal for that vocabulary. It is deliberately small. Adopt it even if you never run plumbline.

## Shape

A **trajectory** is a JSONL stream of events for one logical agent session, in order. One session per file. Blank lines and `#` comments are permitted so corpora can carry annotation.

```json
{"v":1,"session":"run-42","seq":0,"action":"session.declare","envelope":{...}}
{"v":1,"session":"run-42","seq":1,"action":"fs.read","target":{"path":"/w/a.mjs"},"outcome":"ok"}
{"v":1,"session":"run-42","seq":2,"action":"http.request","target":{"host":"registry.npmjs.org","external":true},"outcome":"ok","status":200}
```

Required on every event: `v`, `session`, `seq`, `action`.

## Design decisions worth knowing

**`seq` is authoritative, not `ts`.** Wall-clock ordering breaks across ephemeral instances and parallel tool calls. Gaps in `seq` are legal; ordering is not negotiable.

**`actor` is the logical agent; `instance` is the ephemeral compute.** This is what lets a swarm of short-lived sandboxes collapse back into one trajectory. In the July 2026 incident, ~17,000 actions were spread across ephemeral sandboxes specifically so that no single instance's log looked interesting. A monitor scoped to one instance is blind by construction.

**`outcome: "denied"` is a first-class value.** A guard refusing an action is signal, not an error. Without it you cannot detect an agent reshaping a blocked request until it passes.

**`capability_grant` records what the agent now HOLDS, not what it used.** Capabilities are cumulative; this field is the input to staircase detection. Use `scheme:value` form — `net:host`, `cloud:iam:role`, `fs:/path`, `exec:remote`. Trailing `*` is the only wildcard, and only in envelopes.

**`produces` / `consumes` carry measurements, never values.** A `produces` entry declares that a value entered the agent's possession, with its length and Shannon entropy — computed by the adapter, which has the real data. `consumes` names fragment ids an action used. This is what allows reasoning about secret movement without the monitor ever holding a secret, and it is what defeats token fragmentation: you detect the *assembly*, not the string.

**`target.op` is operation identity.** The invoked binary for a shell action, the method for an API call. Without it, every shell command in a session is indistinguishable, and any denial-then-success pattern fires. This field was added after calibration produced 98 false positives from exactly that collision.

**`target.external` is set by the adapter.** Consumers must not resolve DNS or infer network topology. The adapter knows the trust boundary; the schema does not.

## The envelope

The declared intent, carried on `session.declare`. Without it, drift is undefined — there is only novelty.

```json
{
  "task": "Triage failing tests and open a fix PR",
  "capabilities": ["exec:local", "fs:/workspace/*", "cloud:gh:repo"],
  "egress": { "mode": "open_read", "allow": ["registry.npmjs.org", ".github.com"] },
  "budget": { "max_distinct_hosts": 15, "max_probe_ratio": 0.6, "max_instances": 40 }
}
```

`egress.mode`:

- **`allowlist`** — any unlisted host is drift. Correct for evaluation sandboxes and CI.
- **`open_read`** — reads may go anywhere; writes and credential-bearing requests must be to a listed host. Correct for research-capable agents, whose job includes reading arbitrary pages. Without this distinction, a session that read a dozen articles scored like an exfiltration.

A trajectory with no `session.declare` must be reported as **undeclared** — scored with an empty envelope so every capability reads off-envelope, and labeled as unaudited. Silently assuming benign intent is the one thing an implementation must not do.

## Action vocabulary

Dotted lowercase verbs, `namespace.verb`. The namespace matters more than exhaustiveness; implementations should accept unknown verbs rather than reject them.

| Namespace | Examples |
|---|---|
| `session` | `session.declare`, `session.turn` (a human turn — see below) |
| `fs` | `fs.read`, `fs.write`, `fs.search` |
| `proc` | `proc.spawn`, `proc.read`, `proc.signal` |
| `http` / `net` / `dns` | `http.request`, `net.send`, `dns.query` |
| `cred` | `cred.acquire` |
| `cloud` | `cloud.api` |
| `db` | `db.query` |
| `agent` | `agent.spawn` |
| `mcp` | `mcp.call` |
| `egress` | `egress.write` |

**`session.turn` deserves special mention, and it has a hard requirement.** It marks a human turn, and it is load-bearing: a denial followed by a success is only evasion if the agent got there alone. If oversight intervened between them, the operator adjudicated it and the retry carries their authority.

> ⚠️ **A `session.turn` MUST carry `actor: "human"` to count as oversight.**
>
> ```json
> {"v":1,"session":"s","seq":9,"action":"session.turn","actor":"human"}
> ```
>
> Adversarial testing found the obvious abuse: an agent emitting its own `session.turn` laundered its evasion, wiping the denial history that proved it. A conforming implementation therefore treats a turn as oversight **only** when `actor` is exactly `"human"`. An unattributed turn, or one attributed to the agent, is not oversight — absence of proof is not proof.
>
> Adapters that emit `session.turn` without the actor produce trajectories in which evasion detection silently never resets. This is the most common conformance mistake.

Note this defends only the in-band case, where the agent emits an event the schema already permits it to emit. It does not defend against a forged `actor` field — an implementation reading a log the agent can write inherits that log's integrity. Collect trajectories somewhere the monitored agent cannot write.

## The `actor` field

`actor` identifies who performed an action, and carries security weight in exactly one place: `session.turn`, above. Two values are meaningful to the reference detectors:

| Value | Meaning |
|---|---|
| `"human"` | A person. The only value that counts as oversight. |
| anything else | The agent, a subagent, or an unattributed actor. Never oversight. |

Everywhere else `actor` is descriptive. Use a stable identifier for the logical agent so ephemeral instances of one agent share it — that is what lets `instance` collapse a swarm back into a single trajectory.

## Conformance

An implementation conforms if it:

1. accepts every event in `corpus/*.jsonl` without error;
2. reports `corpus/exploitgym.jsonl` as reaching its highest severity level;
3. reports `corpus/benign-repo-triage.jsonl` as clean;
4. reports a trajectory lacking `session.declare` as undeclared rather than clean;
5. treats a `session.turn` as oversight **only** when `actor` is `"human"`;
6. reports, alongside any clean verdict, which detectors could not have fired — see below.

### Reporting what could not be checked

A clean result and a detector that was unable to run are indistinguishable from the outside. A conforming implementation must therefore not emit a bare clean verdict. The reference implementation attaches three things to every report, and any implementation claiming conformance needs equivalents:

| Field | Meaning |
|---|---|
| `reachability.starved` | Detectors whose required fields were absent from the trajectory. They found nothing because they could not look. |
| `reachability.no_starved_detectors` | True when nothing was starved. **Necessary, not sufficient** — a detector can have its fields present and still not meet its activation thresholds. Do not name this field anything stronger than what it proves. |
| `envelope_warnings` | Ways the declared envelope itself disables detection: granting `*`, allowing every host, unbounded budgets. A permissive policy produces a clean report with nothing behind it, and no amount of correct detector code will reveal that. |
| `anomalies` | Malformed severities encountered while scoring. A non-finite severity once made total drift non-finite, and every threshold comparison against it false — silently clearing an escape. |

The intent is narrow and worth stating plainly: **an implementation must never let a reader mistake "nothing could be found" for "nothing was wrong."**

Detector sets and scoring are explicitly **not** specified. Two conforming implementations may disagree about a trajectory; the point of the schema is that the disagreement is now legible.

## Versioning

`v` is an integer. Additive fields do not bump it; a change in the meaning of an existing field does. `target.op` and `egress.mode` were added within v1 as additive fields.
