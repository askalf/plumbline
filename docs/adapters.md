# Adapters — reach the harness you actually run

plumbline reasons about a portable trajectory schema, so an adapter is just a translator from a harness's logs into it. Seven ship today:

| Adapter | Reads | Notes |
|---|---|---|
| `claude-code` (default) | `~/.claude/projects/**/*.jsonl` transcripts | one transcript = one session |
| `openai` | Chat Completions + Responses API tool-call logs | the most widely used agent runtime |
| `anthropic` | raw Messages API `tool_use` loops | for people building directly on the API |
| `langchain` | LangSmith / LangGraph run trees | `run_type: tool` runs become actions |
| `otel` | OpenTelemetry GenAI (`gen_ai.*`) spans | **one adapter, many frameworks** — anything instrumented with OpenInference / OpenLLMetry |
| `forge` | server-side SDK-engine execution dumps | a second, disjoint tool vocabulary |
| `redstamp` | a [redstamp](https://github.com/askalf/redstamp) per-call audit log | hash-chain verified; see below |

The four framework adapters (`openai`, `anthropic`, `langchain`, `otel`) face a problem the first-party ones don't: **their tools are user-defined.** A Claude Code transcript has a fixed vocabulary; an OpenAI agent calls tools named whatever the developer named them. So those adapters **infer** the capability each tool demonstrates from its name and arguments (`run_shell` → `exec:local`, `fetch_url` → `net:egress`, `query_db` → `db:query`, …), falling back to a per-tool `tool:<name>` capability so an unrecognised tool still accretes against a declared envelope rather than vanishing. Getting that inference right is what keeps `staircase` — which reads only `capability_grant` — alive over them.

**The redstamp adapter closes the Own Your Stack loop.** redstamp is the per-call guard; it records a `decision` for every tool call and hash-chains each audit record to the last. plumbline reads that log and catches the escapes the guard *individually allowed*. It is the only source that natively emits denials, so `ratchet` is fully live, and it **verifies the audit hash chain**: an agent that edits its own trail to hide a denial breaks the chain, and plumbline flags it and emits a tamper event.

Writing an adapter for a harness we don't cover is the most useful contribution you can make — see [CONTRIBUTING.md](../CONTRIBUTING.md).
