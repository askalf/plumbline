# Ways to run it

**As a hook, so nobody has to remember.** A monitor you have to remember to run is a monitor you ran once. `plumbline hook` is the command a harness hook invokes: it reads the hook payload on stdin, scores the transcript it names, and prints **one line** — only when drift crosses a level worth interrupting for.

```bash
plumbline install-hook                  # wires it into ~/.claude/settings.json
plumbline install-hook --print          # or just show the JSON and change nothing
```

Silence is the normal case and the point. When something does cross:

```
plumbline: confirm at drift 0.74 - siphon: ambient credential -> off-provider egress - gist.github.com (aws) [seq 6]
```

Three properties, because a monitor that damages the session it watches gets uninstalled the same day — all three are regression tests: it **never blocks** (exit status is always 0; a non-zero exit from a `Stop` hook is a message back into the agent's loop), it **never hangs** (a watchdog bounds any stall — found the hard way on a sandboxed filesystem where `mkdir` blocked forever), and it **writes to stderr** (hook stdout is the harness's channel; a verdict printed there is fed back into the model's own context). `install-hook` appends rather than replaces, is idempotent, keeps a backup, and refuses to touch a settings file it cannot parse. Add `--report-dir=DIR` to drop a full report for each flagged session.

**As a report a reviewer can open anywhere.** `--report` writes the same assessment as one self-contained HTML file — no CDN, no fonts, no scripts, nothing that fetches anything — so it survives being emailed, attached to a ticket, or read on a box with no network.

```bash
plumbline scan ~/.claude/projects --profile=dev-workstation --report=agents.html
plumbline replay corpus/evasion-residual-floor.jsonl --report=escape.html
```

It carries two things a screenshot of a terminal does not. **The reachability caveat rides on the artifact**, in the same type size as the verdict — an exported "100% clean" that leaves behind the list of detectors that could not fire is worse than no export, because it looks authoritative. And **trajectory text is escaped, never interpolated**: paths, hosts and task strings are written by the monitored agent, and a renderer that trusted them would hand that agent a script tag in its reviewer's browser. Both are regression tests, not intentions. The file contains your own hosts, paths and task text; plumbline says so when it writes one — read it before you share it.

**In CI.** `plumbline scan ... --exit-code` returns 1 on `confirm` or `halt`.

**As a library.**

```js
import { assessTrajectory } from '@askalf/plumbline';

const report = assessTrajectory(jsonlText);
if (report.level === 'halt') console.error(`drift ${report.drift}`, report.timeline.at(-1).signals);
```

## Any other harness is one flag away

```bash
plumbline scan run.json         --adapter=openai    --profile=agent             # OpenAI Agents / Chat Completions
plumbline scan messages.json    --adapter=anthropic --profile=agent             # Anthropic Messages API
plumbline scan langgraph.json   --adapter=langchain --profile=agent             # LangChain / LangGraph
plumbline scan trace.otlp.json  --adapter=otel      --profile=agent             # OpenTelemetry GenAI spans
plumbline scan executions.jsonl --adapter=forge     --profile=agent             # server-side SDK-engine dump
plumbline scan audit.jsonl      --adapter=redstamp  --profile=redstamp-guarded  # redstamp per-call audit log
```

## Usage

```
plumbline replay <file.jsonl> [--semantic] [--only=a,b] [--json] [--report[=FILE]]
plumbline scan   <path> [--adapter=NAME] [--profile=NAME] [--limit=N] [--exit-code] [--report[=FILE]]
plumbline hook                       # score the session a hook names on stdin
plumbline install-hook               # wire that into ~/.claude/settings.json
plumbline validate <file.jsonl>      # schema-check a trajectory
plumbline detectors                  # list detectors
plumbline profiles                   # list envelope profiles
```
