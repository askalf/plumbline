// Fuzz target: capability inference over attacker-named tools.
//
// The framework adapters (openai, anthropic, langchain, otel) parse logs whose
// tool names and arguments are USER-DEFINED — i.e. attacker-influenced. The
// shared agentlog core infers each tool's action and capability from its name
// and args, and `staircase` (the primary detector) reads only the resulting
// capability_grant. So this inference runs on hostile strings by design, and
// it has no sanctioned throw: categorize() and buildTrajectory() must never
// throw here, whatever the tool is called or whatever its arguments contain.
import { buildTrajectory, categorize } from '../src/agentlog.mjs';
import { loadProfile } from '../src/scan.mjs';

// A real, valid envelope so the fuzzer exercises the record-parsing/inference
// path rather than a "missing profile" guard. Loaded once, not per-iteration.
const profile = loadProfile('agent');

export function fuzz(data) {
  const s = data.toString('utf8');
  // Split the bytes into a tool name and a payload used as both args and output.
  const nl = s.indexOf('\n');
  const name = nl === -1 ? s : s.slice(0, nl);
  const payload = nl === -1 ? '' : s.slice(nl + 1);

  // Inference over a hostile name must not throw.
  categorize(name);

  // The full record path: args as a raw string exercises normalizeArgs'
  // JSON.parse branch (OpenAI-style function.arguments), and the payload in
  // output exercises secret measurement and policy-denial detection. No
  // try/catch — buildTrajectory has no throw contract, so any throw is the bug.
  const record = {
    kind: 'tool',
    name,
    args: payload,
    output: payload,
    isError: (data.length & 1) === 1,
    subagent: (data.length & 2) === 2,
  };
  buildTrajectory({ session: 'fuzz', actor: 'agent', task: null, records: [record], profile });
}
