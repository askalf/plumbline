/**
 * OpenTelemetry GenAI adapter — gen_ai.* spans.
 *
 * The highest-leverage adapter: OTel GenAI is the vendor-neutral standard, so
 * anything instrumented with OpenInference / OpenLLMetry (LangChain, CrewAI,
 * AutoGen, LlamaIndex, ...) emits it, and this one adapter reaches all of them.
 * Tool executions are spans with `gen_ai.operation.name = "execute_tool"` and a
 * `gen_ai.tool.name` attribute; an ERROR span status maps to error/denied.
 *
 * Input: a JSON file — an OTLP export (`{resourceSpans:[...]}`), an array of
 * spans, or JSONL of spans.
 *
 * Caveat, reported honestly: OTel tool-argument capture is opt-in, so a trace
 * that records only tool NAMES yields capability grants but no hosts or secrets.
 * Reachability shows exactly which detectors that leaves unfed.
 */

import { readFileSync } from 'node:fs';
import { buildTrajectory } from '../agentlog.mjs';

/** One attribute, whether attributes are an OTLP kv-list or a flat map. */
function attr(span, key) {
  const a = span.attributes;
  if (!a) return undefined;
  if (Array.isArray(a)) {
    const kv = a.find((x) => x.key === key);
    if (!kv) return undefined;
    const v = kv.value ?? {};
    return v.stringValue ?? v.intValue ?? v.boolValue ?? v.doubleValue
      ?? (v.arrayValue ? JSON.stringify(v.arrayValue) : undefined);
  }
  return a[key];
}

function spansFrom(raw) {
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw.spans)) return raw.spans;
  const out = [];
  for (const rs of raw.resourceSpans ?? []) {
    for (const ss of (rs.scopeSpans ?? rs.instrumentationLibrarySpans ?? [])) {
      for (const s of (ss.spans ?? [])) out.push(s);
    }
  }
  return out;
}

const startNs = (s) => Number(s.startTimeUnixNano ?? s.start_time_unix_nano ?? s.startTime ?? 0) || 0;

function statusError(span) {
  const code = span.status?.code ?? span.status?.statusCode;
  return code === 2 || code === 'STATUS_CODE_ERROR' || code === 'ERROR';
}

export function otelToRecords(spans) {
  const ordered = spans.slice().sort((a, b) => startNs(a) - startNs(b));
  const records = [];
  for (const span of ordered) {
    const op = attr(span, 'gen_ai.operation.name');
    const toolName = attr(span, 'gen_ai.tool.name') ?? attr(span, 'tool.name');
    const name = String(span.name ?? '');
    const isTool = op === 'execute_tool' || (toolName != null && (op == null)) || /^execute_tool\b/i.test(name);
    const isAgent = op === 'invoke_agent' || op === 'create_agent';

    if (isTool) {
      const argsRaw = attr(span, 'gen_ai.tool.call.arguments') ?? attr(span, 'gen_ai.tool.arguments')
        ?? attr(span, 'tool.arguments') ?? attr(span, 'input.value');
      const output = attr(span, 'gen_ai.tool.call.result') ?? attr(span, 'gen_ai.tool.result')
        ?? attr(span, 'output.value') ?? '';
      records.push({
        kind: 'tool',
        name: toolName ?? name.replace(/^execute_tool\s*/i, '').trim() ?? 'tool',
        args: argsRaw ?? {},
        output: String(output ?? ''),
        isError: statusError(span),
        id: span.spanId ?? span.span_id ?? attr(span, 'gen_ai.tool.call.id'),
      });
    } else if (isAgent) {
      records.push({
        kind: 'tool',
        name: 'spawn_agent',
        args: { agent: attr(span, 'gen_ai.agent.name') ?? name },
        subagent: true,
        id: span.spanId ?? span.span_id,
      });
    }
  }
  return records;
}

export function readOtel(file, profile) {
  const text = readFileSync(file, 'utf8');
  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    // JSONL of spans.
    raw = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => JSON.parse(l));
  }
  const spans = spansFrom(raw);
  const session = String(
    (!Array.isArray(raw) && (raw.trace_id ?? raw.traceId)) || spans[0]?.traceId || spans[0]?.trace_id
      || file.replace(/^.*[\\/]/, '').replace(/\.jsonl?$|\.json$/, ''),
  );
  const records = otelToRecords(spans);
  const events = buildTrajectory({ session, actor: 'otel', task: null, records, profile });
  return { session, task: null, tool_calls: records.filter((r) => r.kind === 'tool').length, events };
}
