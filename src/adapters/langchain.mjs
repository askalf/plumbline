/**
 * LangChain / LangGraph adapter — LangSmith run trees.
 *
 * A run carries `run_type` ('chain' | 'llm' | 'tool' | 'retriever' | ...),
 * `inputs`, `outputs`, `error`, and either nested `child_runs` or a flat list
 * linked by `parent_run_id`. The tool runs are the actions; the root run's input
 * is the declared task. A run `error` that reads as a policy refusal is a denial.
 *
 * Input: a JSON file — a single root run (with child_runs), or an array of runs
 * (nested or flat).
 */

import { readFileSync } from 'node:fs';
import { buildTrajectory } from '../agentlog.mjs';

function flatten(run, acc) {
  if (!run || typeof run !== 'object') return acc;
  acc.push(run);
  for (const k of (run.child_runs ?? run.children ?? [])) flatten(k, acc);
  return acc;
}

function orderRuns(runs) {
  return runs.slice().sort((a, b) => {
    const ea = a.execution_order ?? 0;
    const eb = b.execution_order ?? 0;
    if (ea !== eb) return ea - eb;
    const ta = Date.parse(a.start_time ?? a.start ?? '') || 0;
    const tb = Date.parse(b.start_time ?? b.start ?? '') || 0;
    return ta - tb;
  });
}

function asText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  return JSON.stringify(value).slice(0, 2000);
}

export function langchainToRecords(runs) {
  const records = [];
  for (const run of orderRuns(runs)) {
    const type = String(run.run_type ?? run.type ?? '').toLowerCase();
    if (type !== 'tool') continue;
    const error = run.error;
    records.push({
      kind: 'tool',
      name: run.name ?? run.serialized?.name ?? 'tool',
      args: run.inputs ?? {},
      // On error, the error text is what a denial heuristic must read.
      output: error ? asText(error) : asText(run.outputs),
      isError: error != null,
      id: run.id,
    });
  }
  return records;
}

function rootTask(runs) {
  const root = runs.find((r) => r.parent_run_id == null && r.parent_run == null) ?? runs[0];
  const inp = root?.inputs;
  if (typeof inp === 'string') return inp;
  if (inp && typeof inp === 'object') {
    const v = inp.input ?? inp.question ?? inp.query ?? inp.text ?? inp.messages;
    return typeof v === 'string' ? v : JSON.stringify(inp).slice(0, 200);
  }
  return null;
}

export function readLangchain(file, profile) {
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const runs = Array.isArray(raw) ? raw.flatMap((r) => flatten(r, [])) : flatten(raw, []);
  const session = String(
    (!Array.isArray(raw) && (raw.id ?? raw.session ?? raw.trace_id)) || runs[0]?.trace_id || runs[0]?.id
      || file.replace(/^.*[\\/]/, '').replace(/\.jsonl?$|\.json$/, ''),
  );
  const records = langchainToRecords(runs);
  const task = rootTask(runs);
  const events = buildTrajectory({ session, actor: 'langchain', task, records, profile });
  return { session, task, tool_calls: records.length, events };
}
