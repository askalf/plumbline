/**
 * OpenAI adapter — Chat Completions and Responses API tool-call logs.
 *
 * The most widely used agent runtime. Two shapes, both common, both handled:
 *   - Chat Completions: messages with role user / assistant (`tool_calls`,
 *     each `{id, function:{name, arguments}}`) / tool (`tool_call_id`, content).
 *   - Responses API / Agents SDK: an item list of `{type:'function_call',...}`,
 *     `{type:'function_call_output',...}`, `{type:'message', role, content}`.
 *
 * Input: a JSON file — an array of messages/items, or `{messages}` / `{input}` /
 * `{output}` wrapping one.
 */

import { readFileSync } from 'node:fs';
import { buildTrajectory } from '../agentlog.mjs';

function textOf(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.map((c) => (typeof c === 'string' ? c : (c?.text ?? c?.content ?? ''))).join('\n');
  }
  return '';
}

function chatToRecords(messages) {
  const records = [];
  const byId = new Map();
  for (const m of messages ?? []) {
    if (!m || typeof m !== 'object') continue;
    if (m.role === 'user') {
      const t = textOf(m.content).trim();
      if (t && !t.startsWith('<')) records.push({ kind: 'human', text: t });
    } else if (m.role === 'assistant' && Array.isArray(m.tool_calls)) {
      for (const tc of m.tool_calls) {
        const fn = tc.function ?? tc;
        const id = tc.id ?? tc.call_id;
        const rec = { kind: 'tool', name: fn?.name ?? 'unknown', args: fn?.arguments ?? {}, id, output: '' };
        if (id) byId.set(id, rec);
        records.push(rec);
      }
    } else if (m.role === 'tool' || m.role === 'function') {
      const rec = byId.get(m.tool_call_id ?? m.name);
      if (rec) rec.output = textOf(m.content);
    }
  }
  return records;
}

function responsesToRecords(items) {
  const records = [];
  const byId = new Map();
  for (const it of items ?? []) {
    if (!it || typeof it !== 'object') continue;
    if (it.type === 'function_call' || it.type === 'tool_call') {
      const id = it.call_id ?? it.id;
      const rec = { kind: 'tool', name: it.name ?? it.function?.name ?? 'unknown', args: it.arguments ?? it.function?.arguments ?? {}, id, output: '' };
      if (id) byId.set(id, rec);
      records.push(rec);
    } else if (it.type === 'function_call_output' || it.type === 'tool_result') {
      const rec = byId.get(it.call_id ?? it.tool_call_id);
      if (rec) rec.output = typeof it.output === 'string' ? it.output : textOf(it.output ?? it.content);
    } else if (it.type === 'message' && it.role === 'user') {
      const t = textOf(it.content).trim();
      if (t && !t.startsWith('<')) records.push({ kind: 'human', text: t });
    }
  }
  return records;
}

export function openaiToRecords(raw) {
  const arr = Array.isArray(raw) ? raw : (raw.messages ?? raw.input ?? raw.output ?? raw.items ?? []);
  const isResponses = arr.some((x) => x && typeof x === 'object' && typeof x.type === 'string'
    && /^(function_call|tool_call|function_call_output|tool_result|message)$/.test(x.type));
  return isResponses ? responsesToRecords(arr) : chatToRecords(arr);
}

const firstHuman = (records) => records.find((r) => r.kind === 'human')?.text ?? null;

export function readOpenai(file, profile) {
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const session = String(raw.id ?? raw.session ?? file.replace(/^.*[\\/]/, '').replace(/\.jsonl?$|\.json$/, ''));
  const records = openaiToRecords(raw);
  const task = firstHuman(records);
  const events = buildTrajectory({ session, actor: 'openai', task, records, profile });
  return { session, task, tool_calls: records.filter((r) => r.kind === 'tool').length, events };
}
