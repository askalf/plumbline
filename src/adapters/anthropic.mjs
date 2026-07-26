/**
 * Anthropic Messages API adapter.
 *
 * The non-Claude-Code path: people running their own tool loop directly on
 * `POST /v1/messages`. A tool_use block in an assistant message is an action;
 * the matching tool_result block in the next user message supplies the outcome,
 * and a result that reads as a policy refusal becomes `denied` (feeds ratchet).
 *
 * Input: a JSON file that is an array of messages, or an object with a
 * `.messages` array — an API request body works as-is.
 */

import { readFileSync } from 'node:fs';
import { buildTrajectory } from '../agentlog.mjs';

function textOf(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.filter((b) => b?.type === 'text' && typeof b.text === 'string').map((b) => b.text).join('\n');
  }
  return '';
}

/** Messages array -> flat records for the shared core. */
export function anthropicToRecords(messages) {
  const records = [];
  const byId = new Map();

  for (const msg of messages ?? []) {
    if (!msg || typeof msg !== 'object') continue;
    const content = msg.content;

    if (msg.role === 'user') {
      // tool_result blocks attach to the tool_use they answer.
      if (Array.isArray(content)) {
        for (const b of content) {
          if (b?.type !== 'tool_result') continue;
          const rec = byId.get(b.tool_use_id);
          if (rec) {
            rec.output = textOf(b.content);
            if (b.is_error === true) rec.isError = true;
          }
        }
      }
      const onlyToolResults = Array.isArray(content) && content.length > 0
        && content.every((b) => b?.type === 'tool_result');
      const text = textOf(content).trim();
      if (text && !onlyToolResults && !text.startsWith('<')) records.push({ kind: 'human', text });
    } else if (msg.role === 'assistant' && Array.isArray(content)) {
      for (const b of content) {
        if (b?.type !== 'tool_use') continue;
        const rec = { kind: 'tool', name: b.name ?? 'unknown', args: b.input ?? {}, id: b.id, output: '' };
        if (b.id) byId.set(b.id, rec);
        records.push(rec);
      }
    }
  }
  return records;
}

const firstHuman = (records) => records.find((r) => r.kind === 'human')?.text ?? null;

/** Read one Anthropic conversation file into a single-session trajectory. */
export function readAnthropic(file, profile) {
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const messages = Array.isArray(raw) ? raw : (raw.messages ?? []);
  const session = String(raw.id ?? raw.session ?? file.replace(/^.*[\\/]/, '').replace(/\.jsonl?$|\.json$/, ''));
  const records = anthropicToRecords(messages);
  const task = firstHuman(records);
  const events = buildTrajectory({ session, actor: 'anthropic', task, records, profile });
  return { session, task, tool_calls: records.filter((r) => r.kind === 'tool').length, events };
}
