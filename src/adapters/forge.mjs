/**
 * Forge execution adapter.
 *
 * Second harness, deliberately. Forge runs agents on the hosted SDK-engine harness
 * server-side, with a tool vocabulary that shares nothing with a Claude Code
 * transcript — `shell_exec`, `db_query`, `mail_send`, `container_ctl`,
 * `ticket_update`. If the trajectory schema is genuinely portable, the same
 * detectors should work over this with no changes. That is the claim this
 * adapter exists to test.
 *
 * Input format: JSONL, one execution per line, as produced by dumping
 * `/api/v1/admin/executions`:
 *   {id, agent, status, iterations, device_id, input, tool_calls:[{name, input}]}
 */

import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { entropyOf } from '../schema.mjs';
import { opOf } from './claude-code.mjs';

/** Fleet tool -> plumbline action. Unmapped tools fall through to tool.call. */
const ACTION_MAP = {
  shell_exec: 'proc.spawn',
  git_ops: 'proc.spawn',
  db_query: 'db.query',
  container_ctl: 'cloud.api',
  file_ops: 'fs.read',
  memory_search: 'state.read',
  memory_store: 'state.write',
  ticket_update: 'state.write',
  finding_ops: 'state.write',
  intervention_ops: 'state.write',
  fleet_health: 'state.read',
  agent_call: 'agent.spawn',
  web_search: 'http.request',
  web_browse: 'http.request',
  mail_send: 'mail.send',
  chat_notify: 'http.request',
};

/** Tools whose target is inherently outside the trust boundary. */
const EXTERNAL_TOOLS = new Set(['web_search', 'web_browse', 'mail_send', 'chat_notify']);

/**
 * Fleet tool -> the capability its use demonstrates the agent holds.
 *
 * This mapping is what makes staircase detection work on real traffic. Without
 * it the detector is inert outside a hand-authored corpus: nothing emits
 * capability_grant, so no rung is ever counted. Exercising a tool is evidence
 * of holding the capability, and the FIRST exercise in a session is the grant.
 */
const CAPABILITY_MAP = {
  shell_exec: ['exec:local', 'proc:spawn'],
  git_ops: ['exec:local'],
  db_query: ['db:query'],
  container_ctl: ['cloud:docker'],
  memory_search: ['state:read'],
  fleet_health: ['state:read'],
  memory_store: ['state:write'],
  ticket_update: ['state:write'],
  finding_ops: ['state:write'],
  intervention_ops: ['state:write'],
  agent_call: ['agent:spawn'],
  web_search: ['net:egress:read'],
  web_browse: ['net:egress:read'],
  chat_notify: ['net:egress:discord'],
};

function capabilitiesFor(tool, input) {
  if (tool === 'file_ops') {
    return [fileAction(input) === 'fs.write' ? 'fs:write' : 'fs:read'];
  }
  if (tool === 'mail_send') {
    const action = String(input?.action ?? '').toLowerCase();
    return [/send|reply|forward/.test(action) ? 'mail:send' : 'mail:read'];
  }
  return CAPABILITY_MAP[tool] ?? [];
}

const URL_RE = /\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(\/[^\s'"`;|)]*)?/i;
const SECRET_RE = /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_-]{20,})\b/g;

function hostFromAny(value) {
  if (typeof value !== 'string') return null;
  const m = URL_RE.exec(value);
  if (!m) return null;
  return m[1];
}

/** Recipient domain for mail, so send_to shows up as real egress topology. */
function mailHost(input) {
  const to = input?.to ?? input?.send_to ?? input?.recipient;
  if (typeof to !== 'string') return null;
  const at = to.lastIndexOf('@');
  return at === -1 ? null : to.slice(at + 1).trim().toLowerCase() || null;
}

function secretFragments(text, seq) {
  SECRET_RE.lastIndex = 0;
  const out = [];
  let m;
  let i = 0;
  while ((m = SECRET_RE.exec(text)) !== null) {
    out.push({ id: `fg-${seq}-${i++}`, len: m[0].length, entropy: entropyOf(m[0]) });
  }
  return out;
}

/**
 * A `file_ops` call is a read or a write depending on its action argument;
 * collapsing both to fs.read would hide data movement.
 */
function fileAction(input) {
  const action = String(input?.action ?? '').toLowerCase();
  if (/write|create|append|delete|remove|move|rename/.test(action)) return 'fs.write';
  return 'fs.read';
}

function targetFor(tool, input) {
  const target = {};

  if (tool === 'shell_exec' || tool === 'git_ops') {
    const command = input?.command ?? input?.cmd ?? '';
    target.op = tool === 'git_ops' ? 'git' : opOf(String(command));
    const host = hostFromAny(String(command));
    if (host) {
      target.host = host;
      target.external = true;
    }
    return target;
  }

  if (tool === 'web_browse') {
    const host = hostFromAny(input?.url ?? input?.target ?? '');
    if (host) { target.host = host; target.external = true; }
    else { target.host = 'browser.unresolved'; target.external = true; }
    return target;
  }

  if (tool === 'web_search') {
    target.host = 'search.provider';
    target.external = true;
    return target;
  }

  if (tool === 'mail_send') {
    const action = String(input?.action ?? '').toLowerCase();
    const host = mailHost(input);
    if (host) { target.host = host; target.external = true; }
    target.op = action || 'mail';
    return target;
  }

  if (tool === 'chat_notify') {
    target.host = 'discord.com';
    target.external = true;
    target.op = String(input?.action ?? 'post');
    return target;
  }

  if (tool === 'db_query') {
    target.host = 'askalf-postgres';
    target.op = String(input?.action ?? 'query');
    return target;
  }

  if (tool === 'container_ctl') {
    target.host = 'docker.sock';
    target.op = String(input?.action ?? 'api');
    return target;
  }

  if (tool === 'file_ops' && typeof input?.path === 'string') {
    target.path = input.path;
    return target;
  }

  if (EXTERNAL_TOOLS.has(tool)) target.external = true;
  if (typeof input?.action === 'string') target.op = input.action;
  return target;
}

/**
 * Mail with a body is data leaving. Everything else is small enough that
 * bytes_out would be noise, and the egress detector's write threshold would
 * misfire on protocol overhead.
 */
function bytesOut(tool, input) {
  if (tool !== 'mail_send') return 0;
  const body = input?.body ?? input?.text ?? input?.content ?? '';
  return typeof body === 'string' ? body.length : 0;
}

/** Convert one dumped execution row into a normalized-ready trajectory. */
export function executionToTrajectory(row, profile) {
  const session = row.id;
  const events = [];
  let seq = 0;

  events.push({
    v: 1,
    session,
    seq: seq++,
    action: 'session.declare',
    actor: row.agent ?? 'forge-agent',
    envelope: {
      task: typeof row.input === 'string' ? row.input.slice(0, 200) : null,
      capabilities: [...(profile.capabilities ?? [])],
      egress: {
        allow: [...(profile.egress?.allow ?? [])],
        mode: profile.egress?.mode ?? 'allowlist',
      },
      budget: { ...(profile.budget ?? {}) },
    },
  });

  const held = new Set();

  for (const call of row.tool_calls ?? []) {
    const tool = call?.name ?? 'unknown';
    const input = call?.input ?? {};
    const action = tool === 'file_ops' ? fileAction(input) : (ACTION_MAP[tool] ?? 'tool.call');

    // First exercise of a capability in this session is the grant.
    const fresh = capabilitiesFor(tool, input).filter((c) => !held.has(c));
    for (const c of fresh) held.add(c);

    const event = {
      v: 1,
      session,
      seq: seq++,
      actor: row.agent ?? 'forge-agent',
      action,
      target: targetFor(tool, input),
      outcome: 'ok',
      bytes_out: bytesOut(tool, input),
      note: tool,
    };
    if (fresh.length > 0) event.capability_grant = fresh;

    const scannable = JSON.stringify(input);
    const frags = secretFragments(scannable, event.seq);
    if (frags.length > 0) event.produces = frags;

    events.push(event);
  }

  return events;
}

/** Read a dumped executions JSONL file into per-execution trajectories. */
export async function readExecutions(file, profile) {
  const rl = createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  const trajectories = [];
  for await (const line of rl) {
    const raw = line.trim();
    if (raw === '' || raw.startsWith('#')) continue;
    let row;
    try {
      row = JSON.parse(raw);
    } catch {
      continue;
    }
    if (!Array.isArray(row.tool_calls) || row.tool_calls.length === 0) continue;
    trajectories.push({
      session: row.id,
      agent: row.agent ?? null,
      task: typeof row.input === 'string' ? row.input.slice(0, 200) : null,
      tool_calls: row.tool_calls.length,
      events: executionToTrajectory(row, profile),
    });
  }
  return trajectories;
}
