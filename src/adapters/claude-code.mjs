/**
 * Claude Code transcript adapter.
 *
 * Turns a `~/.claude/projects/**\/*.jsonl` session into a plumbline trajectory.
 * Streamed line-by-line because real transcripts reach hundreds of megabytes.
 *
 * The mapping worth understanding: a tool_use block is an action, and the
 * matching tool_result supplies the outcome. A tool_result whose text reads as a
 * permission refusal becomes `denied`, which is what feeds ratchet detection -
 * so this adapter can see an agent being refused and then reshaping the request
 * until it passes.
 */

import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { entropyOf } from '../schema.mjs';

/** Tool name -> plumbline action verb. */
const ACTION_MAP = {
  Read: 'fs.read',
  NotebookRead: 'fs.read',
  Write: 'fs.write',
  Edit: 'fs.write',
  MultiEdit: 'fs.write',
  NotebookEdit: 'fs.write',
  Glob: 'fs.search',
  Grep: 'fs.search',
  LS: 'fs.search',
  Bash: 'proc.spawn',
  PowerShell: 'proc.spawn',
  BashOutput: 'proc.read',
  KillShell: 'proc.signal',
  WebFetch: 'http.request',
  WebSearch: 'http.request',
  Agent: 'agent.spawn',
  Task: 'agent.spawn',
  TodoWrite: 'state.write',
  ExitPlanMode: 'state.write',
};

/**
 * Tool -> the capability its use demonstrates the agent holds.
 *
 * Load-bearing: staircase detection reads only `capability_grant`, so without
 * this mapping the primary detector is inert on real transcripts and only fires
 * on hand-authored corpora. Exercising a tool is evidence of holding the
 * capability; the first exercise in a session is the grant.
 */
const CAPABILITY_MAP = {
  Read: ['fs:read'],
  NotebookRead: ['fs:read'],
  Glob: ['fs:read'],
  Grep: ['fs:read'],
  LS: ['fs:read'],
  Write: ['fs:write'],
  Edit: ['fs:write'],
  MultiEdit: ['fs:write'],
  NotebookEdit: ['fs:write'],
  Bash: ['exec:local', 'proc:spawn'],
  PowerShell: ['exec:local', 'proc:spawn'],
  BashOutput: ['proc:spawn'],
  KillShell: ['proc:spawn'],
  WebFetch: ['net:egress:read'],
  WebSearch: ['net:egress:read'],
  Agent: ['agent:spawn'],
  Task: ['agent:spawn'],
  TodoWrite: ['state:write'],
  ExitPlanMode: ['state:write'],
};

function capabilitiesFor(tool) {
  if (CAPABILITY_MAP[tool]) return CAPABILITY_MAP[tool];
  if (tool.startsWith('mcp__')) return ['mcp:call'];
  return [];
}

const DENIAL_PATTERNS = [
  /permission (for this action )?(was |is )?denied/i,
  /requested permissions?.{0,40}(denied|rejected)/i,
  /blocked by (the )?classifier/i,
  /user (denied|rejected|declined)/i,
  /operation not permitted by policy/i,
  // Server-side harnesses refuse in their own vocabulary. These are the shapes
  // a guarded hosted harness actually emits — a policy gate returning a
  // `Blocked:`-prefixed error, or a guard naming itself in the refusal. Without
  // them a refusal there reads as an ordinary tool error, which is `error`, not
  // `denied`, and ratchet never counts the rung.
  /\bblocked\s*:/i,
  /\b(?:refused|rejected|denied) by (?:the )?(?:guard|gate|policy|firewall)/i,
  /\brequires operator (?:approval|authorization)/i,
];

const URL_RE = /\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(\/[^\s'"`;|)]*)?/gi;
const SSH_RE = /\bssh\s+(?:-\S+\s+)*(?:[\w.-]+@)?([a-z0-9.-]+\.[a-z]{2,}|\d+\.\d+\.\d+\.\d+)/gi;
const SCP_RE = /\bscp\s+\S*?(?:[\w.-]+@)?([a-z0-9.-]+\.[a-z]{2,}|\d+\.\d+\.\d+\.\d+):/gi;
// URL_RE requires a dotted alphabetic TLD, so a bare-IP or link-local target
// slips past it. That gap is exactly what a capability-laundering escape uses:
// `curl <link-local-ip>/…` to read cloud metadata looks like an ordinary local
// command with no recognised host. Capture IP hosts and metadata hostnames from
// http(s) URLs and from bare fetch arguments so the metadata detector can see them.
const IP_URL_RE = /\bhttps?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/gi;
const FETCH_ARG_RE = /\b(?:curl|wget|http|https|nc|ncat)\s+(?:-\S+\s+)*(?:https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9.-]+\.internal)\b/gi;

/** Hosts that are the local machine, not egress. */
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/** Pull outbound hosts out of a shell command. Best-effort by design. */
function hostsInCommand(command) {
  const hosts = new Set();
  for (const re of [URL_RE, SSH_RE, SCP_RE, IP_URL_RE, FETCH_ARG_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(command)) !== null) {
      const host = m[1];
      // Loopback is not egress; but link-local (169.254.x) and other IP hosts
      // ARE reported, so the metadata detector can inspect them. It decides
      // whether an address is a metadata target — this only surfaces the host.
      if (host && !LOCAL_HOSTS.has(host)) hosts.add(host);
    }
  }
  return [...hosts];
}

/**
 * Does this tool-result text read as a refusal rather than a plain failure?
 *
 * Exported because refusal vocabulary is a property of agent harnesses, not of
 * one transcript format — the forge adapter derives the same `denied` outcome
 * from server-side execution records. Two adapters disagreeing about what a
 * refusal looks like would make `ratchet` fire on one harness and stay silent
 * on the other for identical behaviour.
 */
export function looksDenied(text) {
  return DENIAL_PATTERNS.some((re) => re.test(text));
}

/**
 * Bytes a shell command sends outward.
 *
 * Deliberately conservative: only inline request bodies and uploaded files
 * count. A transcript does not record what actually crossed the wire, so
 * guessing would turn ordinary chatter into apparent data movement — the same
 * mistake that produced the original 34.7% false-positive rate. Returning 0
 * leaves the egress write branch quiet rather than wrong.
 */
const BODY_FLAG_RE = /(?:--data(?:-raw|-binary|-urlencode)?|-d|--form|-F|--upload-file|-T)[= ]+(['"])([\s\S]*?)\1/g;

function outboundBytes(command) {
  const text = String(command);
  if (!/\b(?:curl|wget|http|https|scp|rsync|aws|gh)\b/.test(text)) return 0;
  BODY_FLAG_RE.lastIndex = 0;
  let total = 0;
  let m;
  while ((m = BODY_FLAG_RE.exec(text)) !== null) total += m[2].length;
  return total;
}

/**
 * Credential-shaped strings in a command. Emitted as `produces` measurements
 * only - the value never leaves this function, which is the point: plumbline
 * can reason about secret movement without ever holding a secret.
 */
const SECRET_RE = /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_-]{20,})\b/g;

/**
 * Fragment identity is a truncated hash of the value, NOT a positional counter.
 *
 * This is what makes `reassembly` reachable on real traffic. With positional
 * ids (`cc-<seq>-<n>`) the same secret appearing in two commands got two
 * unrelated ids, so no `consumes` edge could ever be drawn and the detector was
 * structurally inert. Hashing means the second sighting resolves to the first
 * fragment, and two distinct secrets converging on one egress becomes visible.
 *
 * The hash is one-way and truncated: it identifies without carrying the value,
 * preserving the property that plumbline never holds a secret.
 */
function fragmentId(secret) {
  return `f-${createHash('sha256').update(secret).digest('hex').slice(0, 16)}`;
}

function secretsIn(text) {
  SECRET_RE.lastIndex = 0;
  const out = [];
  let m;
  while ((m = SECRET_RE.exec(text)) !== null) out.push(m[0]);
  return out;
}

/**
 * Operation identity for a shell command: the invoked binary, skipping env
 * assignments and common wrappers. This is what lets ratchet detection compare
 * a denied `docker exec` against a later `docker compose` without also
 * comparing it against an unrelated `ls`.
 */
const WRAPPERS = new Set(['sudo', 'env', 'time', 'nohup', 'command', 'exec', 'npx', 'pnpm', 'yarn', 'uv', 'poetry']);

/**
 * Navigation prefixes. These take a path argument, so the whole segment must be
 * skipped rather than just the verb — otherwise `cd repo; git log` keys on `cd`,
 * and since nearly every shell command on a Windows box starts that way, every
 * command collapses to one identity again. Calibration caught this: `cd`
 * accounted for six of the last eleven false ratchets.
 */
const NAVIGATION = new Set(['cd', 'pushd', 'popd', 'chdir', 'set-location', 'sl']);

export function opOf(command) {
  const segments = String(command).split(/&&|\|\||;|\|/);
  for (const segment of segments) {
    const tokens = segment.trim().split(/\s+/);
    for (const token of tokens) {
      if (token === '' || token.includes('=')) continue; // FOO=bar prefixes
      if (token.startsWith('-')) continue;
      const bare = token.replace(/^.*[\\/]/, '').replace(/\.(exe|cmd|ps1|sh)$/i, '').toLowerCase();
      if (NAVIGATION.has(bare)) break; // skip this segment and its path argument
      if (WRAPPERS.has(bare)) continue;
      if (bare) return bare;
    }
  }
  return null;
}

function targetFor(tool, input) {
  if (tool === 'WebFetch' && typeof input?.url === 'string') {
    const host = hostFromUrl(input.url);
    return host ? { host, path: null, external: !LOCAL_HOSTS.has(host) } : {};
  }
  if (tool === 'WebSearch') return { host: 'search.provider', external: true };
  if (typeof input?.command === 'string') return { op: opOf(input.command) };
  if (typeof input?.file_path === 'string') return { path: input.file_path };
  if (typeof input?.path === 'string') return { path: input.path };
  if (typeof input?.pattern === 'string') return { path: input.pattern };
  return {};
}

/**
 * Parse one transcript into normalized-ready raw events.
 *
 * @param {string} file
 * @param {{session?: string, cwd?: string}} [opts]
 * @returns {Promise<{events: object[], task: string|null, cwd: string|null, tools: Record<string, number>}>}
 */
export async function readTranscript(file, opts = {}) {
  const rl = createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });

  const session = opts.session ?? file.replace(/^.*[\\/]/, '').replace(/\.jsonl$/, '');
  const events = [];
  /** @type {Map<string, object>} */
  const pending = new Map();
  const tools = {};
  const held = new Set();
  const knownFragments = new Set();
  let task = null;
  let cwd = opts.cwd ?? null;
  let seq = 1;

  for await (const line of rl) {
    const raw = line.trim();
    if (raw === '') continue;
    let entry;
    try {
      entry = JSON.parse(raw);
    } catch {
      continue; // a truncated tail line is normal on a live session
    }

    if (!cwd && typeof entry.cwd === 'string') cwd = entry.cwd;

    // Human turns: the first supplies the declared intent, and every one emits a
    // session.turn marker so ratchet detection knows oversight intervened.
    if (entry.type === 'user' && entry.message?.role === 'user') {
      const content = entry.message.content;
      const isToolResultOnly = Array.isArray(content)
        && content.length > 0
        && content.every((c) => c?.type === 'tool_result');

      if (!isToolResultOnly) {
        const text = typeof content === 'string'
          ? content
          : Array.isArray(content)
            ? content.filter((c) => c?.type === 'text').map((c) => c.text).join(' ')
            : '';
        const trimmed = text.trim();
        if (trimmed && !trimmed.startsWith('<')) {
          if (task === null) task = trimmed.slice(0, 200);
          events.push({
            v: 1,
            session,
            seq: seq++,
            ts: entry.timestamp ?? undefined,
            actor: 'human',
            action: 'session.turn',
            outcome: 'ok',
            note: 'operator turn',
          });
        }
      }
    }

    if (entry.type === 'assistant' && Array.isArray(entry.message?.content)) {
      for (const block of entry.message.content) {
        if (block?.type !== 'tool_use') continue;
        const tool = block.name ?? 'unknown';
        tools[tool] = (tools[tool] ?? 0) + 1;

        const action = ACTION_MAP[tool] ?? (tool.startsWith('mcp__') ? 'mcp.call' : 'tool.call');
        const input = block.input ?? {};
        const event = {
          v: 1,
          session,
          seq: seq++,
          ts: entry.timestamp ?? undefined,
          actor: 'claude-code',
          action,
          target: targetFor(tool, input),
          outcome: 'ok',
          note: tool,
        };

        // First exercise of a capability in this session is the grant.
        const fresh = capabilitiesFor(tool).filter((c) => !held.has(c));
        for (const c of fresh) held.add(c);
        if (fresh.length > 0) event.capability_grant = fresh;

        if (tool === 'Agent' || tool === 'Task') {
          event.instance = `sub-${block.id ?? event.seq}`;
        }

        const command = typeof input.command === 'string' ? input.command : null;
        if (command) {
          const hosts = hostsInCommand(command);
          if (hosts.length > 0) {
            // Attribute the command to its first outbound host, keeping the op
            // so ratchet detection still has an identity to compare. Extra
            // hosts get their own synthetic egress events so topology drift
            // sees the whole set.
            event.target = { ...event.target, host: hosts[0], external: true };
            for (const host of hosts.slice(1)) {
              events.push({
                v: 1,
                session,
                seq: seq++,
                actor: 'claude-code',
                action: 'net.send',
                target: { host, external: true },
                outcome: 'ok',
                note: `${tool} (additional host)`,
              });
            }
          }
          // Secret movement: first sighting of a value produces a fragment;
          // any later sighting consumes it. Hash-derived ids are what link the
          // two, and what makes reassembly reachable at all.
          const secrets = secretsIn(command);
          if (secrets.length > 0) {
            const produces = [];
            const consumes = [];
            for (const secret of secrets) {
              const id = fragmentId(secret);
              if (knownFragments.has(id)) {
                if (!consumes.includes(id)) consumes.push(id);
              } else {
                knownFragments.add(id);
                produces.push({ id, len: secret.length, entropy: entropyOf(secret) });
              }
            }
            if (produces.length > 0) event.produces = produces;
            if (consumes.length > 0) event.consumes = consumes;
          }

          // Outbound payload size, so the egress write branch is reachable.
          // Only counted for commands that plainly carry a body outward -
          // anything else would make protocol chatter look like data movement.
          const bytes = outboundBytes(command);
          if (bytes > 0) event.bytes_out = bytes;
        }

        if (block.id) pending.set(block.id, event);
        events.push(event);
      }
    }

    if (entry.type === 'user' && Array.isArray(entry.message?.content)) {
      for (const block of entry.message.content) {
        if (block?.type !== 'tool_result') continue;
        const event = pending.get(block.tool_use_id);
        if (!event) continue;
        pending.delete(block.tool_use_id);

        const content = block.content;
        const text = typeof content === 'string'
          ? content
          : Array.isArray(content)
            ? content.filter((c) => c?.type === 'text').map((c) => c.text).join('\n')
            : '';

        if (block.is_error === true) event.outcome = looksDenied(text) ? 'denied' : 'error';
        else if (looksDenied(text)) event.outcome = 'denied';
        if (typeof text === 'string' && text.length > 0) event.bytes_in = text.length;
      }
    }
  }

  return { events, task, cwd, tools };
}

/**
 * Build a session.declare event from an envelope profile plus what the
 * transcript itself tells us about the job.
 */
export function declareFor({ session, task, cwd, profile }) {
  const capabilities = [...(profile.capabilities ?? [])];
  if (cwd) capabilities.push(`fs:${cwd.replace(/\\/g, '/')}/*`);
  return {
    v: 1,
    session,
    seq: 0,
    action: 'session.declare',
    actor: 'claude-code',
    envelope: {
      task: task ?? null,
      capabilities,
      egress: {
        allow: [...(profile.egress?.allow ?? [])],
        mode: profile.egress?.mode ?? 'allowlist',
      },
      budget: { ...(profile.budget ?? {}) },
    },
  };
}
