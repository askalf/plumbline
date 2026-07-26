/**
 * Shared core for the structured agent-log adapters: openai, anthropic,
 * langchain, otel. Each of those is a thin parser that turns its native log
 * shape into a flat list of `records` and hands them here; this file does the
 * part that has to be identical across all of them.
 *
 * The hard part these share, and the reason it lives in one place:
 *
 *   The tools are USER-DEFINED. A Claude Code transcript has a fixed vocabulary
 *   (Read, Bash, WebFetch), so its adapter can map each tool to a capability by
 *   hand. An OpenAI or LangChain agent calls tools named whatever the developer
 *   named them. So the mapping to plumbline's capability vocabulary has to be
 *   INFERRED from the tool name and arguments — and staircase, the primary
 *   detector, reads only `capability_grant`, so getting this inference right is
 *   what makes these adapters worth anything at all.
 *
 * The inference is deliberately conservative and documented as such: it
 * recognises the common shapes (shell, file, http, db, mail, agent, memory) and
 * falls back to a per-tool `tool:<name>` capability for everything else, so an
 * unrecognised tool still accretes against a declared envelope rather than
 * vanishing. A too-loose envelope silently disables this — see DETECTORS.md.
 */

import { createHash } from 'node:crypto';
import { entropyOf } from './schema.mjs';
import { opOf } from './adapters/claude-code.mjs';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', '::']);

/** Normalise a tool name to space-separated lowercase words, so `readFile`,
 *  `read_file` and `read-file` all match the same rule. */
function words(name) {
  return ` ${String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, ' ')
    .trim()} `;
}

function slug(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'unknown';
}

/**
 * Ordered inference rules. First match wins, so specific shapes (web_search,
 * code_interpreter) must precede general ones (search, exec). Each rule names
 * the plumbline action, the capability the tool's use demonstrates, and how to
 * find the target inside the arguments.
 */
const RULES = [
  { re: / (sub ?agent|handoff|hand off|transfer to|delegate|spawn agent|invoke agent|call agent|dispatch agent|create agent) /,
    action: 'agent.spawn', caps: ['agent:spawn'], subagent: true },
  { re: / (web search|google search|search web|internet search|tavily|serp|serpapi|duckduckgo|ddg|brave search|exa|perplexity|search internet) /,
    action: 'http.request', caps: ['net:egress:read'], host: 'search.provider', external: true },
  { re: / (web browse|browse|browser|navigate|open url|open page|goto|playwright|puppeteer|selenium|render page|screenshot|visit|scrape|crawl) /,
    action: 'http.request', caps: ['net:egress:read'], external: true, urlHost: true },
  { re: / (send email|send mail|email|gmail|smtp|sendgrid|mailgun|ses|mail send|mailer) /,
    action: 'mail.send', caps: ['mail:send'], external: true, mail: true },
  { re: / (slack|discord|telegram|whatsapp|sms|twilio|teams|send message|post message|chat post|notify|pager|pagerduty) /,
    action: 'http.request', caps: ['net:egress:chat'], external: true, host: 'chat.provider' },
  { re: / (sql|db query|database|query db|select|mongo|mongodb|postgres|postgresql|mysql|sqlite|redis|prisma|supabase|run query|execute query|db exec) /,
    action: 'db.query', caps: ['db:query'], dbHost: true, op: true },
  { re: / (aws|gcloud|gcp|azure|boto|kubectl|k8s|kubernetes|helm|docker|podman|terraform|pulumi|cloudformation|s3|iam|lambda|ec2) /,
    action: 'cloud.api', caps: ['cloud:api'], cmdHost: true, op: true },
  { re: / (code interpreter|execute code|run code|run python|python|ipython|jupyter|repl|eval|sandbox|run script|node eval) /,
    action: 'proc.spawn', caps: ['exec:local', 'proc:spawn'], cmdHost: true, op: true },
  { re: / (shell|bash|zsh|exec|execute command|run command|run shell|command|cmd|terminal|console|subprocess|system|spawn|process|run bash) /,
    action: 'proc.spawn', caps: ['exec:local', 'proc:spawn'], cmdHost: true, op: true },
  { re: / (write file|save file|create file|edit|append file|put file|update file|delete file|remove file|patch|mkdir|move file|rename file|file write|save|writefile) /,
    action: 'fs.write', caps: ['fs:write'], pathArg: true },
  { re: / (read file|get file|open file|load file|view file|cat file|file read|readfile|fetch file|cat|head|tail|read) /,
    action: 'fs.read', caps: ['fs:read'], pathArg: true },
  { re: / (glob|grep|ripgrep|find file|search file|list files|list dir|listdir|ls|dir|walk|file tree|find in|locate) /,
    action: 'fs.search', caps: ['fs:read'], pathArg: true },
  { re: / (http request|http get|http post|fetch|request|api call|call api|rest|curl|wget|get url|post url|webhook|graphql|download|http|https|url|api) /,
    action: 'http.request', caps: ['net:egress:read'], external: true, urlHost: true },
  { re: / (remember|memory store|store memory|save memory|write state|kv set|cache set|set state|save state|upsert|store fact) /,
    action: 'state.write', caps: ['state:write'] },
  { re: / (recall|memory search|search memory|get memory|load memory|read state|kv get|cache get|vector search|semantic search|rag|retrieve) /,
    action: 'state.read', caps: ['state:read'] },
];

/** Infer action + capabilities + how to read the target from a tool name. */
export function categorize(name) {
  const w = words(name);
  for (const rule of RULES) {
    if (rule.re.test(w)) return rule;
  }
  return { action: 'tool.call', caps: [`tool:${slug(name)}`] };
}

// ---- pulling structure out of arbitrary argument objects ----------------

const URL_RE = /\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z0-9.-]+\.internal)(?::\d+)?/i;
const SECRET_RE = /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_-]{20,})\b/g;

/** First string value among a set of candidate keys. */
function firstStr(args, keys) {
  if (!args || typeof args !== 'object') return null;
  for (const k of keys) {
    const v = args[k];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return null;
}

function hostInString(value) {
  if (typeof value !== 'string') return null;
  const m = URL_RE.exec(value);
  return m ? m[1] : null;
}

function mailHost(args) {
  const to = firstStr(args, ['to', 'recipient', 'send_to', 'sendTo', 'email', 'address']);
  if (!to) return null;
  const at = to.lastIndexOf('@');
  return at === -1 ? null : (to.slice(at + 1).trim().toLowerCase() || null);
}

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

const DENIAL_PATTERNS = [
  /permission (for this action )?(was |is )?denied/i,
  /requested permissions?.{0,40}(denied|rejected)/i,
  /blocked by (the )?(classifier|guard|policy)/i,
  /(user|operator) (denied|rejected|declined)/i,
  /operation not permitted by policy/i,
  /not allowed by (the )?(policy|allowlist|envelope)/i,
  /\b(refused|forbidden)\b.{0,30}\b(policy|guard|permission)\b/i,
];

function looksDenied(text) {
  return typeof text === 'string' && DENIAL_PATTERNS.some((re) => re.test(text));
}

/** Bytes plausibly leaving on this call: an explicit request/mail body only. */
function outboundBytes(args) {
  const body = firstStr(args, ['body', 'data', 'content', 'payload', 'text', 'message']);
  return body ? body.length : 0;
}

/** Build the target for a tool call from its inferred rule + arguments. */
function targetFor(rule, args) {
  const target = {};
  if (rule.host) { target.host = rule.host; }
  if (rule.external) target.external = true;

  if (rule.cmdHost) {
    const cmd = firstStr(args, ['command', 'cmd', 'script', 'code', 'input', 'query']);
    if (cmd) {
      const op = opOf(cmd);
      if (op) target.op = op;
      const host = hostInString(cmd);
      if (host && !LOCAL_HOSTS.has(host)) { target.host = host; target.external = true; }
    }
  }
  if (rule.op && !target.op) {
    const op = firstStr(args, ['action', 'method', 'operation', 'verb', 'command']);
    if (op) target.op = op.slice(0, 40);
  }
  if (rule.urlHost) {
    const url = firstStr(args, ['url', 'uri', 'endpoint', 'href', 'link', 'address', 'target']) || hostInString(JSON.stringify(args ?? {}));
    const host = hostInString(url) || (typeof url === 'string' && !/\s/.test(url) && url.includes('.') ? url.replace(/^https?:\/\//, '').split('/')[0] : null);
    if (host && !LOCAL_HOSTS.has(host)) { target.host = host; target.external = true; }
    else if (!host) { target.host = target.host ?? 'egress.unresolved'; target.external = true; }
  }
  if (rule.mail) {
    const host = mailHost(args);
    if (host) { target.host = host; target.external = true; }
    const action = firstStr(args, ['action', 'method']);
    if (action) target.op = action;
  }
  if (rule.dbHost) {
    const host = hostInString(firstStr(args, ['host', 'connection', 'database_url', 'dsn', 'uri']) ?? '') ;
    target.host = host || 'database';
  }
  if (rule.pathArg) {
    const path = firstStr(args, ['path', 'file_path', 'filePath', 'filename', 'file', 'dir', 'directory', 'pattern']);
    if (path) target.path = path;
  }
  return target;
}

/**
 * Turn a flat record list into a normalized-ready trajectory.
 *
 * Records are the small intermediate every adapter produces:
 *   { kind: 'human', text }                         a human/user turn
 *   { kind: 'tool', name, args, output, isError,    one tool call + its result
 *                   denied, id, subagent }
 *
 * @param {{session:string, actor?:string, task?:string|null, records:object[], profile:object}} spec
 */
export function buildTrajectory({ session, actor = 'agent', task = null, records, profile }) {
  const events = [declareFor({ session, actor, task, profile })];
  const held = new Set();
  const knownFragments = new Set();
  let subagents = 0;
  let seq = 1;

  for (const rec of records ?? []) {
    if (rec == null) continue;

    if (rec.kind === 'human') {
      const text = typeof rec.text === 'string' ? rec.text.trim() : '';
      if (!text) continue;
      events.push({
        v: 1, session, seq: seq++, ts: rec.ts ?? undefined,
        actor: 'human', action: 'session.turn', outcome: 'ok', note: 'operator turn',
      });
      continue;
    }

    const name = rec.name ?? 'unknown';
    const args = normalizeArgs(rec.args);
    const rule = categorize(name);

    const event = {
      v: 1, session, seq: seq++, ts: rec.ts ?? undefined,
      actor,
      action: rule.action,
      target: targetFor(rule, args),
      outcome: 'ok',
      note: name,
    };

    // Explicit per-call overrides an adapter can supply (e.g. an OTel span that
    // already carries server.address, or a format that flags a denial natively).
    if (rec.external === true) event.target.external = true;
    if (typeof rec.host === 'string') { event.target.host = rec.host; event.target.external = true; }

    // First exercise of a capability in this session is the grant.
    const fresh = rule.caps.filter((c) => !held.has(c));
    for (const c of fresh) held.add(c);
    if (fresh.length > 0) event.capability_grant = fresh;

    // Delegation is ephemeral compute; without an instance identity fanout can
    // never fire and a swarm of subagents is invisible.
    if (rule.subagent || rec.subagent) {
      subagents += 1;
      event.instance = rec.id ? `sub-${rec.id}` : `sub-${subagents}`;
    }

    // Outcome: a native denial flag wins; otherwise a result that reads as a
    // policy refusal is `denied` (feeds ratchet), a plain error is `error`.
    const output = typeof rec.output === 'string' ? rec.output : '';
    if (rec.denied === true || looksDenied(output)) event.outcome = 'denied';
    else if (rec.isError === true) event.outcome = 'error';
    if (output) event.bytes_in = output.length;

    const bytes = outboundBytes(args);
    if (bytes > 0) event.bytes_out = bytes;

    // Secret movement: first sighting of a value produces a fragment, any later
    // sighting consumes it. Hash-derived ids link the two, which is what makes
    // reassembly reachable. The value is measured, never carried.
    const secrets = secretsIn(JSON.stringify(args ?? {}));
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

    events.push(event);
  }

  return events;
}

/** Coerce arguments that arrived as a JSON string (OpenAI function.arguments). */
function normalizeArgs(args) {
  if (args == null) return {};
  if (typeof args === 'object') return args;
  if (typeof args === 'string') {
    try { const p = JSON.parse(args); return (p && typeof p === 'object') ? p : { value: args }; }
    catch { return { value: args }; }
  }
  return { value: args };
}

/** A session.declare from an envelope profile plus the log's own task text. */
export function declareFor({ session, actor = 'agent', task = null, profile }) {
  return {
    v: 1, session, seq: 0, action: 'session.declare', actor,
    envelope: {
      task: typeof task === 'string' ? task.slice(0, 200) : (task ?? null),
      capabilities: [...(profile.capabilities ?? [])],
      egress: {
        allow: [...(profile.egress?.allow ?? [])],
        mode: profile.egress?.mode ?? 'allowlist',
      },
      budget: { ...(profile.budget ?? {}) },
    },
  };
}

export { looksDenied, secretsIn };
