/**
 * redstamp audit adapter.
 *
 * redstamp (https://github.com/askalf/redstamp) is the per-call guard: it sits
 * between an agent and its tools, classifies each call, and writes a
 * tamper-evident audit record. plumbline is the layer above it. This adapter
 * turns redstamp's audit log into a plumbline trajectory, closing the Own Your
 * Stack loop — the guard that judges each call feeds the monitor that judges the
 * sequence.
 *
 * Two things make redstamp the richest trajectory source:
 *
 *  1. It is the ONLY adapter that natively carries `outcome: "denied"`. redstamp
 *     records a `decision` per call, and `block` maps straight to a denial — so
 *     the `ratchet` detector (a guard refused this, then an equivalent call
 *     succeeded) is fully reachable here, where on other adapters it is a blind
 *     spot. The guard's own refusals become the evidence of evasion.
 *
 *  2. Its audit log is a hash chain: each record commits to the previous one, so
 *     any edit or deletion in the middle breaks the chain. This adapter verifies
 *     that chain and refuses to present a tampered log as trustworthy — directly
 *     addressing plumbline's own "log integrity" threat-model gap (a monitored
 *     agent editing its own trail). The check is inline sha256; no dependency on
 *     redstamp itself, so plumbline stays zero-dependency.
 *
 * redstamp audit record shape (chained via AuditLog, or unchained via cc-hook):
 *   { ts, tool, input?, tier, decision, why[], prev?, hash? }
 * where tool is redstamp's normalized name (shell|write|edit|read|grep|list|
 * fetch|...), decision is allow|approve|block, tier is green|yellow|red|black.
 */

import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { entropyOf } from '../schema.mjs';
import { opOf } from './claude-code.mjs';

const GENESIS = '0'.repeat(64);
/** redstamp's chain function, re-implemented so this adapter needs no redstamp import. */
const hashOf = (prev, rec) => createHash('sha256').update(prev + JSON.stringify(rec)).digest('hex');

/** redstamp tool name -> plumbline action. */
const ACTION_MAP = {
  shell: 'proc.spawn',
  write: 'fs.write',
  edit: 'fs.write',
  read: 'fs.read',
  grep: 'fs.search',
  list: 'fs.search',
  fetch: 'http.request',
};

/** redstamp tool -> the capability its use demonstrates (first exercise = grant). */
const CAPABILITY_MAP = {
  shell: ['exec:local', 'proc:spawn'],
  write: ['fs:write'],
  edit: ['fs:write'],
  read: ['fs:read'],
  grep: ['fs:read'],
  list: ['fs:read'],
  fetch: ['net:egress:read'],
};

const SECRET_RE = /\b(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|glpat-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{12,}|eyJ[A-Za-z0-9_-]{20,})\b/g;
const URL_RE = /\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?/i;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);

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

function hostFromUrl(url) {
  const m = URL_RE.exec(String(url));
  return m ? m[1] : null;
}

/**
 * redstamp `why` lines carry hosts even when the record has no `input`
 * (daemon/cc-hook records omit it): "egress to non-allowlisted host(s): a,b" and
 * "EXFIL: ... -> external a,b". Mine them so egress topology is visible either way.
 */
function hostsFromWhy(why) {
  const hosts = new Set();
  for (const line of why ?? []) {
    const m = /(?:external|host\(s\)?:?)\s+([a-z0-9.,:_-]+)/i.exec(String(line));
    if (m) for (const h of m[1].split(',')) { const t = h.trim(); if (t && !LOCAL_HOSTS.has(t)) hosts.add(t); }
  }
  return [...hosts];
}

function targetFor(tool, input, why) {
  const target = {};
  const inp = input ?? {};

  if (tool === 'shell') {
    const command = inp.command ?? inp.cmd ?? '';
    if (command) target.op = opOf(String(command));
    const host = hostFromUrl(command) || hostsFromWhy(why)[0];
    if (host) { target.host = host; target.external = !LOCAL_HOSTS.has(host); }
    return target;
  }
  if (tool === 'fetch') {
    const host = hostFromUrl(inp.url ?? '') || hostsFromWhy(why)[0];
    if (host) { target.host = host; target.external = !LOCAL_HOSTS.has(host); }
    else { const h = hostsFromWhy(why)[0]; if (h) { target.host = h; target.external = true; } }
    return target;
  }
  if (typeof inp.path === 'string' && inp.path) { target.path = inp.path; return target; }
  if (typeof inp.pattern === 'string' && inp.pattern) { target.path = inp.pattern; return target; }
  // No input on the record (daemon/cc-hook). Still surface any host the why names.
  const h = hostsFromWhy(why)[0];
  if (h) { target.host = h; target.external = true; }
  return target;
}

/**
 * Verify the redstamp hash chain over a set of raw records.
 *
 * @returns {{ chained: boolean, intact: boolean, brokenAt: number|null }}
 *   chained  - the records carry prev/hash at all (cc-hook logs do not)
 *   intact   - every record's hash correctly commits to the previous
 *   brokenAt - index of the first record whose hash does not verify
 */
export function verifyChain(rawRecords) {
  const chained = rawRecords.length > 0 && rawRecords.every((r) => typeof r.hash === 'string' && typeof r.prev === 'string');
  if (!chained) return { chained: false, intact: false, brokenAt: null };

  let prev = GENESIS;
  for (let i = 0; i < rawRecords.length; i++) {
    const { prev: p, hash, ...rec } = rawRecords[i];
    if (p !== prev || hashOf(prev, rec) !== hash) return { chained: true, intact: false, brokenAt: i };
    prev = hash;
  }
  return { chained: true, intact: true, brokenAt: null };
}

/**
 * Optional host-observation sidecar (not part of the redstamp audit schema).
 *
 * Joins by audit entry `hash` plus optional operationId/attemptId. Integrity of
 * the audit chain does **not** prove the observer is truthful — only that the
 * audit bytes were not mid-chain edited. `targetToolInvoked: false` is trusted
 * only when `windowComplete === true`.
 *
 * @typedef {object} HostObservation
 * @property {string} auditHash
 * @property {string} [operationId]
 * @property {string} [attemptId]
 * @property {'accepted'|'declined'|'unknown'} [humanResponse]
 * @property {boolean} [targetToolInvoked]
 * @property {'ok'|'error'|'unknown'} [executorResult]
 * @property {boolean} [windowComplete]
 */

/**
 * Index host observations by auditHash. Wrong op/attempt pairs are kept but
 * marked mismatched so a caller can fail closed.
 *
 * @param {HostObservation[]} observations
 * @returns {Map<string, HostObservation[]>}
 */
export function indexHostObservations(observations = []) {
  const byHash = new Map();
  for (const obs of observations) {
    if (!obs || typeof obs.auditHash !== 'string' || !obs.auditHash.trim()) continue;
    const key = obs.auditHash.trim();
    const list = byHash.get(key) ?? [];
    list.push(obs);
    byHash.set(key, list);
  }
  return byHash;
}

/**
 * Checkpoint shape from redstamp: `{ count, head }` of the audit tip.
 * Chain verify alone cannot catch a truncated tail; compare against this.
 *
 * @returns {{ present: boolean, matches: boolean, reason?: string }}
 */
export function verifyCheckpoint(rawRecords, checkpoint) {
  if (!checkpoint || typeof checkpoint !== 'object') {
    return { present: false, matches: false, reason: 'checkpoint missing' };
  }
  const count = checkpoint.count;
  const head = checkpoint.head;
  if (typeof count !== 'number' || typeof head !== 'string') {
    return { present: true, matches: false, reason: 'checkpoint malformed' };
  }
  if (rawRecords.length !== count) {
    return {
      present: true,
      matches: false,
      reason: `count mismatch: records=${rawRecords.length} checkpoint=${count}`,
    };
  }
  const last = rawRecords[rawRecords.length - 1];
  if (!last || last.hash !== head) {
    return { present: true, matches: false, reason: 'head hash mismatch (possible truncated tail)' };
  }
  return { present: true, matches: true };
}

/**
 * Derive plumbline outcome for one redstamp record, optionally refined by a
 * joined host observation. Acceptance-dependent fields are clearly optional.
 *
 * - block → denied (unchanged)
 * - allow → ok (unchanged)
 * - approve without complete observation → ok + note that invocation is unknown
 * - approve + declined + complete window + not invoked → denied
 * - approve + accepted + invoked → ok (executorResult may still be error)
 */
function outcomeFor(rec, observation) {
  if (rec.decision === 'block') return { outcome: 'denied', host: null };

  if (rec.decision !== 'approve') {
    return { outcome: 'ok', host: null };
  }

  if (!observation) {
    return {
      outcome: 'ok',
      host: {
        status: 'unknown',
        reason: 'approve without host observation — invocation unknown',
      },
    };
  }

  if (observation._join === 'mismatch') {
    return {
      outcome: 'ok',
      host: {
        status: 'unknown',
        reason: 'host observation join mismatch (operationId/attemptId)',
      },
    };
  }

  if (observation.windowComplete !== true) {
    return {
      outcome: 'ok',
      host: {
        status: 'unknown',
        reason: 'incomplete observation window — cannot claim non-invocation',
        humanResponse: observation.humanResponse ?? 'unknown',
      },
    };
  }

  if (observation.humanResponse === 'declined' && observation.targetToolInvoked === false) {
    return {
      outcome: 'denied',
      host: {
        status: 'not_invoked',
        humanResponse: 'declined',
        targetToolInvoked: false,
        windowComplete: true,
      },
    };
  }

  if (observation.humanResponse === 'accepted' && observation.targetToolInvoked === true) {
    return {
      outcome: observation.executorResult === 'error' ? 'error' : 'ok',
      host: {
        status: 'invoked',
        humanResponse: 'accepted',
        targetToolInvoked: true,
        executorResult: observation.executorResult ?? 'unknown',
        windowComplete: true,
      },
    };
  }

  return {
    outcome: 'ok',
    host: {
      status: 'unknown',
      reason: 'approve observation present but not authoritative for non-invocation',
      humanResponse: observation.humanResponse ?? 'unknown',
      targetToolInvoked: observation.targetToolInvoked,
      windowComplete: observation.windowComplete === true,
    },
  };
}

/**
 * Convert redstamp audit records into a plumbline trajectory.
 *
 * @param {object[]} records  parsed redstamp audit entries, in log order
 * @param {object} profile    envelope profile (task/capabilities/egress/budget)
 * @param {{session?: string, hostObservations?: HostObservation[], checkpoint?: {count:number, head:string}}} [opts]
 * @returns {{events: object[], chain: object, checkpoint: object}}
 */
export function recordsToTrajectory(records, profile, {
  session = 'redstamp-audit',
  hostObservations,
  checkpoint,
} = {}) {
  const chain = verifyChain(records);
  const checkpointResult = verifyCheckpoint(records, checkpoint);
  const obsByHash = indexHostObservations(hostObservations);
  const events = [];
  let seq = 0;

  events.push({
    v: 1,
    session,
    seq: seq++,
    action: 'session.declare',
    actor: 'redstamp',
    note: chain.chained
      ? `audit chain ${chain.intact ? 'verified intact' : `BROKEN at record ${chain.brokenAt}`}`
      : 'unchained audit log (cc-hook format) - integrity not cryptographically guaranteed',
    envelope: {
      task: profile.task ?? null,
      capabilities: [...(profile.capabilities ?? [])],
      egress: { allow: [...(profile.egress?.allow ?? [])], mode: profile.egress?.mode ?? 'allowlist' },
      budget: { ...(profile.budget ?? {}) },
    },
  });

  // A broken chain is itself a finding: something edited the audit trail. Emit a
  // denied session.turn-shaped marker so the trajectory carries the tamper flag
  // into scoring rather than only into the declare note.
  if (chain.chained && !chain.intact) {
    events.push({
      v: 1,
      session,
      seq: seq++,
      action: 'audit.tampered',
      actor: 'redstamp',
      target: {},
      outcome: 'error',
      note: `hash chain broken at record ${chain.brokenAt} - the audit trail was altered`,
    });
  }

  if (checkpointResult.present && !checkpointResult.matches) {
    events.push({
      v: 1,
      session,
      seq: seq++,
      action: 'audit.checkpoint_mismatch',
      actor: 'redstamp',
      target: {},
      outcome: 'error',
      note: `audit checkpoint mismatch: ${checkpointResult.reason}`,
    });
  }

  const held = new Set();
  const knownFragments = new Set();

  for (const rec of records) {
    const tool = rec.tool ?? 'unknown';
    const action = ACTION_MAP[tool] ?? 'tool.call';
    const input = rec.input ?? {};

    // Optional host observation — join on audit hash (+ op/attempt when supplied).
    // why[] is treated as tainted; we mine hosts only and never copy it verbatim.
    let observation = null;
    if (typeof rec.hash === 'string') {
      const candidates = obsByHash.get(rec.hash) ?? [];
      observation = candidates.find((o) => {
        const opOk = o.operationId === undefined || o.operationId === rec.operationId;
        const attOk = o.attemptId === undefined || o.attemptId === rec.attemptId;
        return opOk && attOk;
      }) ?? null;
      // Wrong join: observation exists for hash but op/attempt mismatch → unknown.
      if (!observation && candidates.length > 0) {
        observation = {
          auditHash: rec.hash,
          windowComplete: false,
          humanResponse: 'unknown',
          _join: 'mismatch',
        };
      }
    }

    const { outcome, host } = outcomeFor(rec, observation);

    const fresh = (CAPABILITY_MAP[tool] ?? []).filter((c) => !held.has(c));
    for (const c of fresh) held.add(c);

    const event = {
      v: 1,
      session,
      seq: seq++,
      ts: rec.ts ?? undefined,
      actor: 'redstamp',
      action,
      target: targetFor(tool, input, rec.why),
      outcome,
      note: `redstamp: ${tool} tier=${rec.tier ?? '?'} decision=${rec.decision ?? '?'}`,
    };
    if (host) event.host_observation = host;
    if (typeof rec.hash === 'string') event.audit_hash = rec.hash;
    if (fresh.length > 0) event.capability_grant = fresh;

    // Secret movement, hashed so a value seen twice links produce->consume.
    const scannable = typeof input.command === 'string' ? input.command
      : typeof input.content === 'string' ? input.content
        : JSON.stringify(input);
    const secrets = secretsIn(scannable);
    if (secrets.length > 0) {
      const produces = [];
      const consumes = [];
      for (const secret of secrets) {
        const id = fragmentId(secret);
        if (knownFragments.has(id)) { if (!consumes.includes(id)) consumes.push(id); }
        else { knownFragments.add(id); produces.push({ id, len: secret.length, entropy: entropyOf(secret) }); }
      }
      if (produces.length > 0) event.produces = produces;
      if (consumes.length > 0) event.consumes = consumes;
    }

    events.push(event);
  }

  return { events, chain, checkpoint: checkpointResult };
}

/** Read a redstamp audit JSONL file into a trajectory. */
export async function readRedstampAudit(file, profile, opts = {}) {
  const rl = createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  const records = [];
  for await (const line of rl) {
    const raw = line.trim();
    if (raw === '' || raw.startsWith('#')) continue;
    try {
      records.push(JSON.parse(raw));
    } catch {
      // a torn final line on a live-appended log is normal; skip it
    }
  }
  return recordsToTrajectory(records, profile, opts);
}
