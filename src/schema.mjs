/**
 * Trajectory event validation and normalization.
 *
 * Deliberately not a general JSON Schema engine — plumbline is zero-dependency,
 * so this hand-checks the constraints that actually protect the detectors from
 * malformed input. `schema/trajectory.schema.json` remains the published contract
 * for other implementations; this is the runtime guard for ours.
 */

const ACTION_RE = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
const OUTCOMES = new Set(['ok', 'error', 'denied']);

export class TrajectoryError extends Error {
  constructor(message, { line, event } = {}) {
    super(line == null ? message : `line ${line}: ${message}`);
    this.name = 'TrajectoryError';
    this.line = line ?? null;
    this.event = event ?? null;
  }
}

/**
 * Shannon entropy in bits/char. Exposed for adapters: they measure real values
 * and emit only the measurement, so a secret never reaches plumbline itself.
 */
export function entropyOf(value) {
  const s = String(value);
  if (s.length === 0) return 0;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function requireString(event, field, { optional = false } = {}) {
  const v = event[field];
  if (v === undefined) {
    if (optional) return null;
    throw new TrajectoryError(`missing required field "${field}"`, { event });
  }
  if (typeof v !== 'string' || v.length === 0) {
    throw new TrajectoryError(`"${field}" must be a non-empty string`, { event });
  }
  return v;
}

function normalizeFragments(event) {
  const raw = event.produces;
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    throw new TrajectoryError('"produces" must be an array', { event });
  }
  return raw.map((f) => {
    if (f === null || typeof f !== 'object' || Array.isArray(f)) {
      throw new TrajectoryError('"produces" entries must be objects', { event });
    }
    if (typeof f.id !== 'string' || f.id.length === 0) {
      throw new TrajectoryError('"produces" entries require a non-empty id', { event });
    }
    return {
      id: f.id,
      len: Number.isFinite(f.len) ? f.len : 0,
      entropy: Number.isFinite(f.entropy) ? f.entropy : 0,
    };
  });
}

/** Validate and normalize one event into the shape detectors consume. */
export function normalizeEvent(event, { line } = {}) {
  if (event === null || typeof event !== 'object' || Array.isArray(event)) {
    throw new TrajectoryError('event must be an object', { line, event });
  }
  if (event.v !== 1) {
    throw new TrajectoryError(`unsupported schema version ${JSON.stringify(event.v)}`, { line, event });
  }

  let session, action;
  try {
    session = requireString(event, 'session');
    action = requireString(event, 'action');
  } catch (err) {
    throw new TrajectoryError(err.message, { line, event });
  }

  if (!ACTION_RE.test(action)) {
    throw new TrajectoryError(`action "${action}" is not a dotted lowercase verb`, { line, event });
  }
  if (!Number.isInteger(event.seq) || event.seq < 0) {
    throw new TrajectoryError('"seq" must be a non-negative integer', { line, event });
  }
  if (event.outcome !== undefined && !OUTCOMES.has(event.outcome)) {
    throw new TrajectoryError(`outcome "${event.outcome}" is not ok|error|denied`, { line, event });
  }

  const target = event.target ?? {};
  if (target === null || typeof target !== 'object' || Array.isArray(target)) {
    throw new TrajectoryError('"target" must be an object', { line, event });
  }

  const consumes = event.consumes ?? [];
  if (!Array.isArray(consumes) || consumes.some((id) => typeof id !== 'string')) {
    throw new TrajectoryError('"consumes" must be an array of strings', { line, event });
  }

  const grants = event.capability_grant ?? [];
  if (!Array.isArray(grants) || grants.some((c) => typeof c !== 'string')) {
    throw new TrajectoryError('"capability_grant" must be an array of strings', { line, event });
  }

  return {
    v: 1,
    session,
    seq: event.seq,
    ts: event.ts ?? null,
    actor: event.actor ?? null,
    instance: event.instance ?? null,
    action,
    target: {
      host: typeof target.host === 'string' ? target.host : null,
      path: typeof target.path === 'string' ? target.path : null,
      // Operation identity: the invoked binary for a shell action, the method
      // for an API call. Load-bearing for ratchet detection — without it every
      // shell command in a session is indistinguishable from every other.
      op: typeof target.op === 'string' ? target.op : null,
      external: target.external === true,
    },
    outcome: event.outcome ?? 'ok',
    status: Number.isInteger(event.status) ? event.status : null,
    bytes_in: Number.isFinite(event.bytes_in) ? event.bytes_in : 0,
    bytes_out: Number.isFinite(event.bytes_out) ? event.bytes_out : 0,
    capability_grant: grants,
    produces: normalizeFragments(event),
    consumes,
    envelope: event.envelope ?? null,
    note: typeof event.note === 'string' ? event.note : null,
  };
}

/**
 * Parse a JSONL trajectory. Blank lines and `#` comments are skipped so corpus
 * files can carry inline annotation.
 */
export function parseTrajectory(text) {
  const events = [];
  const lines = String(text).split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (raw === '' || raw.startsWith('#')) continue;
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      throw new TrajectoryError(`invalid JSON (${err.message})`, { line: i + 1 });
    }
    events.push(normalizeEvent(parsed, { line: i + 1 }));
  }

  const sessions = new Set(events.map((e) => e.session));
  if (sessions.size > 1) {
    throw new TrajectoryError(
      `trajectory mixes ${sessions.size} sessions (${[...sessions].join(', ')}); split them first`,
    );
  }
  return events;
}
