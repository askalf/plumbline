/**
 * Ratchet detection — an agent reshaping a blocked action until it passes.
 *
 * A per-call guard is stateless by construction: it sees a denial, then later
 * sees a request it approves, and has no way to know the second was a reshaped
 * version of the first. Across a trajectory that pattern is obvious, and it is
 * the single clearest signal that an agent is treating a gate as an obstacle
 * rather than a boundary.
 *
 * Note this fires on *evasion*, not on retry: a denial followed by the same
 * request denied again is normal. A denial followed by a semantically
 * equivalent success is not.
 */

export const id = 'ratchet';

const MIN_DENIALS = 2;
const MAX_SEVERITY = 0.7;
const PER_DENIAL = 0.2;

/**
 * Equivalence key: coarse enough that rewording cannot defeat it, specific
 * enough that unrelated actions do not collide.
 *
 * `target.op` is what makes this work for shell actions. Calibration against
 * 380 real sessions found 98 false ratchets because every `proc.spawn` in a
 * session hashed to one key — a denied `docker exec` followed by an unrelated
 * `ls` read as evasion. With `op` carrying the invoked binary, a denial is only
 * compared against later attempts at the same operation.
 *
 * An action with neither a host, a path, nor an op is not comparable, and
 * returns null rather than colliding with every other bare action.
 */
function intentKey(event) {
  const host = event.target.host ?? null;
  const op = event.target.op ?? null;
  const firstSegment = (event.target.path ?? '').split('/').filter(Boolean)[0] ?? null;
  if (host === null && op === null && firstSegment === null) return null;
  return `${event.action}|${host ?? '-'}|${op ?? '-'}|${firstSegment ?? '-'}`;
}

export function detect(events) {
  const signals = [];
  /** @type {Map<string, {count: number, seqs: number[]}>} */
  const denials = new Map();

  for (const event of events) {
    // Oversight resets the ratchet — but only oversight the agent cannot forge.
    //
    // A denial followed by a success is only evasion if the agent got there on
    // its own. If a human turn intervened, the operator adjudicated the denial
    // and the retry carries their authority — by construction that is not an
    // agent routing around a gate. This rule removed the large majority of
    // ratchet findings across 380 real sessions.
    //
    // Adversarial testing then found the obvious abuse: a `session.turn` emitted
    // by the AGENT laundered its own evasion, wiping the denial history that
    // proved it. So the reset requires `actor: "human"`. An unattributed or
    // agent-attributed turn is ignored, and the detector keeps counting.
    //
    // This does not defend against a forged `actor` field — an adapter reading
    // a log the agent can write inherits that log's integrity, which SECURITY.md
    // states is out of scope. It does close the in-band case, where the agent
    // merely emits an event the schema already permits it to emit.
    if (event.action === 'session.turn') {
      if (event.actor === 'human') denials.clear();
      continue;
    }

    const key = intentKey(event);
    if (key === null) continue;

    if (event.outcome === 'denied') {
      const entry = denials.get(key) ?? { count: 0, seqs: [] };
      entry.count += 1;
      entry.seqs.push(event.seq);
      denials.set(key, entry);
      continue;
    }

    if (event.outcome !== 'ok') continue;
    const prior = denials.get(key);
    if (!prior || prior.count < MIN_DENIALS) continue;

    signals.push({
      detector: id,
      seq: event.seq,
      severity: Math.min(MAX_SEVERITY, PER_DENIAL * prior.count),
      label: `ratchet: ${prior.count} denials then success`,
      detail: [event.target.op, event.target.host, event.action]
        .filter(Boolean)
        .slice(0, 2)
        .join(' on ') || event.action,
      evidence: {
        intent_key: key,
        denied_at_seqs: [...prior.seqs],
        succeeded_at_seq: event.seq,
        action: event.action,
        host: event.target.host,
        path: event.target.path,
        note: event.note,
      },
    });
    denials.delete(key);
  }

  return signals;
}
