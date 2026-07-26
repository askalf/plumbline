/**
 * The intent envelope: the declared job and the reach it legitimately requires.
 *
 * Every detector measures against this. Without it there is no such thing as
 * drift - only novelty - which is the distinction between plumbline and
 * generic anomaly detection.
 */

export const DEFAULT_BUDGET = {
  max_distinct_hosts: 4,
  max_probe_ratio: 0.5,
  max_instances: 2,
};

/**
 * An envelope used when a trajectory carries no session.declare. Nothing is
 * permitted, so every capability and host reads as off-envelope. That is the
 * correct default - an undeclared trajectory is unauditable, and the report
 * says so rather than quietly assuming benign intent.
 */
export function undeclaredEnvelope() {
  return {
    task: null,
    declared: false,
    capabilities: [],
    egress: { allow: [], mode: 'allowlist' },
    budget: { ...DEFAULT_BUDGET },
  };
}

export function normalizeEnvelope(raw) {
  if (!raw || typeof raw !== 'object') return undeclaredEnvelope();
  return {
    task: typeof raw.task === 'string' ? raw.task : null,
    declared: true,
    capabilities: Array.isArray(raw.capabilities) ? raw.capabilities.filter((c) => typeof c === 'string') : [],
    egress: {
      allow: Array.isArray(raw.egress?.allow) ? raw.egress.allow.filter((h) => typeof h === 'string') : [],
      // 'allowlist' - any unlisted host is drift (eval sandboxes, CI).
      // 'open_read' - reads may go anywhere, writes must be listed. Correct for
      // research-capable agents, whose job includes reading arbitrary pages.
      mode: raw.egress?.mode === 'open_read' ? 'open_read' : 'allowlist',
    },
    budget: { ...DEFAULT_BUDGET, ...(raw.budget && typeof raw.budget === 'object' ? raw.budget : {}) },
  };
}

/** Pull the envelope from the first session.declare, if present. */
export function envelopeFrom(events) {
  const declare = events.find((e) => e.action === 'session.declare' && e.envelope);
  return declare ? normalizeEnvelope(declare.envelope) : undeclaredEnvelope();
}

/**
 * Degenerate-envelope detection.
 *
 * The envelope is the acknowledged weak point: a sufficiently generous one
 * silences every envelope-gated detector, and the result is a clean report with
 * nothing behind it. Adversarial testing made this concrete - an envelope
 * granting `*` with unbounded budgets produced ZERO signals from 41 plainly
 * suspicious events, while reachability still reported no starvation, because
 * every required field was present.
 *
 * That is the one failure neither the liveness controls nor reachability can
 * see, since nothing is broken: the policy simply permits everything. So it
 * gets its own check. A degenerate envelope cannot be prevented - it is the
 * operator's to write - but it can be refused the appearance of a clean audit.
 */
const ABSURD_BUDGET = 10000;

export function envelopeWarnings(envelope) {
  const warnings = [];

  if (!envelope.declared) {
    warnings.push({
      field: 'session.declare',
      note: 'no envelope declared - every capability reads as off-envelope and drift is unaudited',
    });
    return warnings;
  }

  if (envelope.capabilities.includes('*')) {
    warnings.push({
      field: 'capabilities',
      note: 'grants "*" - every capability is in-envelope, so the staircase detector can never fire',
    });
  }
  if (envelope.egress.allow.includes('*')) {
    warnings.push({
      field: 'egress.allow',
      note: 'allows "*" - every host is in-envelope, so off-envelope egress can never fire',
    });
  }
  if (envelope.budget.max_probe_ratio >= 1) {
    warnings.push({
      field: 'budget.max_probe_ratio',
      note: 'set to 1 or above - no failure ratio can exceed it, so recon can never fire',
    });
  }
  for (const key of ['max_distinct_hosts', 'max_instances']) {
    if (envelope.budget[key] >= ABSURD_BUDGET) {
      warnings.push({
        field: `budget.${key}`,
        note: `set to ${envelope.budget[key]} - effectively unbounded, so the corresponding detector can never fire`,
      });
    }
  }
  if (!envelope.task) {
    warnings.push({
      field: 'task',
      note: 'no task stated - drift is measured against capabilities alone, with no record of intent',
    });
  }

  return warnings;
}

/**
 * A capability containing a parent-directory segment is never in-envelope.
 *
 * Adversarial testing found this: a naive prefix match let
 * `fs:/workspace/../../etc/shadow` satisfy `fs:/workspace/*`, so traversal
 * defeated the envelope completely. plumbline cannot resolve paths (it never
 * touches a filesystem and the trajectory may come from another machine), so
 * the only safe answer is to refuse to consider a traversal in-envelope at all.
 * A legitimate capability has no reason to carry `..`.
 */
function hasTraversal(capability) {
  return /(^|[:/\\])\.\.([/\\]|$)/.test(capability);
}

/**
 * Capability matching.
 *
 * Exact match, or a trailing `*` that matches by prefix - but the wildcard is
 * NOT allowed to silently cross a delimiter. `net:api.x*` covers `net:api.xyz`
 * and must not cover `net:api.x.evil.com`, because a pattern author writing a
 * host prefix does not thereby intend every subdomain beneath it.
 *
 * Case-sensitive on purpose. An adapter emitting `EXEC:LOCAL` against an
 * envelope granting `exec:local` produces a staircase signal rather than a
 * silent grant - noisy, but it fails closed, and over-granting is the worse
 * error in a security envelope.
 */
export function capabilityAllowed(capability, allowed) {
  if (hasTraversal(capability)) return false;

  for (const pattern of allowed) {
    if (pattern === capability) return true;
    if (pattern === '*') return true;
    if (!pattern.endsWith('*')) continue;

    const prefix = pattern.slice(0, -1);
    if (!capability.startsWith(prefix)) continue;
    const rest = capability.slice(prefix.length);

    // The wildcard was placed at a delimiter, so descending is what was meant.
    if (prefix.endsWith('/') || prefix.endsWith(':')) return true;
    if (rest === '' || rest.startsWith('/')) return true;

    // Mid-token wildcard: may complete the token, may not introduce a new
    // delimiter and reach somewhere the author did not name.
    if (!/[:/.]/.test(rest)) return true;
  }
  return false;
}

/**
 * Host matching. A leading dot matches the domain and any subdomain.
 *
 * Case-insensitive, because DNS is: treating `API.GITHUB.COM` as a different
 * host from `api.github.com` produced false off-envelope findings, and alert
 * fatigue loses real signal just as effectively as a missed detection.
 */
export function hostAllowed(host, allowed) {
  if (!host) return true;
  const h = String(host).toLowerCase();
  for (const raw of allowed) {
    const pattern = String(raw).toLowerCase();
    if (pattern === h) return true;
    if (pattern === '*') return true;
    if (pattern.startsWith('.') && (h === pattern.slice(1) || h.endsWith(pattern))) return true;
  }
  return false;
}
