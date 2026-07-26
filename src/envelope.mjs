/**
 * The intent envelope: the declared job and the reach it legitimately requires.
 *
 * Every detector measures against this. Without it there is no such thing as
 * drift — only novelty — which is the distinction between plumbline and
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
 * correct default — an undeclared trajectory is unauditable, and the report
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
      // 'allowlist' — any unlisted host is drift (eval sandboxes, CI).
      // 'open_read' — reads may go anywhere, writes must be listed. Correct for
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
 * Capability matching. A pattern ending in `*` matches by prefix, so
 * `fs:/workspace/*` covers `fs:/workspace/src/index.mjs`. Everything else is
 * exact — capability grammar is deliberately not a glob language, because a
 * permissive matcher here silently widens the envelope.
 */
export function capabilityAllowed(capability, allowed) {
  for (const pattern of allowed) {
    if (pattern === capability) return true;
    if (pattern.endsWith('*') && capability.startsWith(pattern.slice(0, -1))) return true;
  }
  return false;
}

/** Host matching. A leading dot matches the domain and any subdomain. */
export function hostAllowed(host, allowed) {
  if (!host) return true;
  for (const pattern of allowed) {
    if (pattern === host) return true;
    if (pattern === '*') return true;
    if (pattern.startsWith('.') && (host === pattern.slice(1) || host.endsWith(pattern))) return true;
  }
  return false;
}
