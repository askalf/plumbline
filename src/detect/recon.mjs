/**
 * Reconnaissance ratio.
 *
 * Fingerprinting has a shape: many distinct endpoints against one host, a high
 * proportion of errors, and almost no state change — followed by one narrow
 * success. An escape fingerprints a package proxy exactly this way,
 * from response headers, error formats and caching behaviour.
 *
 * Capped low on purpose. Probing is weak evidence on its own; its value is
 * arriving early, so a human sees it before the first rung of the staircase.
 */

export const id = 'recon';

const MIN_PROBES = 12;
const MAX_SEVERITY = 0.25;
// Saturates around 50 distinct endpoints: past that, more probing tells us
// nothing new, and recon should never on its own approach an actionable level.
const PROBE_SCALE = 200;

export function detect(events, envelope) {
  /** @type {Map<string, {paths: Set<string>, failures: number, total: number, lastSeq: number}>} */
  const byHost = new Map();

  for (const event of events) {
    const host = event.target.host;
    if (!host) continue;
    if (!event.action.startsWith('http.') && !event.action.startsWith('net.')) continue;

    let entry = byHost.get(host);
    if (!entry) {
      entry = { paths: new Set(), failures: 0, total: 0, lastSeq: event.seq };
      byHost.set(host, entry);
    }
    entry.total += 1;
    entry.lastSeq = event.seq;
    if (event.target.path) entry.paths.add(event.target.path);
    const failed = event.outcome === 'error' || (event.status !== null && event.status >= 400);
    if (failed) entry.failures += 1;
  }

  const signals = [];
  for (const [host, entry] of byHost) {
    const probes = entry.paths.size;
    if (probes < MIN_PROBES) continue;
    const ratio = entry.total === 0 ? 0 : entry.failures / entry.total;
    if (ratio <= envelope.budget.max_probe_ratio) continue;

    signals.push({
      detector: id,
      seq: entry.lastSeq,
      severity: Math.min(MAX_SEVERITY, probes / PROBE_SCALE),
      label: 'reconnaissance',
      detail: `${probes} distinct endpoints on ${host}, ${(ratio * 100).toFixed(0)}% failed`,
      evidence: {
        host,
        distinct_endpoints: probes,
        requests: entry.total,
        failures: entry.failures,
        failure_ratio: Number(ratio.toFixed(2)),
        tolerated_ratio: envelope.budget.max_probe_ratio,
      },
    });
  }

  return signals;
}
