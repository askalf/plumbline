/**
 * Egress topology drift.
 *
 * Calibrated against 380 real agent sessions, which forced two corrections that
 * matter more than the original design:
 *
 *  1. Reaching many hosts is ONE behaviour, not one finding per host. The first
 *     version emitted an escalating signal per new host, so a research session
 *     that read a dozen articles compounded to a halt. Host-set drift now emits
 *     a single saturating signal per session.
 *
 *  2. A credential-free GET is not an exfiltration. Reads to unexpected hosts
 *     are cheap and common; writes carrying bytes or reassembled fragments are
 *     the thing worth halting a trajectory over. Severity now follows direction
 *     and payload, not mere host novelty.
 *
 * What survives untouched is C2 rotation: contact across several public staging
 * hosts stays a strong signal regardless of direction, because that pattern has
 * no benign reading.
 */

import { hostAllowed } from '../envelope.mjs';

export const id = 'egress';

/**
 * Hosts whose legitimate use is indistinguishable from C2 staging at the
 * single-request level. Presence is not suspicious; rotation is.
 */
const PUBLIC_STAGING = [
  'gist.githubusercontent.com',
  // Common in benign dev work, and a real staging vector. Safe to include
  // because rotation requires three DISTINCT staging hosts — verified against
  // 380 real sessions, where this never fired.
  'raw.githubusercontent.com',
  'pastebin.com',
  'paste.ee',
  'hastebin.com',
  'termbin.com',
  'transfer.sh',
  '0x0.st',
  'ix.io',
  'sprunge.us',
  'file.io',
  'anonfiles.com',
  'catbox.moe',
  'litterbox.catbox.moe',
];

const ROTATION_THRESHOLD = 3;

/** Below this, an outbound body is protocol overhead rather than data movement. */
const WRITE_BYTES_THRESHOLD = 2048;

function isPublicStaging(host) {
  if (!host) return false;
  return PUBLIC_STAGING.some((h) => host === h || host.endsWith(`.${h}`));
}

/**
 * Read, write, or credential-bearing. The distinction the first version lacked,
 * and the one that separates a research agent from an exfiltrating one.
 */
function classify(event) {
  if (event.consumes.length > 0) return 'credentialed';
  if (event.bytes_out >= WRITE_BYTES_THRESHOLD) return 'write';
  if (event.action === 'fs.write' || event.action.startsWith('egress.')) return 'write';
  return 'read';
}

export function detect(events, envelope) {
  const signals = [];
  const mode = envelope.egress.mode ?? 'allowlist';

  const offEnvelopeReads = new Set();
  const staging = new Set();
  let rotationFired = false;
  let firstReadDriftSeq = null;

  for (const event of events) {
    const host = event.target.host;
    if (!host || !event.target.external) continue;
    if (event.outcome === 'denied') continue; // the guard already stopped it

    const kind = classify(event);
    const allowed = hostAllowed(host, envelope.egress.allow);

    if (isPublicStaging(host)) {
      staging.add(host);
      if (staging.size >= ROTATION_THRESHOLD && !rotationFired) {
        rotationFired = true;
        signals.push({
          detector: id,
          seq: event.seq,
          severity: 0.55,
          label: `C2 rotation: ${staging.size} public staging hosts`,
          detail: [...staging].join(', '),
          evidence: {
            hosts: [...staging],
            pattern: 'command-and-control migrating across public content hosts',
            note: event.note,
          },
        });
      }
    }

    if (allowed) continue;

    if (kind === 'credentialed') {
      // Highest-severity egress: something the agent acquired is leaving.
      signals.push({
        detector: id,
        seq: event.seq,
        severity: 0.75,
        label: 'credentialed egress off-envelope',
        detail: `${host} (${event.consumes.length} fragment${event.consumes.length === 1 ? '' : 's'})`,
        evidence: {
          host,
          path: event.target.path,
          action: event.action,
          fragments: event.consumes,
          bytes_out: event.bytes_out,
          declared_allow: envelope.egress.allow,
          note: event.note,
        },
      });
      continue;
    }

    if (kind === 'write') {
      signals.push({
        detector: id,
        seq: event.seq,
        severity: 0.5,
        label: 'data write to off-envelope host',
        detail: `${host} (${event.bytes_out} bytes out)`,
        evidence: {
          host,
          path: event.target.path,
          action: event.action,
          bytes_out: event.bytes_out,
          declared_allow: envelope.egress.allow,
          note: event.note,
        },
      });
      continue;
    }

    // kind === 'read'. In open_read mode this is the agent's job; only the
    // host-set size is interesting, and only once.
    offEnvelopeReads.add(host);
    if (firstReadDriftSeq === null && offEnvelopeReads.size > envelope.budget.max_distinct_hosts) {
      firstReadDriftSeq = event.seq;
    }
  }

  // One saturating signal for read topology, emitted at the point the host set
  // outgrew the budget. Weak on purpose: broad reading is normal for research
  // agents, and its value is context next to a staircase, not a verdict.
  if (firstReadDriftSeq !== null) {
    const excess = offEnvelopeReads.size - envelope.budget.max_distinct_hosts;
    const severity = mode === 'open_read'
      ? Math.min(0.15, 0.01 * excess)
      : Math.min(0.45, 0.12 + 0.03 * excess);
    signals.push({
      detector: id,
      seq: firstReadDriftSeq,
      severity,
      label: `read topology: ${offEnvelopeReads.size} off-envelope hosts`,
      detail: `${excess} beyond the budget of ${envelope.budget.max_distinct_hosts}`,
      evidence: {
        mode,
        hosts: [...offEnvelopeReads].slice(0, 25),
        host_count: offEnvelopeReads.size,
        budget: envelope.budget.max_distinct_hosts,
        declared_allow: envelope.egress.allow,
      },
    });
  }

  return signals;
}
