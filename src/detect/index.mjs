/**
 * Detector registry.
 *
 * Every detector is a pure function of (events, envelope) returning signals, so
 * it can be re-run over a growing prefix for streaming use without changing its
 * contract. Order here is presentation order only; scoring is order-independent.
 */

import * as recon from './recon.mjs';
import * as staircase from './staircase.mjs';
import * as reassembly from './reassembly.mjs';
import * as egress from './egress.mjs';
import * as ratchet from './ratchet.mjs';
import * as fanout from './fanout.mjs';

export const DETECTORS = [recon, staircase, reassembly, egress, ratchet, fanout];

export const DETECTOR_IDS = DETECTORS.map((d) => d.id);

/**
 * Run every detector (or a named subset) and return signals in sequence order.
 *
 * An unknown name in `only` throws. Silently filtering it produced the worst
 * possible interface failure: `--only=stiarcase` ran ZERO detectors and
 * reported clean, so a typo looked exactly like a passing scan.
 */
export function runDetectors(events, envelope, { only = null } = {}) {
  if (only) {
    const unknown = only.filter((id) => !DETECTOR_IDS.includes(id));
    if (unknown.length > 0) {
      throw new Error(
        `unknown detector(s): ${unknown.join(', ')}. Known: ${DETECTOR_IDS.join(', ')}`,
      );
    }
    if (only.length === 0) throw new Error('an empty detector selection would report clean without checking anything');
  }
  const active = only ? DETECTORS.filter((d) => only.includes(d.id)) : DETECTORS;
  const signals = [];
  for (const detector of active) {
    for (const signal of detector.detect(events, envelope)) signals.push(signal);
  }
  return signals.sort((a, b) => a.seq - b.seq || a.detector.localeCompare(b.detector));
}

export { recon, staircase, reassembly, egress, ratchet, fanout };
