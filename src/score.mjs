/**
 * Drift scoring.
 *
 * Two rules carry all the meaning:
 *
 *  1. Within one action, take the strongest signal — never compound. Several
 *     detectors firing on the same event are describing one thing from
 *     different angles; compounding there would let an unremarkable action
 *     score like an escape.
 *
 *  2. Across actions, combine by noisy-OR: drift = 1 - Π(1 - s). Each step
 *     contributes independently, the score rises monotonically, and it
 *     saturates toward 1 instead of running away. This is what makes a
 *     staircase read as a staircase — four authorized rungs compound into a
 *     verdict no single rung would justify.
 *
 * Output is a drift timeline and a level, never allow/deny. The consumer
 * decides what a level means; plumbline's job is to be right about the shape.
 */

export const LEVELS = ['observe', 'warn', 'confirm', 'halt'];

export const DEFAULT_THRESHOLDS = {
  warn: 0.25,
  confirm: 0.5,
  halt: 0.85,
};

export function levelFor(drift, thresholds = DEFAULT_THRESHOLDS) {
  if (drift >= thresholds.halt) return 'halt';
  if (drift >= thresholds.confirm) return 'confirm';
  if (drift >= thresholds.warn) return 'warn';
  return 'observe';
}

function round(n) {
  return Number(n.toFixed(4));
}

/**
 * Sanitize a detector's severity.
 *
 * Adversarial testing found three fail-opens here, all reachable from a single
 * buggy detector:
 *
 *   - a NEGATIVE severity *lowered* accumulated drift, letting one detector
 *     suppress the findings of others;
 *   - a severity above 1 pushed drift past 1 and inverted the survival term;
 *   - a NaN made drift NaN, and since every `>=` comparison against NaN is
 *     false, `levelFor` returned "observe" — a malformed signal silently
 *     cleared an escape.
 *
 * Non-finite values are clamped to 0 AND recorded, never silently dropped: the
 * report marks the assessment anomalous so a clean verdict produced alongside a
 * malformed signal can never be read as a clean verdict.
 */
function sanitizeSeverity(raw, anomalies, signal) {
  if (typeof raw !== 'number' || !Number.isFinite(raw)) {
    anomalies.push({
      detector: signal.detector,
      seq: signal.seq,
      reason: `non-finite severity ${String(raw)} - treated as 0`,
    });
    return 0;
  }
  if (raw < 0) {
    anomalies.push({
      detector: signal.detector,
      seq: signal.seq,
      reason: `negative severity ${raw} - clamped to 0`,
    });
    return 0;
  }
  if (raw > 1) {
    anomalies.push({
      detector: signal.detector,
      seq: signal.seq,
      reason: `severity ${raw} above 1 - clamped to 1`,
    });
    return 1;
  }
  return raw;
}

/**
 * @param {Array<object>} signals - from runDetectors()
 * @returns {{drift: number, level: string, timeline: Array<object>, crossings: object, signals: Array<object>}}
 */
export function score(signals, { thresholds = DEFAULT_THRESHOLDS } = {}) {
  /** @type {Map<number, Array<object>>} */
  const bySeq = new Map();
  for (const signal of signals) {
    const bucket = bySeq.get(signal.seq);
    if (bucket) bucket.push(signal);
    else bySeq.set(signal.seq, [signal]);
  }

  const seqs = [...bySeq.keys()].sort((a, b) => a - b);
  const timeline = [];
  const crossings = { warn: null, confirm: null, halt: null };
  const anomalies = [];

  let survival = 1; // Π(1 - s) — probability nothing has gone wrong yet.
  let previousLevel = 'observe';

  for (const seq of seqs) {
    const atSeq = bySeq.get(seq)
      .map((s) => ({ ...s, severity: sanitizeSeverity(s.severity, anomalies, s) }))
      .sort((a, b) => b.severity - a.severity);
    const dominant = atSeq[0];

    survival *= 1 - dominant.severity;
    // Level and crossings are derived from the SAME rounded value that gets
    // displayed. Using the raw value made a report show drift 0.25 while
    // labelling it "observe", because 0.24999 rounds up for display but sits
    // below the threshold in the comparison. A security report whose own two
    // numbers disagree teaches the reader to distrust both.
    const drift = round(1 - survival);
    const level = levelFor(drift, thresholds);

    for (const name of ['warn', 'confirm', 'halt']) {
      if (crossings[name] === null && drift >= thresholds[name]) crossings[name] = seq;
    }

    timeline.push({
      seq,
      drift,
      level,
      escalated: level !== previousLevel,
      dominant: {
        detector: dominant.detector,
        label: dominant.label,
        detail: dominant.detail ?? null,
        severity: round(dominant.severity),
      },
      signals: atSeq.map((s) => ({
        detector: s.detector,
        label: s.label,
        detail: s.detail ?? null,
        severity: round(s.severity),
        evidence: s.evidence ?? null,
      })),
    });

    previousLevel = level;
  }

  const drift = timeline.length === 0 ? 0 : timeline[timeline.length - 1].drift;

  return {
    drift,
    level: levelFor(drift, thresholds),
    timeline,
    crossings,
    thresholds,
    signals,
    /**
     * Malformed severities encountered while scoring. Non-empty means at least
     * one detector emitted a value that could have corrupted the score, so the
     * verdict must not be read as authoritative.
     */
    anomalies,
  };
}

/**
 * The number that matters operationally: the first point a human could have
 * acted. A monitor that only reaches certainty at the last rung has told you
 * nothing you could have used.
 */
export function earliestActionable(scored) {
  return scored.crossings.warn;
}
