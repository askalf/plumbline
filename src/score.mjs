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

  let survival = 1; // Π(1 - s) — probability nothing has gone wrong yet.
  let previousLevel = 'observe';

  for (const seq of seqs) {
    const atSeq = bySeq.get(seq).sort((a, b) => b.severity - a.severity);
    const dominant = atSeq[0];

    survival *= 1 - dominant.severity;
    const drift = 1 - survival;
    const level = levelFor(drift, thresholds);

    for (const name of ['warn', 'confirm', 'halt']) {
      if (crossings[name] === null && drift >= thresholds[name]) crossings[name] = seq;
    }

    timeline.push({
      seq,
      drift: round(drift),
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
    drift: round(drift),
    level: levelFor(drift, thresholds),
    timeline,
    crossings,
    thresholds,
    signals,
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
