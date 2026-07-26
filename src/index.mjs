/**
 * plumbline — trajectory-level monitoring for autonomous agents.
 *
 * Per-action authorization is necessary and insufficient. An escape can be
 * composed entirely of individually-authorized steps, which is precisely what
 * happened when OpenAI's models left an evaluation sandbox in July 2026 and
 * reached a third party's production infrastructure. Every step was permitted.
 * The sequence was the attack.
 *
 * plumbline scores the sequence against the job it was supposed to be doing.
 */

import { parseTrajectory, normalizeEvent, entropyOf, TrajectoryError } from './schema.mjs';
import { envelopeFrom, normalizeEnvelope, undeclaredEnvelope } from './envelope.mjs';
import { runDetectors, DETECTORS, DETECTOR_IDS } from './detect/index.mjs';
import { score, levelFor, earliestActionable, LEVELS, DEFAULT_THRESHOLDS } from './score.mjs';

/**
 * Assess a normalized event list.
 *
 * @param {Array<object>} events
 * @param {{envelope?: object, only?: string[]|null, thresholds?: object}} [options]
 */
export function assess(events, { envelope = null, only = null, thresholds = DEFAULT_THRESHOLDS } = {}) {
  const env = envelope ? normalizeEnvelope(envelope) : envelopeFrom(events);
  const signals = runDetectors(events, env, { only });
  const scored = score(signals, { thresholds });

  return {
    session: events.length > 0 ? events[0].session : null,
    envelope: env,
    events: events.length,
    span: events.length === 0 ? null : { first: events[0].seq, last: events[events.length - 1].seq },
    ...scored,
    earliest_actionable: earliestActionable(scored),
  };
}

/** Assess a JSONL trajectory string. */
export function assessTrajectory(text, options = {}) {
  return assess(parseTrajectory(text), options);
}

export {
  parseTrajectory,
  normalizeEvent,
  entropyOf,
  TrajectoryError,
  envelopeFrom,
  normalizeEnvelope,
  undeclaredEnvelope,
  runDetectors,
  DETECTORS,
  DETECTOR_IDS,
  score,
  levelFor,
  earliestActionable,
  LEVELS,
  DEFAULT_THRESHOLDS,
};
