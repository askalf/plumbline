/**
 * plumbline — trajectory-level monitoring for autonomous agents.
 *
 * Per-action authorization is necessary and insufficient. An escape can be
 * composed entirely of individually-authorized steps, which is precisely what
 * happened in July 2026 when two models under a cyber-capability evaluation
 * left their sandbox and reached a third party's production infrastructure.
 * Every step was permitted. The sequence was the attack.
 *
 * plumbline scores the sequence against the job it was supposed to be doing.
 */

import { parseTrajectory, normalizeEvent, entropyOf, TrajectoryError } from './schema.mjs';
import { envelopeFrom, normalizeEnvelope, undeclaredEnvelope, envelopeWarnings } from './envelope.mjs';
import { runDetectors, DETECTORS, DETECTOR_IDS } from './detect/index.mjs';
import { score, levelFor, earliestActionable, LEVELS, DEFAULT_THRESHOLDS } from './score.mjs';
import { reachability, summarizeReachability, fieldCensus, DEPENDENCIES, FIELDS } from './reachability.mjs';
import { assessSemantic, buildPrompt, actionLine } from './semantic.mjs';

/**
 * Assess a normalized event list.
 *
 * @param {Array<object>} events
 * @param {{envelope?: object, only?: string[]|null, thresholds?: object}} [options]
 */
export function assess(events, { envelope = null, only = null, thresholds = DEFAULT_THRESHOLDS, extraSignals = [] } = {}) {
  const env = envelope ? normalizeEnvelope(envelope) : envelopeFrom(events);
  const detected = runDetectors(events, env, { only });
  // extraSignals carries the semantic layer's findings, computed asynchronously
  // by the caller (it needs a model) and merged here so it flows through the
  // same noisy-OR scoring as every deterministic signal. The core stays sync.
  const signals = extraSignals.length > 0
    ? [...detected, ...extraSignals].sort((a, b) => a.seq - b.seq)
    : detected;
  const scored = score(signals, { thresholds });
  const reach = reachability(events, { detectorIds: only ?? DETECTOR_IDS });

  return {
    session: events.length > 0 ? events[0].session : null,
    envelope: env,
    events: events.length,
    span: events.length === 0 ? null : { first: events[0].seq, last: events[events.length - 1].seq },
    ...scored,
    earliest_actionable: earliestActionable(scored),
    /**
     * Reachability travels with every verdict, deliberately. A caller that
     * reads `level` without reading `reachability.no_starved_detectors` can mistake
     * "nothing could be found" for "nothing was wrong" — which is exactly the
     * bug this project shipped and then caught three times.
     */
    reachability: reach,
    /**
     * Ways this envelope disables detection. Non-empty means a clean verdict may
     * reflect a permissive policy rather than safe behaviour — the one failure
     * mode neither the liveness controls nor reachability can see, because
     * nothing is broken.
     */
    envelope_warnings: envelopeWarnings(env),
  };
}

/** Assess a JSONL trajectory string. */
export function assessTrajectory(text, options = {}) {
  return assess(parseTrajectory(text), options);
}

/**
 * Assess with the optional semantic layer.
 *
 * Runs the deterministic detectors and the model-backed semantic detector, then
 * merges both into one verdict. This is the only assessment path that can catch
 * the semantic-escape floor — an escape composed entirely of in-envelope actions
 * that simply do not serve the task. It requires a `judge` (see
 * `src/judges/ollama.mjs`); without one it degrades to a plain assessment with a
 * note that the semantic layer did not run, never silently pretending it did.
 *
 * @param {Array<object>} events
 * @param {{judge?: Function, envelope?: object, only?: string[]|null, thresholds?: object}} [options]
 */
export async function assessWithSemantic(events, { judge, ...options } = {}) {
  const env = options.envelope ? normalizeEnvelope(options.envelope) : envelopeFrom(events);
  const semantic = await assessSemantic(events, env, { judge });
  const report = assess(events, { ...options, extraSignals: semantic.signals });

  return {
    ...report,
    semantic: {
      ran: semantic.available,
      error: semantic.error ?? null,
      findings: semantic.signals.length,
    },
  };
}

/** Async convenience over a JSONL string. */
export async function assessTrajectoryWithSemantic(text, options = {}) {
  return assessWithSemantic(parseTrajectory(text), options);
}

export {
  parseTrajectory,
  normalizeEvent,
  entropyOf,
  TrajectoryError,
  envelopeFrom,
  normalizeEnvelope,
  undeclaredEnvelope,
  envelopeWarnings,
  runDetectors,
  DETECTORS,
  DETECTOR_IDS,
  score,
  levelFor,
  earliestActionable,
  LEVELS,
  DEFAULT_THRESHOLDS,
  reachability,
  summarizeReachability,
  fieldCensus,
  DEPENDENCIES,
  FIELDS,
  assessSemantic,
  buildPrompt,
  actionLine,
};
