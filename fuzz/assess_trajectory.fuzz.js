// Fuzz target: the full parse -> score pipeline over raw, untrusted JSONL.
//
// assessTrajectory(text) is the primary entry point and the widest attack
// surface — a caller feeds it a trajectory log that an agent (or an attacker
// shaping that agent's behaviour) influenced. The contract at this boundary is
// "controlled failure only": on malformed input it may raise TrajectoryError,
// and on well-formed input it returns a report — but it must NEVER throw
// anything else (TypeError, RangeError, a stack overflow) and must never hang.
// Any other throw is a way to crash or blind the monitor with a crafted log.
import { assessTrajectory } from '../src/index.mjs';
import { TrajectoryError } from '../src/schema.mjs';

export function fuzz(data) {
  let report;
  try {
    report = assessTrajectory(data.toString('utf8'));
  } catch (err) {
    // The one sanctioned failure mode. Everything else is a real bug.
    if (err instanceof TrajectoryError || err?.name === 'TrajectoryError') return;
    throw err;
  }

  // A returned verdict must be well-formed: a NaN drift or an out-of-range
  // level is the exact bug class (see the "malformed severity" CI gate) that
  // makes an escape read as "observe".
  const LEVELS = new Set(['observe', 'warn', 'confirm', 'halt']);
  if (!LEVELS.has(report.level)) {
    throw new Error(`assessTrajectory returned an unknown level: ${report.level}`);
  }
  if (!Number.isFinite(report.drift)) {
    throw new Error(`assessTrajectory returned a non-finite drift: ${report.drift}`);
  }
}
