// Fuzz target: schema normalization over arbitrary JSON, and the entropy
// invariant.
//
// normalizeEvent() is the per-event guard that stands between an arbitrary
// parsed JSON object and the detectors. Its contract is controlled failure:
// TrajectoryError on anything malformed, a normalized event otherwise — never
// a bare TypeError from indexing a hostile shape (an array where an object was
// expected, a null field, a number where a string was expected).
//
// entropyOf() feeds fragment severity; a NaN or negative result there is the
// upstream of the "malformed severity -> escape reads as observe" bug, so it
// gets a hard invariant on every input.
import { normalizeEvent, entropyOf, TrajectoryError } from '../src/schema.mjs';

export function fuzz(data) {
  const s = data.toString('utf8');

  const h = entropyOf(s);
  if (!Number.isFinite(h) || h < 0) {
    throw new Error(`entropyOf returned a non-finite/negative value: ${h}`);
  }

  let obj;
  try {
    obj = JSON.parse(s);
  } catch {
    return; // not JSON — nothing to normalize
  }

  try {
    normalizeEvent(obj);
  } catch (err) {
    if (err instanceof TrajectoryError || err?.name === 'TrajectoryError') return;
    throw err; // any non-TrajectoryError throw is a real bug
  }
}
