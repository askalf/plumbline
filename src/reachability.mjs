/**
 * Detector reachability.
 *
 * The structural answer to the failure mode that has bitten this project three
 * times: a detector that is registered, correct, and completely unable to fire
 * because nothing feeds it the field it reads. Every corpus then reports clean,
 * and a clean report from a starved detector is indistinguishable from a clean
 * report from a working one.
 *
 *   1. `staircase` reads only `capability_grant` — no adapter emitted it.
 *   2. `reassembly` needs `consumes` — no adapter emitted it.
 *   3. The liveness guard written to catch (1) derived its expected set from
 *      the registry it was checking, so it could not fail.
 *
 * So: every detector declares the event fields it depends on, and reachability
 * is computed from the events actually present. A clean verdict is only
 * meaningful alongside the list of detectors that could have produced one.
 *
 * Three kinds of dependency, because they fail differently:
 *
 *   requires     — absent, the detector CANNOT fire. False-clean risk.
 *   unlocks      — absent, some branches cannot fire. Partial coverage.
 *   calibratedBy — absent, the detector still fires but is miscalibrated,
 *                  usually over-reporting. Not a false-clean risk; a
 *                  false-positive one.
 */

/** Field markers, in the vocabulary the probes below use. */
export const FIELDS = {
  CAPABILITY_GRANT: 'capability_grant',
  PRODUCES: 'produces',
  CONSUMES: 'consumes',
  DENIED: 'outcome.denied',
  INSTANCE: 'instance',
  EXTERNAL: 'target.external',
  HOST: 'target.host',
  OP: 'target.op',
  BYTES_OUT: 'bytes_out',
  HUMAN_TURN: 'session.turn',
};

/**
 * What each detector depends on. Kept here rather than on the detector modules
 * so this file is a single readable contract — and so a detector cannot quietly
 * declare itself reachable.
 */
export const DEPENDENCIES = {
  staircase: {
    requires: [FIELDS.CAPABILITY_GRANT],
    unlocks: [],
    calibratedBy: [],
  },
  reassembly: {
    requires: [FIELDS.PRODUCES, FIELDS.CONSUMES],
    unlocks: [],
    calibratedBy: [],
  },
  egress: {
    requires: [FIELDS.EXTERNAL],
    unlocks: [FIELDS.BYTES_OUT, FIELDS.CONSUMES],
    calibratedBy: [],
  },
  ratchet: {
    requires: [FIELDS.DENIED],
    unlocks: [],
    // Without human turns the oversight reset never applies, so every
    // operator-adjudicated denial reads as evasion. Over-reports, not under.
    calibratedBy: [FIELDS.HUMAN_TURN],
  },
  recon: {
    requires: [FIELDS.HOST],
    unlocks: [],
    calibratedBy: [],
  },
  fanout: {
    requires: [FIELDS.INSTANCE],
    unlocks: [],
    calibratedBy: [],
  },
};

/**
 * What an adapter is *capable* of emitting, versus what a given corpus happens
 * to contain. Conflating these is the subtlety that makes reachability useful
 * rather than alarming:
 *
 *   field absent, adapter CAN emit it   -> the corpus genuinely lacks that
 *                                          activity. Expected and fine. Most
 *                                          sessions contain no credential
 *                                          reuse and no denials.
 *   field absent, adapter CANNOT emit it -> a structural blind spot. The
 *                                          detector is dead for every corpus
 *                                          read through that adapter, forever,
 *                                          and no amount of data will fix it.
 *
 * Only the second is a defect. Declaring it here means it is stated up front
 * rather than discovered later from a suspiciously clean report.
 */
export const ADAPTER_CAPABILITIES = {
  'claude-code': {
    emits: Object.values(FIELDS),
    blind: [],
  },
  forge: {
    emits: Object.values(FIELDS).filter((f) => f !== FIELDS.DENIED && f !== FIELDS.HUMAN_TURN),
    blind: [
      {
        field: FIELDS.DENIED,
        detectors: ['ratchet'],
        reason: 'forge execution records carry tool_calls without per-call outcomes, '
          + 'so a refused call is indistinguishable from a successful one',
      },
      {
        field: FIELDS.HUMAN_TURN,
        detectors: [],
        reason: 'forge agents run autonomously; there is no human turn mid-execution. '
          + 'Ratchet would over-report here if it were reachable at all',
      },
    ],
  },
};

/**
 * Classify a corpus-level absence. Requires knowing which adapter produced it.
 *
 * @param {string[]} deadDetectors detectors no session could feed
 * @param {string} adapterId
 */
export function classifyDeadDetectors(deadDetectors, adapterId) {
  const caps = ADAPTER_CAPABILITIES[adapterId];
  const blindSpots = [];
  const absentFromCorpus = [];

  for (const id of deadDetectors) {
    const deps = DEPENDENCIES[id];
    const blocking = caps
      ? (deps?.requires ?? []).filter((f) => !caps.emits.includes(f))
      : [];
    if (blocking.length > 0) {
      const reasons = caps.blind.filter((b) => blocking.includes(b.field)).map((b) => b.reason);
      blindSpots.push({ detector: id, fields: blocking, reason: reasons[0] ?? 'adapter cannot emit this field' });
    } else {
      absentFromCorpus.push(id);
    }
  }

  return { blindSpots, absentFromCorpus };
}

/** Count how many events carry each field marker. */
export function fieldCensus(events) {
  const census = Object.fromEntries(Object.values(FIELDS).map((f) => [f, 0]));
  for (const e of events) {
    if (e.capability_grant?.length > 0) census[FIELDS.CAPABILITY_GRANT] += 1;
    if (e.produces?.length > 0) census[FIELDS.PRODUCES] += 1;
    if (e.consumes?.length > 0) census[FIELDS.CONSUMES] += 1;
    if (e.outcome === 'denied') census[FIELDS.DENIED] += 1;
    if (e.instance) census[FIELDS.INSTANCE] += 1;
    if (e.target?.external) census[FIELDS.EXTERNAL] += 1;
    if (e.target?.host) census[FIELDS.HOST] += 1;
    if (e.target?.op) census[FIELDS.OP] += 1;
    if (e.bytes_out > 0) census[FIELDS.BYTES_OUT] += 1;
    if (e.action === 'session.turn') census[FIELDS.HUMAN_TURN] += 1;
  }
  return census;
}

/**
 * Per-detector reachability over a set of events.
 *
 * @returns {{census: object, detectors: object, starved: string[], partial: string[], uncalibrated: string[], trustworthy: boolean}}
 */
export function reachability(events, { detectorIds = Object.keys(DEPENDENCIES) } = {}) {
  const census = fieldCensus(events);
  const present = (field) => census[field] > 0;

  const detectors = {};
  const starved = [];
  const partial = [];
  const uncalibrated = [];

  for (const id of detectorIds) {
    const deps = DEPENDENCIES[id];
    if (!deps) {
      // A detector with no declared dependencies is itself a gap — we cannot
      // reason about whether it could fire, so say so rather than assume.
      detectors[id] = { status: 'undeclared', missing: [], note: 'no dependency declaration in DEPENDENCIES' };
      continue;
    }

    const missingRequired = deps.requires.filter((f) => !present(f));
    const missingUnlocks = deps.unlocks.filter((f) => !present(f));
    const missingCalibration = deps.calibratedBy.filter((f) => !present(f));

    if (missingRequired.length > 0) {
      starved.push(id);
      detectors[id] = {
        status: 'starved',
        missing: missingRequired,
        note: `cannot fire: no event carries ${missingRequired.join(' or ')}`,
      };
      continue;
    }

    if (missingUnlocks.length > 0) partial.push(id);
    if (missingCalibration.length > 0) uncalibrated.push(id);

    detectors[id] = {
      status: missingUnlocks.length > 0 ? 'partial' : 'reachable',
      missing: missingUnlocks,
      uncalibrated: missingCalibration,
      note: missingUnlocks.length > 0
        ? `some branches cannot fire: no event carries ${missingUnlocks.join(' or ')}`
        : null,
    };
  }

  return {
    census,
    detectors,
    starved,
    partial,
    uncalibrated,
    /**
     * A clean verdict is only trustworthy when no detector is starved. This is
     * the single most useful boolean in the library: it separates "nothing was
     * wrong" from "nothing could have been found".
     */
    trustworthy: starved.length === 0,
  };
}

/** One-line human summary, for CLI reports. */
export function summarizeReachability(r) {
  const total = Object.keys(r.detectors).length;
  const live = total - r.starved.length;
  if (r.starved.length === 0 && r.partial.length === 0) return `all ${total} detectors reachable`;
  const parts = [`${live}/${total} detectors reachable`];
  if (r.starved.length > 0) parts.push(`STARVED: ${r.starved.join(', ')}`);
  if (r.partial.length > 0) parts.push(`partial: ${r.partial.join(', ')}`);
  return parts.join(' | ');
}
