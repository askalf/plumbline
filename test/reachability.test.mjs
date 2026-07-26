import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  reachability, fieldCensus, summarizeReachability,
  DEPENDENCIES, FIELDS, ADAPTER_CAPABILITIES, classifyDeadDetectors,
} from '../src/reachability.mjs';
import { normalizeEvent, parseTrajectory } from '../src/schema.mjs';
import { assessTrajectory } from '../src/index.mjs';
import { DETECTOR_IDS } from '../src/detect/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const corpus = (name) => readFileSync(join(here, '..', 'corpus', name), 'utf8');
const ev = (o) => normalizeEvent({ v: 1, session: 's', seq: 0, action: 'http.request', ...o });

test('every registered detector has a dependency declaration', () => {
  // Without one, reachability cannot reason about the detector and would
  // silently treat it as fine — the same blind spot in a new place.
  const undeclared = DETECTOR_IDS.filter((id) => !DEPENDENCIES[id]);
  assert.deepEqual(undeclared, [], `add these to DEPENDENCIES: ${undeclared.join(', ')}`);
});

test('a detector with no declaration is reported undeclared, not reachable', () => {
  const r = reachability([ev({})], { detectorIds: ['not_a_real_detector'] });
  assert.equal(r.detectors.not_a_real_detector.status, 'undeclared');
});

test('fieldCensus counts each marker independently', () => {
  const census = fieldCensus([
    ev({ capability_grant: ['a:b'] }),
    ev({ produces: [{ id: 'f', len: 1, entropy: 1 }] }),
    ev({ consumes: ['f'] }),
    ev({ outcome: 'denied' }),
    ev({ instance: 'i-1' }),
    ev({ target: { host: 'h', external: true } }),
    ev({ target: { op: 'git' } }),
    ev({ bytes_out: 10 }),
    ev({ action: 'session.turn' }),
  ]);
  assert.equal(census[FIELDS.CAPABILITY_GRANT], 1);
  assert.equal(census[FIELDS.PRODUCES], 1);
  assert.equal(census[FIELDS.CONSUMES], 1);
  assert.equal(census[FIELDS.DENIED], 1);
  assert.equal(census[FIELDS.INSTANCE], 1);
  assert.equal(census[FIELDS.EXTERNAL], 1);
  assert.equal(census[FIELDS.OP], 1);
  assert.equal(census[FIELDS.BYTES_OUT], 1);
  assert.equal(census[FIELDS.HUMAN_TURN], 1);
});

test('a detector whose required field is absent is starved, and named', () => {
  const r = reachability([ev({})], { detectorIds: ['staircase'] });
  assert.equal(r.detectors.staircase.status, 'starved');
  assert.deepEqual(r.detectors.staircase.missing, [FIELDS.CAPABILITY_GRANT]);
  assert.deepEqual(r.starved, ['staircase']);
  assert.equal(r.no_starved_detectors, false);
});

test('trustworthy is false whenever anything is starved — the headline boolean', () => {
  const starved = reachability([ev({})]);
  assert.equal(starved.no_starved_detectors, false);

  const fed = reachability([
    ev({ capability_grant: ['a:b'] }),
    ev({ produces: [{ id: 'f', len: 9, entropy: 4 }] }),
    ev({ consumes: ['f'], bytes_out: 10, target: { host: 'h', external: true } }),
    ev({ outcome: 'denied' }),
    ev({ instance: 'i-1' }),
  ]);
  assert.equal(fed.no_starved_detectors, true, JSON.stringify(fed.starved));
});

test('reassembly requires BOTH produces and consumes', () => {
  const onlyProduces = reachability(
    [ev({ produces: [{ id: 'f', len: 9, entropy: 4 }] })],
    { detectorIds: ['reassembly'] },
  );
  assert.equal(onlyProduces.detectors.reassembly.status, 'starved');
  assert.deepEqual(onlyProduces.detectors.reassembly.missing, [FIELDS.CONSUMES]);
});

test('egress is partial when it can see hosts but no payload signal', () => {
  const r = reachability(
    [ev({ target: { host: 'h', external: true } })],
    { detectorIds: ['egress'] },
  );
  assert.equal(r.detectors.egress.status, 'partial');
  assert.deepEqual(r.partial, ['egress']);
  assert.ok(r.detectors.egress.missing.includes(FIELDS.BYTES_OUT));
  assert.equal(r.no_starved_detectors, true, 'partial is not starved — some branches still work');
});

test('ratchet without human turns is reachable but flagged uncalibrated', () => {
  const r = reachability([ev({ outcome: 'denied' })], { detectorIds: ['ratchet'] });
  assert.equal(r.detectors.ratchet.status, 'reachable');
  assert.deepEqual(r.uncalibrated, ['ratchet']);
  assert.ok(r.detectors.ratchet.uncalibrated.includes(FIELDS.HUMAN_TURN));
});

test('summarizeReachability names the starved detectors', () => {
  const r = reachability([ev({})]);
  const s = summarizeReachability(r);
  assert.match(s, /STARVED/);
  assert.match(s, /staircase/);
});

test('assess() attaches reachability to every verdict', () => {
  const report = assessTrajectory(corpus('benign-repo-triage.jsonl'));
  assert.ok(report.reachability, 'a verdict without reachability can be misread as proven');
  assert.equal(typeof report.reachability.no_starved_detectors, 'boolean');
});

test('the benign corpus is clean but explicitly NOT trustworthy', () => {
  // The whole point: clean plus starved detectors is an unproven result, and
  // the report must say so rather than implying safety.
  const report = assessTrajectory(corpus('benign-repo-triage.jsonl'));
  assert.equal(report.level, 'observe');
  assert.equal(report.reachability.no_starved_detectors, false);
  assert.ok(report.reachability.starved.length > 0);
});

test('the exercise corpus feeds everything except what it deliberately omits', () => {
  const report = assessTrajectory(corpus('detector-exercise.jsonl'));
  // It has no denials-with-op reachable? It does: seq 15-17 are denied.
  assert.ok(!report.reachability.starved.includes('staircase'));
  assert.ok(!report.reachability.starved.includes('reassembly'));
  assert.ok(!report.reachability.starved.includes('fanout'));
});

test('every adapter on disk has a capability declaration', () => {
  // Enumerated from the filesystem, deliberately NOT from ADAPTER_CAPABILITIES.
  // A hardcoded list here would be the same circularity that let the liveness
  // guard pass while a detector was missing: a new adapter could ship with no
  // declaration, and every corpus it produced would report clean with unknown
  // blind spots.
  const dir = join(here, '..', 'src', 'adapters');
  const adapters = readdirSync(dir)
    .filter((f) => f.endsWith('.mjs'))
    .map((f) => f.replace(/\.mjs$/, ''));

  assert.ok(adapters.length > 0, 'no adapters found - check the path');

  const undeclared = adapters.filter((id) => !ADAPTER_CAPABILITIES[id]);
  assert.deepEqual(
    undeclared,
    [],
    `these adapters have no ADAPTER_CAPABILITIES entry: ${undeclared.join(', ')}. ` +
      'Without one, plumbline cannot tell an adapter blind spot from an unexercised corpus, ' +
      'and will report clean without knowing what it could not see.',
  );

  for (const id of adapters) {
    assert.ok(Array.isArray(ADAPTER_CAPABILITIES[id].emits), `${id}.emits must be an array`);
    assert.ok(Array.isArray(ADAPTER_CAPABILITIES[id].blind), `${id}.blind must be an array`);
    // A declared blind field must not also be claimed as emitted.
    for (const b of ADAPTER_CAPABILITIES[id].blind) {
      assert.ok(
        !ADAPTER_CAPABILITIES[id].emits.includes(b.field),
        `${id} declares "${b.field}" as both emitted and blind`,
      );
      assert.ok(b.reason && b.reason.length > 20, `${id} blind spot "${b.field}" needs a real reason`);
    }
  }
});

test('classifyDeadDetectors separates an adapter blind spot from an unexercised corpus', () => {
  // forge cannot emit denials at all -> ratchet is a permanent blind spot.
  const forge = classifyDeadDetectors(['ratchet', 'reassembly'], 'forge');
  assert.deepEqual(forge.blindSpots.map((b) => b.detector), ['ratchet']);
  assert.deepEqual(forge.absentFromCorpus, ['reassembly']);
  assert.match(forge.blindSpots[0].reason, /per-call outcomes/);

  // claude-code can emit everything -> the same absences are just missing data.
  const cc = classifyDeadDetectors(['ratchet', 'reassembly'], 'claude-code');
  assert.deepEqual(cc.blindSpots, []);
  assert.deepEqual(cc.absentFromCorpus, ['ratchet', 'reassembly']);
});

test('an unknown adapter does not silently claim zero blind spots', () => {
  // This test previously asserted the OPPOSITE of its own name: it checked that
  // blindSpots was empty, which is precisely the silent zero-coverage claim the
  // name warns about. Caught by adversarial review, not by the suite.
  //
  // Correct behaviour: an undeclared adapter cannot be reasoned about, so every
  // dead detector is attributed to an unknown cause and the result is unproven
  // rather than clean.
  const r = classifyDeadDetectors(['staircase', 'ratchet'], 'never-heard-of-it');
  assert.equal(r.adapterKnown, false, 'an undeclared adapter must be marked unknown');
  assert.deepEqual(r.unknownCause, ['staircase', 'ratchet']);
  assert.deepEqual(r.blindSpots, [], 'no blind spot can be attributed without a declaration');
  assert.deepEqual(r.absentFromCorpus, [], 'nor can absence be attributed to the corpus');
});

test('a known adapter is marked known, so the two cases are distinguishable', () => {
  const r = classifyDeadDetectors(['ratchet'], 'forge');
  assert.equal(r.adapterKnown, true);
  assert.deepEqual(r.unknownCause, []);
  assert.equal(r.blindSpots.length, 1);
});
