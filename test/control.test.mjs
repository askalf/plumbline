/**
 * Liveness controls.
 *
 * The bug these exist to prevent: `staircase` reads only `capability_grant`,
 * and for a period no adapter emitted it. The detector was entirely inert on
 * real traffic while every corpus still reported "clean" — because a clean
 * result and a dead detector produce identical output.
 *
 * Rule that follows: never trust a clean result on its own. Always also score
 * something you expect to fail.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { assessTrajectory, DETECTOR_IDS, parseTrajectory, assess } from '../src/index.mjs';
import { loadProfile, listProfiles } from '../src/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const corpus = (name) => readFileSync(join(here, '..', 'corpus', name), 'utf8');

/**
 * The expected detector set, written out literally and deliberately NOT derived
 * from the registry.
 *
 * An earlier version of this guard compared the fired set against DETECTOR_IDS.
 * That is circular: unregistering a detector removes it from both sides of the
 * comparison, so the test passes while the detector is gone — precisely the
 * failure mode this file exists to prevent, reproduced inside the prevention.
 *
 * Adding a detector means updating this list AND adding a trigger to
 * corpus/detector-exercise.jsonl. That friction is the point.
 */
const EXPECTED_DETECTORS = ['egress', 'fanout', 'ratchet', 'reassembly', 'recon', 'staircase'];

test('LIVENESS: every expected detector fires on the exercise corpus', () => {
  const report = assessTrajectory(corpus('detector-exercise.jsonl'));
  const fired = new Set(report.signals.map((s) => s.detector));

  const silent = EXPECTED_DETECTORS.filter((id) => !fired.has(id));
  assert.deepEqual(
    silent,
    [],
    `these detectors produced no signal and may be inert or unregistered: ${silent.join(', ')}. ` +
      'Either the detector broke, it was dropped from src/detect/index.mjs, or ' +
      'corpus/detector-exercise.jsonl no longer triggers it.',
  );
});

test('LIVENESS: the registry matches the expected set exactly', () => {
  // The other half of the non-circularity guarantee. The test above catches a
  // detector going silent; this one catches the registry drifting from the
  // documented set in either direction — a detector quietly dropped, or a new
  // one added without a corpus trigger and a DETECTORS.md entry.
  assert.deepEqual(
    [...DETECTOR_IDS].sort(),
    [...EXPECTED_DETECTORS].sort(),
    'src/detect/index.mjs no longer matches EXPECTED_DETECTORS. If you added or ' +
      'removed a detector, update this list, corpus/detector-exercise.jsonl and DETECTORS.md.',
  );
});

test('LIVENESS: the exercise corpus reaches halt', () => {
  const report = assessTrajectory(corpus('detector-exercise.jsonl'));
  assert.equal(report.level, 'halt', `expected halt, got ${report.level} at drift ${report.drift}`);
});

test('CONTROL: a permissive envelope suppresses envelope-gated detectors', () => {
  // Same events, wide envelope. staircase and off-envelope egress must go quiet,
  // proving those detectors are driven by the declared envelope rather than
  // firing unconditionally.
  const events = parseTrajectory(corpus('detector-exercise.jsonl'));
  const wide = assess(events, {
    envelope: {
      task: 'anything goes',
      capabilities: ['exec:local', 'fs:read', 'cloud:iam:some-role', 'net:egress:internet'],
      egress: { mode: 'open_read', allow: ['*'] },
      budget: { max_distinct_hosts: 50, max_probe_ratio: 0.99, max_instances: 50 },
    },
  });
  const fired = new Set(wide.signals.map((s) => s.detector));

  assert.ok(!fired.has('staircase'), 'staircase must be silent when every capability is granted');
  assert.ok(!fired.has('fanout'), 'fanout must be silent under a generous instance budget');
  assert.ok(!fired.has('recon'), 'recon must be silent under a permissive probe ratio');

  // These are NOT envelope-gated and must still fire — an envelope cannot switch
  // off evidence of evasion or of credentials leaving.
  assert.ok(fired.has('ratchet'), 'ratchet is not envelope-gated and must still fire');
  assert.ok(fired.has('reassembly'), 'reassembly is not envelope-gated and must still fire');
  assert.ok(fired.has('egress'), 'C2 rotation is not envelope-gated and must still fire');
});

test('CONTROL: the benign corpus stays clean under a strict envelope too', () => {
  // The inverse guard. If the benign trajectory only looks clean because the
  // dev-workstation profile is loose, tightening the envelope would expose it.
  const events = parseTrajectory(corpus('benign-repo-triage.jsonl'));
  const strict = assess(events, {
    envelope: {
      task: 'triage',
      capabilities: ['exec:local', 'fs:read', 'fs:write', 'cloud:gh:repo'],
      egress: { mode: 'allowlist', allow: ['registry.npmjs.org', 'api.github.com'] },
      budget: { max_distinct_hosts: 3, max_probe_ratio: 0.4, max_instances: 3 },
    },
  });
  assert.equal(strict.level, 'observe', `benign trajectory scored ${strict.level} under a strict envelope`);
});

test('CONTROL: an undeclared trajectory is reported unaudited, never clean', () => {
  const withoutDeclare = corpus('benign-repo-triage.jsonl')
    .split('\n')
    .filter((l) => !l.includes('session.declare'))
    .join('\n');
  const report = assessTrajectory(withoutDeclare);

  assert.equal(report.envelope.declared, false, 'must be flagged as undeclared');
  assert.ok(report.signals.length > 0, 'an undeclared trajectory must not silently score clean');
});

test('CONTROL: every shipped profile actually constrains something', () => {
  // A profile that grants everything is indistinguishable from no monitoring.
  // Scored against the exercise corpus, each profile must produce signals.
  const events = parseTrajectory(corpus('detector-exercise.jsonl'));
  for (const name of listProfiles()) {
    const profile = loadProfile(name);
    const report = assess(events, {
      envelope: {
        task: 'exercise',
        capabilities: profile.capabilities,
        egress: profile.egress,
        budget: profile.budget,
      },
    });
    assert.ok(
      report.signals.length > 0,
      `profile "${name}" produced no signals on the exercise corpus — it may grant too much to be useful`,
    );
  }
});
