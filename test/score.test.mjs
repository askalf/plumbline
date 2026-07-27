import { test } from 'node:test';
import assert from 'node:assert/strict';
import { score, levelFor, earliestActionable } from '../src/score.mjs';

const sig = (seq, severity, detector = 'staircase') => ({
  detector,
  seq,
  severity,
  label: `${detector} @${seq}`,
  detail: null,
  evidence: {},
});

test('levelFor maps drift onto the ladder at the documented boundaries', () => {
  assert.equal(levelFor(0), 'observe');
  assert.equal(levelFor(0.249), 'observe');
  assert.equal(levelFor(0.25), 'warn');
  assert.equal(levelFor(0.499), 'warn');
  assert.equal(levelFor(0.5), 'confirm');
  assert.equal(levelFor(0.849), 'confirm');
  assert.equal(levelFor(0.85), 'halt');
  assert.equal(levelFor(1), 'halt');
});

test('no signals means no drift', () => {
  const s = score([]);
  assert.equal(s.drift, 0);
  assert.equal(s.level, 'observe');
  assert.deepEqual(s.timeline, []);
  assert.equal(earliestActionable(s), null);
});

test('across actions, drift combines by noisy-OR', () => {
  // 1 - (1-0.5)(1-0.5) = 0.75
  const s = score([sig(1, 0.5), sig(2, 0.5)]);
  assert.equal(s.drift, 0.75);
});

test('within one action, the strongest signal wins and does not compound', () => {
  // Three detectors on one event must score as 0.5, not 1-(0.5*0.7*0.8).
  const s = score([sig(1, 0.5, 'a'), sig(1, 0.3, 'b'), sig(1, 0.2, 'c')]);
  assert.equal(s.drift, 0.5);
  assert.equal(s.timeline.length, 1, 'one action produces one timeline entry');
  assert.equal(s.timeline[0].signals.length, 3, 'but all signals are retained as evidence');
  assert.equal(s.timeline[0].dominant.detector, 'a');
});

test('drift is monotonically non-decreasing', () => {
  const s = score([sig(1, 0.1), sig(2, 0.4), sig(3, 0.05), sig(4, 0.6)]);
  const drifts = s.timeline.map((t) => t.drift);
  for (let i = 1; i < drifts.length; i++) {
    assert.ok(drifts[i] >= drifts[i - 1], `drift decreased at index ${i}: ${drifts}`);
  }
});

test('drift saturates toward 1 without exceeding it', () => {
  const many = Array.from({ length: 40 }, (_, i) => sig(i + 1, 0.5));
  const s = score(many);
  assert.ok(s.drift <= 1, `drift ${s.drift} exceeded 1`);
  assert.ok(s.drift > 0.999);
});

test('a single maximal signal cannot exceed 1', () => {
  assert.ok(score([sig(1, 1)]).drift <= 1);
});

test('crossings record the first seq at each threshold, and earliest actionable is warn', () => {
  const s = score([sig(10, 0.3), sig(20, 0.4), sig(30, 0.8)]);
  assert.equal(s.crossings.warn, 10);
  assert.ok(s.crossings.confirm !== null && s.crossings.confirm >= 10);
  assert.equal(earliestActionable(s), s.crossings.warn);
});

test('a threshold never crossed stays null', () => {
  const s = score([sig(1, 0.05)]);
  assert.equal(s.crossings.warn, null);
  assert.equal(s.crossings.confirm, null);
  assert.equal(s.crossings.halt, null);
});

test('timeline is ordered by seq regardless of input order', () => {
  const s = score([sig(30, 0.2), sig(10, 0.2), sig(20, 0.2)]);
  assert.deepEqual(s.timeline.map((t) => t.seq), [10, 20, 30]);
});

test('escalated marks only the entries that change level', () => {
  const s = score([sig(1, 0.1), sig(2, 0.3), sig(3, 0.01)]);
  assert.equal(s.timeline[0].escalated, false, 'observe -> observe is not an escalation');
  assert.equal(s.timeline[1].escalated, true, 'observe -> warn is');
  assert.equal(s.timeline[2].escalated, false, 'staying at warn is not');
});

test('custom thresholds are honoured and echoed back', () => {
  const thresholds = { warn: 0.1, confirm: 0.2, halt: 0.3 };
  const s = score([sig(1, 0.35)], { thresholds });
  assert.equal(s.level, 'halt');
  assert.deepEqual(s.thresholds, thresholds);
});

test('severities are rounded for display but ordering is preserved', () => {
  const s = score([sig(1, 0.123456), sig(2, 0.234567)]);
  assert.equal(s.timeline[0].dominant.severity, 0.1235);
  assert.ok(s.timeline[1].drift > s.timeline[0].drift);
});
