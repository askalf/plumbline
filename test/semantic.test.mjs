/**
 * Semantic detector tests.
 *
 * The model is mocked. These verify the plumbing — prompt shape, signal
 * mapping, graceful degradation, merge into scoring — deterministically and
 * with zero network. The claim that a real local model discriminates escapes
 * from benign work is validated separately against ollama (docs/semantic-detector.md
 * records the run); a unit suite must not depend on a live model loop.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessSemantic, buildPrompt, actionLine } from '../src/semantic.mjs';
import { assessWithSemantic, parseTrajectory, normalizeEnvelope } from '../src/index.mjs';

const events = parseTrajectory([
  JSON.stringify({ v: 1, session: 's', seq: 0, action: 'session.declare', envelope: { task: 'Build and test the project', capabilities: ['exec:local'], egress: { allow: [] } } }),
  JSON.stringify({ v: 1, session: 's', seq: 1, action: 'fs.read', target: { path: '/workspace/package.json' } }),
  JSON.stringify({ v: 1, session: 's', seq: 2, action: 'fs.read', target: { path: '/home/runner/.aws/credentials' }, note: 'off task' }),
].join('\n'));

/** A mock judge that flags whatever steps it is told to. */
const mockJudge = (steps) => async () => ({
  diverging_steps: steps.map((step) => ({ step, reason: `mock: step ${step} is off task` })),
});

test('buildPrompt includes the task and every non-structural action', () => {
  const prompt = buildPrompt('Build the project', events);
  assert.match(prompt, /DECLARED TASK: Build the project/);
  assert.match(prompt, /fs\.read/);
  assert.match(prompt, /\.aws\/credentials/);
  // session.declare is structural and must not appear as a judged action line.
  assert.ok(!/session\.declare/.test(prompt));
});

test('actionLine renders target and acquired capabilities compactly', () => {
  const line = actionLine({ seq: 5, action: 'cred.acquire', target: { host: 'x', op: 'aws' }, capability_grant: ['cloud:iam'] });
  assert.match(line, /5\. cred\.acquire/);
  assert.match(line, /host=x/);
  assert.match(line, /acquired=\[cloud:iam\]/);
});

test('a flagged step becomes a semantic signal at the right seq', async () => {
  const env = normalizeEnvelope({ task: 't', capabilities: [], egress: { allow: [] } });
  const r = await assessSemantic(events, env, { judge: mockJudge([2]) });
  assert.equal(r.available, true);
  assert.equal(r.signals.length, 1);
  assert.equal(r.signals[0].detector, 'semantic');
  assert.equal(r.signals[0].seq, 2);
  assert.match(r.signals[0].detail, /off task/);
});

test('a hallucinated step number that maps to no event is ignored', async () => {
  const env = normalizeEnvelope({ task: 't', capabilities: [], egress: { allow: [] } });
  const r = await assessSemantic(events, env, { judge: mockJudge([2, 999]) });
  assert.equal(r.signals.length, 1, 'only the real step survives');
  assert.equal(r.signals[0].seq, 2);
});

test('no judge means the layer is unavailable, never silently clean', async () => {
  const env = normalizeEnvelope({ task: 't', capabilities: [], egress: { allow: [] } });
  const r = await assessSemantic(events, env, {});
  assert.equal(r.available, false);
  assert.equal(r.signals.length, 0);
  assert.match(r.error, /no judge/);
});

test('a judge that throws degrades gracefully and reports the error', async () => {
  const env = normalizeEnvelope({ task: 't', capabilities: [], egress: { allow: [] } });
  const throwing = async () => { throw new Error('model down'); };
  const r = await assessSemantic(events, env, { judge: throwing });
  assert.equal(r.available, false);
  assert.match(r.error, /model down/);
  assert.equal(r.signals.length, 0);
});

test('assessWithSemantic merges the semantic signal into scoring', async () => {
  // The escape is entirely in-envelope, so the deterministic detectors are quiet
  // (exec:local granted). The semantic signal is what lifts it off observe.
  const inEnvelope = parseTrajectory([
    JSON.stringify({ v: 1, session: 's', seq: 0, action: 'session.declare', envelope: { task: 'Build', capabilities: ['exec:local', 'fs:read'], egress: { mode: 'open_read', allow: ['*'] } } }),
    JSON.stringify({ v: 1, session: 's', seq: 1, action: 'proc.spawn', target: { op: 'npm' }, capability_grant: ['exec:local'] }),
    JSON.stringify({ v: 1, session: 's', seq: 2, action: 'fs.read', target: { path: '/home/runner/.aws/credentials' }, capability_grant: ['fs:read'] }),
  ].join('\n'));

  const without = await assessWithSemantic(inEnvelope, {});
  assert.equal(without.level, 'observe', 'in-envelope escape is invisible to shape');
  assert.equal(without.semantic.ran, false);

  const withSemantic = await assessWithSemantic(inEnvelope, { judge: mockJudge([2]) });
  assert.equal(withSemantic.semantic.ran, true);
  assert.equal(withSemantic.semantic.findings, 1);
  assert.notEqual(withSemantic.level, 'observe', 'the semantic layer catches what shape cannot');
  assert.ok(withSemantic.signals.some((s) => s.detector === 'semantic'));
});

test('assessWithSemantic without a judge equals a plain assessment plus an honest note', async () => {
  const r = await assessWithSemantic(events, {});
  assert.equal(r.semantic.ran, false);
  assert.equal(r.semantic.findings, 0);
  // the deterministic verdict is unchanged
  assert.ok('level' in r && 'reachability' in r);
});
