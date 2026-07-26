import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEvent, parseTrajectory, entropyOf, TrajectoryError } from '../src/schema.mjs';

const base = { v: 1, session: 's', seq: 0, action: 'fs.read' };
const bad = (event, match) => {
  assert.throws(() => normalizeEvent(event), (err) => {
    assert.ok(err instanceof TrajectoryError, `expected TrajectoryError, got ${err.name}`);
    if (match) assert.match(err.message, match);
    return true;
  });
};

test('accepts a minimal valid event and fills defaults', () => {
  const e = normalizeEvent(base);
  assert.equal(e.outcome, 'ok');
  assert.equal(e.target.host, null);
  assert.equal(e.target.op, null);
  assert.equal(e.target.external, false);
  assert.deepEqual(e.capability_grant, []);
  assert.deepEqual(e.produces, []);
  assert.deepEqual(e.consumes, []);
});

test('rejects a wrong or missing schema version', () => {
  bad({ ...base, v: 2 }, /unsupported schema version/);
  bad({ ...base, v: undefined }, /unsupported schema version/);
});

test('rejects missing or empty required strings', () => {
  bad({ ...base, session: undefined }, /session/);
  bad({ ...base, session: '' }, /session/);
  bad({ ...base, action: undefined }, /action/);
});

test('rejects a non-object event', () => {
  bad(null, /must be an object/);
  bad([], /must be an object/);
  bad('nope', /must be an object/);
});

test('enforces the dotted lowercase action grammar', () => {
  bad({ ...base, action: 'fsread' }, /dotted lowercase verb/);
  bad({ ...base, action: 'FS.read' }, /dotted lowercase verb/);
  bad({ ...base, action: 'fs..read' }, /dotted lowercase verb/);
  bad({ ...base, action: '.read' }, /dotted lowercase verb/);
  assert.equal(normalizeEvent({ ...base, action: 'a.b.c' }).action, 'a.b.c');
  assert.equal(normalizeEvent({ ...base, action: 'mcp.call_tool' }).action, 'mcp.call_tool');
});

test('seq must be a non-negative integer', () => {
  bad({ ...base, seq: -1 }, /non-negative integer/);
  bad({ ...base, seq: 1.5 }, /non-negative integer/);
  bad({ ...base, seq: '3' }, /non-negative integer/);
  assert.equal(normalizeEvent({ ...base, seq: 0 }).seq, 0);
});

test('outcome must be ok, error or denied', () => {
  bad({ ...base, outcome: 'maybe' }, /is not ok\|error\|denied/);
  for (const o of ['ok', 'error', 'denied']) {
    assert.equal(normalizeEvent({ ...base, outcome: o }).outcome, o);
  }
});

test('array fields are type-checked, not silently coerced', () => {
  bad({ ...base, consumes: 'frag' }, /consumes/);
  bad({ ...base, consumes: [1] }, /consumes/);
  bad({ ...base, capability_grant: 'net:x' }, /capability_grant/);
  bad({ ...base, produces: {} }, /produces/);
  bad({ ...base, produces: [{ len: 3 }] }, /require a non-empty id/);
});

test('fragment measurements default to zero rather than NaN', () => {
  const e = normalizeEvent({ ...base, produces: [{ id: 'f1' }] });
  assert.equal(e.produces[0].len, 0);
  assert.equal(e.produces[0].entropy, 0);
});

test('target is normalized and a non-object target is rejected', () => {
  bad({ ...base, target: 'x' }, /target/);
  const e = normalizeEvent({ ...base, target: { host: 'h', path: '/p', op: 'git', external: true } });
  assert.deepEqual(e.target, { host: 'h', path: '/p', op: 'git', external: true });
});

test('parseTrajectory skips blanks and # comments', () => {
  const text = [
    '# a comment',
    '',
    JSON.stringify({ ...base, seq: 1 }),
    '   ',
    JSON.stringify({ ...base, seq: 2 }),
  ].join('\n');
  assert.equal(parseTrajectory(text).length, 2);
});

test('parseTrajectory reports the offending line number', () => {
  const text = [JSON.stringify(base), '{not json'].join('\n');
  assert.throws(() => parseTrajectory(text), (err) => {
    assert.equal(err.line, 2);
    assert.match(err.message, /line 2/);
    return true;
  });
});

test('parseTrajectory refuses a file mixing sessions', () => {
  const text = [
    JSON.stringify({ ...base, session: 'a', seq: 1 }),
    JSON.stringify({ ...base, session: 'b', seq: 2 }),
  ].join('\n');
  assert.throws(() => parseTrajectory(text), /mixes 2 sessions/);
});

test('parseTrajectory handles CRLF', () => {
  const text = `${JSON.stringify(base)}\r\n${JSON.stringify({ ...base, seq: 1 })}\r\n`;
  assert.equal(parseTrajectory(text).length, 2);
});

test('entropyOf is 0 for empty and uniform input, log2(n) for n distinct symbols', () => {
  assert.equal(entropyOf(''), 0);
  assert.equal(entropyOf('zzzz'), 0);
  assert.ok(Math.abs(entropyOf('ab') - 1) < 1e-9);
  assert.ok(Math.abs(entropyOf('abcdefgh') - 3) < 1e-9);
});

test('entropyOf ranks a random-looking token above English prose', () => {
  const token = 'ghp_A9fK2mQ7xZ1pL4vR8nT6bW3cY5dE0sJhUgIo';
  const prose = 'the quick brown fox jumps over the lazy dog again and again';
  assert.ok(entropyOf(token) > entropyOf(prose));
});
