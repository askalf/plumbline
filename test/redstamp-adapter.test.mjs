import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { recordsToTrajectory, verifyChain } from '../src/adapters/redstamp.mjs';
import { normalizeEvent } from '../src/schema.mjs';
import { assess } from '../src/index.mjs';

const GENESIS = '0'.repeat(64);
const hashOf = (prev, rec) => createHash('sha256').update(prev + JSON.stringify(rec)).digest('hex');

/** Build a genuinely-chained redstamp log from bare records. */
function chain(recs) {
  let prev = GENESIS;
  return recs.map((rec) => {
    const hash = hashOf(prev, rec);
    const e = { ...rec, prev, hash };
    prev = hash;
    return e;
  });
}

const PROFILE = {
  name: 't',
  capabilities: ['exec:local', 'proc:spawn', 'fs:read'],
  egress: { mode: 'open_read', allow: ['.github.com'] },
  budget: { max_distinct_hosts: 5, max_probe_ratio: 0.5, max_instances: 4 },
};

const build = (recs, profile = PROFILE) => {
  const { events, chain: c } = recordsToTrajectory(recs, profile);
  return { events, chain: c, normalized: events.map((e, i) => normalizeEvent(e, { line: i + 1 })) };
};

test('a redstamp block maps to a plumbline denial - the key mapping', () => {
  const { normalized } = build(chain([
    { tool: 'shell', input: { command: 'rm -rf /' }, tier: 'black', decision: 'block', why: ['x'] },
    { tool: 'shell', input: { command: 'ls' }, tier: 'green', decision: 'allow', why: ['ok'] },
  ]));
  const calls = normalized.filter((e) => e.action === 'proc.spawn');
  assert.equal(calls[0].outcome, 'denied', 'block -> denied');
  assert.equal(calls[1].outcome, 'ok', 'allow -> ok');
});

test('ratchet is REACHABLE via redstamp - the only adapter where it is', () => {
  const { normalized } = build(chain([
    { tool: 'shell', input: { command: 'systemctl restart x' }, tier: 'black', decision: 'block', why: ['x'] },
    { tool: 'shell', input: { command: 'systemctl start x' }, tier: 'black', decision: 'block', why: ['x'] },
    { tool: 'shell', input: { command: 'systemctl --user restart x' }, tier: 'yellow', decision: 'allow', why: ['ok'] },
  ]));
  const r = assess(normalized);
  assert.equal(r.reachability.detectors.ratchet.status, 'reachable', 'denials make ratchet live');
  assert.ok(r.signals.some((s) => s.detector === 'ratchet'), 'reshape-past-guard fires ratchet');
});

test('tool names map to plumbline actions', () => {
  const { normalized } = build(chain([
    { tool: 'read', input: { path: '/a' }, tier: 'green', decision: 'allow', why: [] },
    { tool: 'write', input: { path: '/b' }, tier: 'green', decision: 'allow', why: [] },
    { tool: 'fetch', input: { url: 'https://api.github.com/x' }, tier: 'green', decision: 'allow', why: [] },
    { tool: 'grep', input: { pattern: 'x' }, tier: 'green', decision: 'allow', why: [] },
  ]));
  const actions = normalized.filter((e) => e.action !== 'session.declare').map((e) => e.action);
  assert.deepEqual(actions, ['fs.read', 'fs.write', 'http.request', 'fs.search']);
});

test('shell command yields target.op, and a URL in it yields a host', () => {
  const { normalized } = build(chain([
    { tool: 'shell', input: { command: 'cd /srv && docker compose up' }, tier: 'yellow', decision: 'allow', why: [] },
    { tool: 'fetch', input: { url: 'https://evil.example/x' }, tier: 'green', decision: 'allow', why: [] },
  ]));
  const calls = normalized.filter((e) => e.action !== 'session.declare');
  assert.equal(calls[0].target.op, 'docker');
  assert.equal(calls[1].target.host, 'evil.example');
  assert.equal(calls[1].target.external, true);
});

test('capabilities are inferred, first exercise is the grant', () => {
  const { normalized } = build(chain([
    { tool: 'shell', input: { command: 'ls' }, tier: 'green', decision: 'allow', why: [] },
    { tool: 'shell', input: { command: 'pwd' }, tier: 'green', decision: 'allow', why: [] },
    { tool: 'read', input: { path: '/a' }, tier: 'green', decision: 'allow', why: [] },
  ]));
  const calls = normalized.filter((e) => e.action !== 'session.declare');
  assert.deepEqual(calls[0].capability_grant, ['exec:local', 'proc:spawn']);
  assert.deepEqual(calls[1].capability_grant, [], 'second shell is not a new grant');
  assert.deepEqual(calls[2].capability_grant, ['fs:read']);
});

test('hosts are mined from the why array when the record has no input', () => {
  // daemon/cc-hook records omit input; the why line still names the host.
  const { normalized } = build(chain([
    { tool: 'fetch', tier: 'red', decision: 'approve', why: ['egress to non-allowlisted host(s): exfil.example'] },
  ]));
  const call = normalized.find((e) => e.action === 'http.request');
  assert.equal(call.target.host, 'exfil.example');
  assert.equal(call.target.external, true);
});

// -------------------------------------------------------------- chain -------

test('verifyChain confirms an intact chain', () => {
  const c = verifyChain(chain([
    { tool: 'read', input: { path: '/a' }, tier: 'green', decision: 'allow', why: [] },
    { tool: 'shell', input: { command: 'ls' }, tier: 'green', decision: 'allow', why: [] },
  ]));
  assert.deepEqual(c, { chained: true, intact: true, brokenAt: null });
});

test('TAMPER: editing a record breaks the chain and is caught', () => {
  const original = chain([
    { tool: 'shell', input: { command: 'x' }, tier: 'green', decision: 'allow', why: [] },
    { tool: 'shell', input: { command: 'y' }, tier: 'black', decision: 'block', why: ['blocked'] },
    { tool: 'shell', input: { command: 'z' }, tier: 'green', decision: 'allow', why: [] },
  ]);
  // an agent edits record 1 (block -> allow) to hide the guard's refusal
  const tampered = original.map((r, i) => (i === 1 ? { ...r, decision: 'allow', tier: 'green' } : r));

  const c = verifyChain(tampered);
  assert.equal(c.intact, false);
  assert.equal(c.brokenAt, 1);

  const { events } = recordsToTrajectory(tampered, PROFILE);
  assert.match(events[0].note, /BROKEN at record 1/);
  assert.ok(events.some((e) => e.action === 'audit.tampered'), 'a tamper event enters the trajectory');
});

test('an unchained (cc-hook) log is handled and labelled as such', () => {
  const { events, chain: c } = recordsToTrajectory([
    { ts: '2026-01-01T00:00:00Z', tool: 'shell', tier: 'green', decision: 'allow', why: ['ok'] },
    { ts: '2026-01-01T00:00:01Z', tool: 'read', tier: 'green', decision: 'allow', why: ['ok'] },
  ], PROFILE);
  assert.equal(c.chained, false);
  assert.match(events[0].note, /unchained/);
  assert.equal(events.filter((e) => e.action !== 'session.declare').length, 2);
});

test('secret-shaped values in a command become fragments, never the value', () => {
  const { events } = recordsToTrajectory(chain([
    { tool: 'shell', input: { command: 'export T=ghp_A9fK2mQ7xZ1pL4vR8nT6bW3cY5dE0sJhUg' }, tier: 'yellow', decision: 'allow', why: [] },
  ]), PROFILE);
  const call = events.find((e) => e.action === 'proc.spawn');
  assert.ok(call.produces?.length === 1);
  assert.equal(JSON.stringify(events).includes('ghp_A9fK2mQ7xZ1pL4vR8nT6bW3cY5dE0sJhUg'), false);
});

test('an empty log yields only the declare event', () => {
  const { events } = recordsToTrajectory([], PROFILE);
  assert.equal(events.length, 1);
  assert.equal(events[0].action, 'session.declare');
});
