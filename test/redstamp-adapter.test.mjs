import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readCheckpoint, readRedstampAudit, recordsToTrajectory, verifyChain, verifyCheckpoint } from '../src/adapters/redstamp.mjs';
import { scanRedstampAudit } from '../src/scan.mjs';
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

// ---------------------------------------------------- checkpoint ---------

const CORPUS = join(dirname(fileURLToPath(import.meta.url)), '..', 'corpus', 'redstamp');
const SCHEMA = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'schema', 'trajectory.schema.json'), 'utf8'));

const THREE = () => chain([
  { tool: 'shell', input: { command: 'npm test' }, tier: 'green', decision: 'allow', why: ['ok'] },
  { tool: 'shell', input: { command: 'curl https://ex.example/x' }, tier: 'red', decision: 'approve', why: ['needs human'] },
  { tool: 'shell', input: { command: 'npm run build' }, tier: 'green', decision: 'allow', why: ['ok'] },
]);

test('an approve record maps to ok and every event stays inside the published schema', () => {
  const { events } = recordsToTrajectory(THREE(), PROFILE, { checkpoint: { count: 9, head: 'x' } });
  assert.equal(events.find((e) => e.note?.includes('decision=approve')).outcome, 'ok');
  const allowed = new Set(Object.keys(SCHEMA.properties));
  for (const e of events) {
    for (const k of Object.keys(e)) assert.ok(allowed.has(k), `${e.action} carries ${k}, which the schema does not define`);
  }
});

test('a checkpoint catches a truncated tail the chain alone passes', () => {
  const recs = THREE();
  const cut = recs.slice(0, 2);
  assert.equal(verifyChain(cut).intact, true, 'a prefix still verifies');
  const { events, checkpoint } = recordsToTrajectory(cut, PROFILE, { checkpoint: { count: 3, head: recs[2].hash } });
  assert.equal(checkpoint.matches, false);
  assert.match(checkpoint.reason, /^truncated/);
  assert.ok(events.some((e) => e.action === 'audit.checkpoint_mismatch'));
});

test('a log that grew past its checkpoint still matches', () => {
  const recs = THREE();
  const r = verifyCheckpoint(recs, { count: 2, head: recs[1].hash });
  assert.deepEqual(r, { present: true, matches: true });
  const { events } = recordsToTrajectory(recs, PROFILE, { checkpoint: { count: 2, head: recs[1].hash } });
  assert.ok(!events.some((e) => e.action === 'audit.checkpoint_mismatch'));
});

test('a rewritten prefix of the same length is a rollback', () => {
  const other = chain([
    { tool: 'shell', input: { command: 'ls' }, tier: 'green', decision: 'allow', why: ['ok'] },
    { tool: 'shell', input: { command: 'pwd' }, tier: 'green', decision: 'allow', why: ['ok'] },
    { tool: 'shell', input: { command: 'id' }, tier: 'green', decision: 'allow', why: ['ok'] },
  ]);
  const r = verifyCheckpoint(other, { count: 3, head: THREE()[2].hash });
  assert.equal(r.matches, false);
  assert.match(r.reason, /^rollback/);
});

test('unchained lines do not count toward the checkpoint', () => {
  const recs = THREE();
  const mixed = [recs[0], { ts: 't', tool: 'shell', tier: 'green', decision: 'allow', why: ['daemon down'] }, recs[1], recs[2]];
  assert.deepEqual(verifyCheckpoint(mixed, { count: 3, head: recs[2].hash }), { present: true, matches: true });
});

test('no checkpoint means no check, and a malformed one reports as a mismatch', () => {
  assert.deepEqual(verifyCheckpoint(THREE(), undefined), { present: false, matches: false });
  for (const bad of [{}, { count: 0, head: 'x' }, { count: 1.5, head: 'x' }, { count: 1 }]) {
    const r = verifyCheckpoint(THREE(), bad);
    assert.equal(r.present, true);
    assert.equal(r.matches, false);
    assert.equal(r.reason, 'checkpoint malformed');
  }
});

test('corpus approve-path: chain intact, the .chk beside the log is read and matches', async () => {
  const { events, chain: c, checkpoint } = await readRedstampAudit(join(CORPUS, 'approve-path.jsonl'), PROFILE);
  assert.equal(c.intact, true);
  assert.deepEqual(checkpoint, { present: true, matches: true });
  const calls = events.filter((e) => e.action === 'proc.spawn');
  assert.equal(calls.length, 3);
  assert.ok(calls.every((e) => e.outcome === 'ok'), 'approve is ok: the record does not say whether the call ran');
});

test('scan reaches the checkpoint: a truncated copy of the corpus log is flagged', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'plumbline-redstamp-'));
  const log = join(dir, 'audit.jsonl');
  const lines = readFileSync(join(CORPUS, 'approve-path.jsonl'), 'utf8').trimEnd().split('\n');
  writeFileSync(log, lines.slice(0, -1).join('\n') + '\n');
  copyFileSync(join(CORPUS, 'approve-path.jsonl.chk'), `${log}.chk`);
  const { results } = await scanRedstampAudit(log, PROFILE);
  assert.equal(results[0].chain.intact, true, 'the chain alone passes the cut log');
  assert.equal(results[0].checkpoint.matches, false);
  assert.match(results[0].checkpoint.reason, /^truncated/);
});

test('a checkpoint that exists but cannot be read reports as a mismatch, not as absent', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'plumbline-redstamp-'));
  const log = join(dir, 'audit.jsonl');
  copyFileSync(join(CORPUS, 'approve-path.jsonl'), log);
  assert.equal(await readCheckpoint(log), undefined, 'no .chk at all: no check');
  mkdirSync(`${log}.chk`); // reading a directory fails with EISDIR, not ENOENT
  assert.deepEqual(await readCheckpoint(log), {});
  const { events, checkpoint } = await readRedstampAudit(log, PROFILE);
  assert.deepEqual(checkpoint, { present: true, matches: false, reason: 'checkpoint malformed' });
  assert.ok(events.some((e) => e.action === 'audit.checkpoint_mismatch'));
});

test('a checkpoint that is not JSON reports as a mismatch', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'plumbline-redstamp-'));
  const log = join(dir, 'audit.jsonl');
  copyFileSync(join(CORPUS, 'approve-path.jsonl'), log);
  writeFileSync(`${log}.chk`, 'not json');
  const { checkpoint } = await readRedstampAudit(log, PROFILE);
  assert.equal(checkpoint.reason, 'checkpoint malformed');
});
