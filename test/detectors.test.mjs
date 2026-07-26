import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEvent, parseTrajectory, entropyOf } from '../src/schema.mjs';
import { normalizeEnvelope, undeclaredEnvelope, capabilityAllowed, hostAllowed } from '../src/envelope.mjs';
import { runDetectors } from '../src/detect/index.mjs';
import * as staircase from '../src/detect/staircase.mjs';
import * as reassembly from '../src/detect/reassembly.mjs';
import * as egress from '../src/detect/egress.mjs';
import * as ratchet from '../src/detect/ratchet.mjs';
import * as recon from '../src/detect/recon.mjs';
import * as fanout from '../src/detect/fanout.mjs';

function ev(overrides) {
  return normalizeEvent({ v: 1, session: 's', seq: 0, action: 'http.request', ...overrides });
}

test('entropyOf: uniform bytes approach log2(alphabet)', () => {
  assert.equal(entropyOf(''), 0);
  assert.equal(entropyOf('aaaa'), 0);
  assert.ok(Math.abs(entropyOf('abcd') - 2) < 1e-9);
});

test('capabilityAllowed: exact and trailing-wildcard only', () => {
  assert.ok(capabilityAllowed('fs:/workspace/src/a.mjs', ['fs:/workspace/*']));
  assert.ok(capabilityAllowed('exec:local', ['exec:local']));
  assert.ok(!capabilityAllowed('exec:remote:x', ['exec:local']));
  assert.ok(!capabilityAllowed('fs:/etc/passwd', ['fs:/workspace/*']));
});

test('hostAllowed: leading dot matches domain and subdomains', () => {
  assert.ok(hostAllowed('api.github.com', ['.github.com']));
  assert.ok(hostAllowed('github.com', ['.github.com']));
  assert.ok(!hostAllowed('evil.com', ['.github.com']));
  assert.ok(hostAllowed('anything', ['*']));
});

test('staircase: counts only off-envelope grants, once each, escalating', () => {
  const env = normalizeEnvelope({ task: 't', capabilities: ['exec:local'] });
  const events = [
    ev({ seq: 1, action: 'proc.spawn', capability_grant: ['exec:local'] }),        // in envelope
    ev({ seq: 2, action: 'cred.acquire', capability_grant: ['cloud:iam:role'] }),   // rung 1
    ev({ seq: 3, action: 'cred.acquire', capability_grant: ['cloud:iam:role'] }),   // dup, ignored
    ev({ seq: 4, action: 'proc.spawn', capability_grant: ['net:egress:internet'] }),// rung 2
  ];
  const signals = staircase.detect(events, env);
  assert.equal(signals.length, 2);
  assert.equal(signals[0].evidence.rung, 1);
  assert.equal(signals[1].evidence.rung, 2);
  assert.ok(signals[1].severity > signals[0].severity);
});

test('reassembly: fires only on 2+ fragments from distinct actions converging on egress', () => {
  const events = [
    ev({ seq: 1, action: 'cred.acquire', produces: [{ id: 'f1', len: 20, entropy: 4 }] }),
    ev({ seq: 2, action: 'cred.acquire', produces: [{ id: 'f2', len: 20, entropy: 4 }] }),
    ev({ seq: 3, action: 'http.request', target: { host: 'x.com', external: true }, consumes: ['f1', 'f2'] }),
  ];
  const signals = reassembly.detect(events);
  assert.equal(signals.length, 1);
  assert.equal(signals[0].evidence.fragments.length, 2);
});

test('reassembly: a single fragment to egress is NOT trajectory-level (redstamp owns it)', () => {
  const events = [
    ev({ seq: 1, action: 'cred.acquire', produces: [{ id: 'f1', len: 40, entropy: 5 }] }),
    ev({ seq: 2, action: 'http.request', target: { host: 'x.com', external: true }, consumes: ['f1'] }),
  ];
  assert.equal(reassembly.detect(events).length, 0);
});

test('reassembly: two fragments from the SAME action do not count (not fragmentation)', () => {
  const events = [
    ev({ seq: 1, action: 'cred.acquire', produces: [{ id: 'f1', len: 20, entropy: 4 }, { id: 'f2', len: 20, entropy: 4 }] }),
    ev({ seq: 2, action: 'http.request', target: { host: 'x.com', external: true }, consumes: ['f1', 'f2'] }),
  ];
  assert.equal(reassembly.detect(events).length, 0);
});

test('egress: a single off-envelope READ is not a finding', () => {
  // Calibration lesson from 380 real sessions: an agent reading one unexpected
  // page is normal, and treating it as a finding produced a 34% flag rate.
  const env = normalizeEnvelope({ task: 't', egress: { allow: ['.github.com'] } });
  const events = [
    ev({ seq: 1, target: { host: 'api.github.com', external: true } }),
    ev({ seq: 2, target: { host: 'arxiv.org', external: true } }),
  ];
  assert.equal(egress.detect(events, env).length, 0);
});

test('egress: a WRITE to an off-envelope host fires', () => {
  const env = normalizeEnvelope({ task: 't', egress: { allow: ['.github.com'] } });
  const events = [ev({ seq: 1, target: { host: 'evil.com', external: true }, bytes_out: 65536 })];
  const signals = egress.detect(events, env);
  assert.equal(signals.length, 1);
  assert.match(signals[0].label, /data write/);
});

test('egress: credential-bearing egress outranks a plain write', () => {
  const env = normalizeEnvelope({ task: 't', egress: { allow: [] } });
  const write = egress.detect(
    [ev({ seq: 1, target: { host: 'evil.com', external: true }, bytes_out: 65536 })],
    env,
  );
  const credentialed = egress.detect(
    [ev({ seq: 1, target: { host: 'evil.com', external: true }, consumes: ['f1'] })],
    env,
  );
  assert.equal(credentialed.length, 1);
  assert.match(credentialed[0].label, /credentialed/);
  assert.ok(credentialed[0].severity > write[0].severity);
});

test('egress: read topology fires once per session, not once per host', () => {
  const env = normalizeEnvelope({
    task: 't',
    egress: { allow: [], mode: 'open_read' },
    budget: { max_distinct_hosts: 3 },
  });
  const events = [];
  for (let i = 0; i < 20; i++) {
    events.push(ev({ seq: i + 1, target: { host: `host${i}.example`, external: true } }));
  }
  const topology = egress.detect(events, env).filter((s) => s.label.startsWith('read topology'));
  assert.equal(topology.length, 1, 'exactly one topology signal per session');
  assert.ok(topology[0].severity <= 0.15, `open_read topology must stay weak, got ${topology[0].severity}`);
});

test('egress: allowlist mode scores read drift harder than open_read', () => {
  const events = [];
  for (let i = 0; i < 10; i++) {
    events.push(ev({ seq: i + 1, target: { host: `host${i}.example`, external: true } }));
  }
  const strict = egress.detect(
    events,
    normalizeEnvelope({ task: 't', egress: { allow: [], mode: 'allowlist' }, budget: { max_distinct_hosts: 2 } }),
  ).find((s) => s.label.startsWith('read topology'));
  const open = egress.detect(
    events,
    normalizeEnvelope({ task: 't', egress: { allow: [], mode: 'open_read' }, budget: { max_distinct_hosts: 2 } }),
  ).find((s) => s.label.startsWith('read topology'));
  assert.ok(strict.severity > open.severity);
});

test('egress: denied off-envelope attempts do not score (the guard already stopped them)', () => {
  const env = normalizeEnvelope({ task: 't', egress: { allow: [] } });
  const events = [ev({ seq: 1, target: { host: 'evil.com', external: true }, outcome: 'denied' })];
  assert.equal(egress.detect(events, env).length, 0);
});

test('egress: C2 rotation fires at the third distinct public staging host', () => {
  const env = normalizeEnvelope({ task: 't', egress: { allow: ['*'] } }); // hosts allowed; rotation still flagged
  const events = [
    ev({ seq: 1, target: { host: 'raw.githubusercontent.com', external: true } }),
    ev({ seq: 2, target: { host: 'pastebin.com', external: true } }),
    ev({ seq: 3, target: { host: 'transfer.sh', external: true } }),
  ];
  const signals = egress.detect(events, env).filter((s) => s.label.startsWith('C2'));
  assert.equal(signals.length, 1);
  assert.equal(signals[0].evidence.hosts.length, 3);
});

test('ratchet: 2 denials then an equivalent success fires; a bare retry does not', () => {
  const events = [
    ev({ seq: 1, action: 'http.request', target: { host: 'h', path: '/admin/x' }, outcome: 'denied' }),
    ev({ seq: 2, action: 'http.request', target: { host: 'h', path: '/admin/y' }, outcome: 'denied' }),
    ev({ seq: 3, action: 'http.request', target: { host: 'h', path: '/admin/z' }, outcome: 'ok' }),
  ];
  const signals = ratchet.detect(events);
  assert.equal(signals.length, 1);
  assert.deepEqual(signals[0].evidence.denied_at_seqs, [1, 2]);
});

test('ratchet: shell commands are compared by invoked binary, not lumped together', () => {
  // The 98-false-positive bug: without target.op every proc.spawn in a session
  // shared one key, so two unrelated denials plus any later success fired.
  const events = [
    ev({ seq: 1, action: 'proc.spawn', target: { op: 'docker' }, outcome: 'denied' }),
    ev({ seq: 2, action: 'proc.spawn', target: { op: 'systemctl' }, outcome: 'denied' }),
    ev({ seq: 3, action: 'proc.spawn', target: { op: 'ls' }, outcome: 'ok' }),
  ];
  assert.equal(ratchet.detect(events).length, 0, 'unrelated binaries must not collide');
});

test('ratchet: repeated denials of the SAME binary then success does fire', () => {
  const events = [
    ev({ seq: 1, action: 'proc.spawn', target: { op: 'docker' }, outcome: 'denied' }),
    ev({ seq: 2, action: 'proc.spawn', target: { op: 'docker' }, outcome: 'denied' }),
    ev({ seq: 3, action: 'proc.spawn', target: { op: 'docker' }, outcome: 'ok' }),
  ];
  const signals = ratchet.detect(events);
  assert.equal(signals.length, 1);
  assert.equal(signals[0].evidence.intent_key.includes('docker'), true);
});

test('ratchet: an action with no host, path or op is not comparable', () => {
  const events = [
    ev({ seq: 1, action: 'state.write', outcome: 'denied' }),
    ev({ seq: 2, action: 'state.write', outcome: 'denied' }),
    ev({ seq: 3, action: 'state.write', outcome: 'ok' }),
  ];
  assert.equal(ratchet.detect(events).length, 0);
});

test('ratchet: one denial then success is a normal retry, not a ratchet', () => {
  const events = [
    ev({ seq: 1, action: 'http.request', target: { host: 'h', path: '/admin/x' }, outcome: 'denied' }),
    ev({ seq: 2, action: 'http.request', target: { host: 'h', path: '/admin/x' }, outcome: 'ok' }),
  ];
  assert.equal(ratchet.detect(events).length, 0);
});

test('recon: many endpoints + high failure ratio fires above tolerated probe ratio', () => {
  const env = normalizeEnvelope({ task: 't', budget: { max_probe_ratio: 0.3 } });
  const events = [];
  for (let i = 0; i < 20; i++) {
    events.push(ev({ seq: i, target: { host: 'h', path: `/probe/${i}` }, outcome: 'error', status: 403 }));
  }
  const signals = recon.detect(events, env);
  assert.equal(signals.length, 1);
  assert.equal(signals[0].evidence.distinct_endpoints, 20);
});

test('recon: a well-behaved client under the probe ratio stays silent', () => {
  const env = normalizeEnvelope({ task: 't', budget: { max_probe_ratio: 0.5 } });
  const events = [];
  for (let i = 0; i < 20; i++) {
    events.push(ev({ seq: i, target: { host: 'h', path: `/api/${i}` }, outcome: 'ok', status: 200 }));
  }
  assert.equal(recon.detect(events, env).length, 0);
});

test('fanout: instance count beyond budget fires at the crossing point', () => {
  const env = normalizeEnvelope({ task: 't', budget: { max_instances: 2 } });
  const events = [
    ev({ seq: 1, instance: 'a' }),
    ev({ seq: 2, instance: 'b' }),
    ev({ seq: 3, instance: 'c' }),
    ev({ seq: 4, instance: 'd' }),
  ];
  const signals = fanout.detect(events, env);
  assert.equal(signals.length, 1);
  assert.equal(signals[0].seq, 3);
  assert.equal(signals[0].evidence.instances_observed, 4);
});

test('undeclared envelope makes every capability off-envelope', () => {
  const env = undeclaredEnvelope();
  const events = [ev({ seq: 1, action: 'proc.spawn', capability_grant: ['exec:local'] })];
  assert.equal(staircase.detect(events, env).length, 1);
});

test('runDetectors returns signals sorted by seq', () => {
  const env = normalizeEnvelope({ task: 't', capabilities: [], egress: { allow: [] } });
  const events = parseTrajectory(
    [
      JSON.stringify({ v: 1, session: 's', seq: 5, action: 'cred.acquire', capability_grant: ['cloud:x'] }),
      JSON.stringify({ v: 1, session: 's', seq: 2, action: 'http.request', target: { host: 'e.com', external: true } }),
    ].join('\n'),
  );
  const signals = runDetectors(events, env);
  assert.ok(signals[0].seq <= signals[signals.length - 1].seq);
});
