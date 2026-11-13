/**
 * Profiles that extend another.
 *
 * A machine's own hosts are declared by extending a shipped profile, so the
 * merge has to add and never cut: a child that could drop a base capability by
 * omission, or a chain that loaded half way, would score against an envelope
 * nobody wrote.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadProfile } from '../src/scan.mjs';
import { capabilityAllowed, hostAllowed } from '../src/envelope.mjs';

function withDir(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'plumbline-profile-'));
  try {
    for (const [name, body] of Object.entries(files)) {
      const path = join(dir, name);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, typeof body === 'string' ? body : JSON.stringify(body));
    }
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('a profile without extends loads exactly as written', () => {
  const base = loadProfile('dev-workstation');
  assert.equal(base.name, 'dev-workstation');
  assert.equal(base.extends, undefined);
  withDir({ 'p.json': { name: 'mine', capabilities: ['exec:local'] } }, (dir) => {
    assert.deepEqual(loadProfile(join(dir, 'p.json')), { name: 'mine', capabilities: ['exec:local'] });
  });
});

test('extends adds capabilities and hosts to the base and keeps all of the base', () => {
  const base = loadProfile('dev-workstation');
  withDir({
    'mine.json': {
      extends: 'dev-workstation',
      capabilities: ['exec:remote:build-01', 'net:transfer:build-01'],
      egress: { allow: ['artifacts.example.internal'] },
    },
  }, (dir) => {
    const p = loadProfile(join(dir, 'mine.json'));
    for (const c of base.capabilities) assert.ok(p.capabilities.includes(c), `lost base capability ${c}`);
    for (const h of base.egress.allow) assert.ok(p.egress.allow.includes(h), `lost base host ${h}`);
    assert.ok(capabilityAllowed('exec:remote:build-01', p.capabilities));
    assert.ok(capabilityAllowed('net:transfer:build-01', p.capabilities));
    assert.ok(!capabilityAllowed('exec:remote:build-02', p.capabilities), 'only the named host is added');
    assert.ok(hostAllowed('artifacts.example.internal', p.egress.allow));
    assert.equal(p.egress.mode, base.egress.mode, 'mode comes from the base when the child sets none');
    assert.equal(p.extends, undefined);
    assert.equal(p.name, 'dev-workstation (extended)', 'an unnamed child is not reported as the stock profile');
  });
});

test('a child cannot drop a base capability by leaving it out', () => {
  withDir({ 'narrow.json': { extends: 'dev-workstation', capabilities: [] } }, (dir) => {
    const p = loadProfile(join(dir, 'narrow.json'));
    assert.deepEqual(p.capabilities, loadProfile('dev-workstation').capabilities);
  });
});

test('scalars and budget keys of the child override the base; lists do not duplicate', () => {
  withDir({
    'b.json': { name: 'b', capabilities: ['exec:local'], egress: { mode: 'open_read', allow: ['a.example'] }, budget: { max_distinct_hosts: 4, max_instances: 2 } },
    'c.json': { extends: './b.json', name: 'c', capabilities: ['exec:local', 'x'], egress: { mode: 'allowlist', allow: ['a.example'] }, budget: { max_distinct_hosts: 9 } },
  }, (dir) => {
    const p = loadProfile(join(dir, 'c.json'));
    assert.equal(p.name, 'c');
    assert.deepEqual(p.capabilities, ['exec:local', 'x']);
    assert.deepEqual(p.egress, { mode: 'allowlist', allow: ['a.example'] });
    assert.deepEqual(p.budget, { max_distinct_hosts: 9, max_instances: 2 });
  });
});

test('a chain merges in order and a relative path is read from the extending file', () => {
  withDir({
    'base/root.json': { name: 'root', capabilities: ['a'] },
    'mid/mid.json': { extends: '../base/root.json', name: 'mid', capabilities: ['b'] },
    'leaf.json': { extends: './mid/mid.json', capabilities: ['c'] },
  }, (dir) => {
    const p = loadProfile(join(dir, 'leaf.json'));
    assert.deepEqual(p.capabilities, ['a', 'b', 'c']);
    assert.equal(p.name, 'mid (extended)');
  });
});

test('a cycle, a missing base, a bad extends value or a non-object fails instead of loading part of a chain', () => {
  withDir({
    'x.json': { extends: './y.json', capabilities: ['x'] },
    'y.json': { extends: './x.json', capabilities: ['y'] },
    'self.json': { extends: './self.json' },
    'missing.json': { extends: './nowhere.json' },
    'number.json': { extends: 7 },
    'empty.json': { extends: '' },
    'array.json': { extends: './list.json' },
    'list.json': '["exec:local"]',
  }, (dir) => {
    assert.throws(() => loadProfile(join(dir, 'x.json')), /cycle/);
    assert.throws(() => loadProfile(join(dir, 'self.json')), /cycle/);
    assert.throws(() => loadProfile(join(dir, 'missing.json')), /no such profile/);
    assert.throws(() => loadProfile(join(dir, 'number.json')), /must be a profile name or path/);
    assert.throws(() => loadProfile(join(dir, 'empty.json')), /must be a profile name or path/);
    assert.throws(() => loadProfile(join(dir, 'array.json')), /not a JSON object/);
  });
});

test('a chain longer than the cap fails', () => {
  const files = { 'p0.json': { capabilities: ['p0'] } };
  for (let i = 1; i <= 8; i++) files[`p${i}.json`] = { extends: `./p${i - 1}.json`, capabilities: [`p${i}`] };
  withDir(files, (dir) => {
    assert.deepEqual(loadProfile(join(dir, 'p7.json')).capabilities, ['p0', 'p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7']);
    assert.throws(() => loadProfile(join(dir, 'p8.json')), /longer than 8/);
  });
});

test('malformed lists and objects in a child are ignored, not spread', () => {
  withDir({ 'm.json': { extends: 'dev-workstation', capabilities: 'exec:remote:x', egress: 'open', budget: [1] } }, (dir) => {
    const base = loadProfile('dev-workstation');
    const p = loadProfile(join(dir, 'm.json'));
    assert.deepEqual(p.capabilities, base.capabilities);
    assert.deepEqual(p.egress, base.egress);
    assert.deepEqual(p.budget, base.budget ?? {});
  });
});

test('an explicit relative extends reads the sibling file even when its name matches a shipped profile', () => {
  withDir({
    'dev-workstation': { name: 'local base', capabilities: ['local-only'] },
    'child.json': { extends: './dev-workstation', capabilities: ['c'] },
  }, (dir) => {
    const p = loadProfile(join(dir, 'child.json'));
    assert.deepEqual(p.capabilities, ['local-only', 'c']);
    assert.equal(p.name, 'local base (extended)');
  });
});
