import { test } from 'node:test';
import assert from 'node:assert/strict';
import { opOf } from '../src/adapters/claude-code.mjs';

test('opOf: plain command', () => {
  assert.equal(opOf('git status'), 'git');
});

test('opOf: skips env assignments and flags', () => {
  assert.equal(opOf('FOO=bar -v docker ps'), 'docker');
});

test('opOf: unwraps sudo/env/npx', () => {
  assert.equal(opOf('sudo systemctl restart nginx'), 'systemctl');
  assert.equal(opOf('npx tsc --noEmit'), 'tsc');
});

test('opOf: skips a cd segment AND its path argument', () => {
  // The bug that produced 6 of the last 11 false ratchets: nearly every shell
  // command on this box begins `cd <path>;`, so keying on `cd` collapsed them
  // all to one identity.
  assert.equal(opOf('cd "C:\\repo\\thing"; git log --oneline'), 'git');
  assert.equal(opOf('cd /srv/app && docker compose up -d'), 'docker');
  assert.equal(opOf('pushd x; npm test'), 'npm');
});

test('opOf: strips path and extension', () => {
  assert.equal(opOf('/usr/bin/python3 script.py'), 'python3');
  assert.equal(opOf('C:\\Windows\\System32\\where.exe node'), 'where');
});

test('opOf: distinguishes different binaries', () => {
  assert.notEqual(opOf('cd a; docker ps'), opOf('cd a; ls -la'));
});

test('opOf: returns null for an empty command', () => {
  assert.equal(opOf('   '), null);
  assert.equal(opOf('cd /tmp'), null);
});
