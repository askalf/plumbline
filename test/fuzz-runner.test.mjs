/**
 * fuzz/run.mjs, the fuzz runner CI uses.
 *
 * Each test copies the runner into a scratch tree next to a stand-in for Jazzer's CLI, so the
 * scheduling is exercised without Jazzer. A target's name says how its stand-in behaves:
 * `<label>_<ok|failN>_<ms>` sleeps <ms> and exits 0 or N. The stand-in logs when each target
 * starts and ends, which gives the launch order and how many ran at once.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(here, '..', 'fuzz', 'run.mjs');

const STUB = `
const { appendFileSync } = require('node:fs');
const path = require('node:path');
const name = path.basename(process.argv[2]).replace(/\\.fuzz$/, '');
const [, kind, ms] = name.split('_');
const log = process.env.STUB_LOG;
appendFileSync(log, 'start ' + name + '\\n');
process.stdout.write(name + ' first\\n');
setTimeout(() => {
  process.stdout.write(name + ' last\\n');
  appendFileSync(log, 'end ' + name + '\\n');
  process.exit(kind === 'ok' ? 0 : Number(kind.slice(4)));
}, Number(ms));
`;

function run(targets, jobs) {
  const root = mkdtempSync(join(tmpdir(), 'plumbline-fuzz-'));
  mkdirSync(join(root, 'fuzz'));
  copyFileSync(RUNNER, join(root, 'fuzz', 'run.mjs'));
  for (const t of targets) writeFileSync(join(root, 'fuzz', `${t}.fuzz.js`), '');
  const core = join(root, '.clusterfuzzlite', 'node_modules', '@jazzer.js', 'core');
  mkdirSync(join(core, 'dist'), { recursive: true });
  writeFileSync(join(root, '.clusterfuzzlite', 'package.json'), '{"private":true}');
  writeFileSync(join(core, 'package.json'), '{"name":"@jazzer.js/core","version":"0.0.0"}');
  writeFileSync(join(core, 'dist', 'cli.js'), STUB);
  const log = join(root, 'stub.log');
  writeFileSync(log, '');
  const env = { ...process.env, STUB_LOG: log, FUZZ_SECONDS: '1' };
  for (const k of ['FUZZ_JOBS', 'FUZZ_CORPUS_DIR', 'FUZZ_ARTIFACT_DIR']) delete env[k];
  if (jobs !== undefined) env.FUZZ_JOBS = jobs;
  const r = spawnSync(process.execPath, [join('fuzz', 'run.mjs')], { cwd: root, env, encoding: 'utf8' });
  const events = readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => l.split(' '));
  let live = 0;
  let peak = 0;
  for (const [ev] of events) {
    live += ev === 'start' ? 1 : -1;
    peak = Math.max(peak, live);
  }
  return {
    status: r.status,
    stdout: r.stdout,
    stderr: r.stderr,
    started: events.filter(([ev]) => ev === 'start').map(([, n]) => n),
    ended: events.filter(([ev]) => ev === 'end').map(([, n]) => n),
    peak,
  };
}

const OK3 = ['a_ok_400', 'b_ok_400', 'c_ok_400'];

// With more than one job, every header is followed directly by that target's own two lines.
function assertGrouped(stdout, names) {
  const lines = stdout.split('\n');
  for (const n of names) {
    const i = lines.indexOf(`=== fuzzing ${n} (1s) ===`);
    assert.ok(i >= 0, `no header for ${n}`);
    assert.deepEqual(lines.slice(i + 1, i + 3), [`${n} first`, `${n} last`]);
  }
}

test('without FUZZ_JOBS the targets run one after another', () => {
  const r = run(OK3);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.started, OK3);
  assert.deepEqual(r.ended, OK3);
  assert.equal(r.peak, 1);
  for (const n of OK3) assert.match(r.stdout, new RegExp(`=== fuzzing ${n} \\(1s\\) ===`));
});

test('FUZZ_JOBS bounds how many targets run at once and groups each one\'s output', () => {
  const r = run(OK3, '2');
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual([...r.started].sort(), OK3);
  assert.deepEqual([...r.ended].sort(), OK3);
  assert.equal(r.peak, 2);
  assertGrouped(r.stdout, OK3);
});

test('a FUZZ_JOBS that is not a positive number counts as 1', () => {
  for (const jobs of ['abc', '0', '-2']) {
    const r = run(OK3, jobs);
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.started, OK3, `FUZZ_JOBS=${jobs}`);
    assert.equal(r.peak, 1, `FUZZ_JOBS=${jobs}`);
  }
});

test('a FUZZ_JOBS above the number of targets is capped at that number', () => {
  const r = run(OK3, '9');
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.started.length, 3);
  assert.equal(r.peak, 3);
  assertGrouped(r.stdout, OK3);
});

test('with one job a failing target stops the queue', () => {
  const r = run(['a_ok_50', 'b_fail3_50', 'c_ok_50']);
  assert.equal(r.status, 3);
  assert.deepEqual(r.started, ['a_ok_50', 'b_fail3_50']);
  assert.match(r.stderr, /b_fail3_50: jazzer exited with 3/);
});

test('with several jobs a failure stops queued targets but lets running ones finish', () => {
  const r = run(['a_fail3_50', 'b_ok_800', 'c_ok_50'], '2');
  assert.equal(r.status, 3);
  assert.deepEqual([...r.started].sort(), ['a_fail3_50', 'b_ok_800']);
  assert.deepEqual([...r.ended].sort(), ['a_fail3_50', 'b_ok_800']);
  assertGrouped(r.stdout, ['a_fail3_50', 'b_ok_800']);
  assert.match(r.stderr, /a_fail3_50: jazzer exited with 3/);
});

test('every failure is reported and the run exits with the first one\'s status', () => {
  const r = run(['a_fail3_800', 'b_fail5_50', 'c_ok_50'], '2');
  assert.equal(r.status, 5);
  assert.deepEqual([...r.started].sort(), ['a_fail3_800', 'b_fail5_50']);
  assert.match(r.stderr, /b_fail5_50: jazzer exited with 5/);
  assert.match(r.stderr, /a_fail3_800: jazzer exited with 3/);
  assert.ok(r.stderr.indexOf('b_fail5_50') < r.stderr.indexOf('a_fail3_800'));
});
