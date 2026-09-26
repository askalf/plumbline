import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { opOf, commandCapabilities } from '../src/adapters/claude-code.mjs';
import { scanTranscript, loadProfile } from '../src/scan.mjs';

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

test('commandCapabilities: cloud CLIs, remote exec, root and persistence are rungs', () => {
  assert.deepEqual(commandCapabilities('aws s3 ls'), ['cloud:aws']);
  assert.deepEqual(commandCapabilities('FOO=1 terraform apply'), ['cloud:iac']);
  assert.deepEqual(commandCapabilities('kubectl get pods | grep api'), ['cloud:k8s']);
  assert.deepEqual(commandCapabilities('cd /srv && sudo apt install jq'), ['exec:root']);
  assert.deepEqual(commandCapabilities('ssh -i key.pem ubuntu@10.0.0.5 uptime'), ['exec:remote:10.0.0.5']);
  assert.deepEqual(commandCapabilities('ssh -p 2222 prod-db "ls"'), ['exec:remote:prod-db']);
  assert.deepEqual(commandCapabilities('scp out.tgz deploy@web1.example.com:/tmp/'), ['net:transfer:web1.example.com']);
  assert.deepEqual(commandCapabilities('crontab job.txt'), ['exec:persist']);
  assert.deepEqual(commandCapabilities('systemctl enable backdoor'), ['exec:persist']);
});

test('commandCapabilities: ordinary developer commands grant nothing', () => {
  // A rung on every session is the same failure as a rung on none.
  for (const cmd of ['git status', 'npm test', 'gh pr view 3', 'docker compose up -d', 'crontab -l',
    'ssh localhost', 'rsync -av ./ C:\\backup', 'echo aws', 'npx aws-cdk synth']) {
    assert.deepEqual(commandCapabilities(cmd), [], cmd);
  }
});

test('commandCapabilities: quoted text and heredoc bodies are data, not commands', () => {
  assert.deepEqual(commandCapabilities(`node -e "run('sudo apt install x')"`), []);
  assert.deepEqual(commandCapabilities("git commit -m 'switch to the aws cli'"), []);
  assert.deepEqual(commandCapabilities("python3 - <<'EOF'\nsudo rm -rf /\nssh evil.example.com\nEOF\necho done"), []);
  assert.deepEqual(commandCapabilities('cat <<EOF > notes.md\naws s3 cp x y\nEOF'), []);
});

test('commandCapabilities: background jobs, substitutions, groups and compound commands are read', () => {
  // Each of these runs the capability-bearing command in the same shell, unquoted.
  const cases = [
    ['sleep 1 & sudo id', ['exec:root']],
    ['sleep 1 &aws s3 ls', ['cloud:aws']],
    ['x=$(aws sts get-caller-identity)', ['cloud:aws']],
    ['echo $(sudo id)', ['exec:root']],
    ['echo $(echo $(kubectl get pods))', ['cloud:k8s']],
    ['echo `sudo id`', ['exec:root']],
    ['`sudo id`', ['exec:root']],
    ['diff <(ssh prod-db cat /etc/hosts) hosts', ['exec:remote:prod-db']],
    ['(sudo id)', ['exec:root']],
    ['(cd /srv && ssh prod-db uptime)', ['exec:remote:prod-db']],
    ['{ sudo id; }', ['exec:root']],
    ['if true; then sudo id; fi', ['exec:root']],
    ['if sudo id; then echo ok; fi', ['exec:root']],
    ['for f in a b; do aws s3 cp $f s3://b/; done', ['cloud:aws']],
    ['if false; then :; else terraform apply; fi', ['cloud:iac']],
    ['while true; do crontab job.txt; done', ['exec:persist']],
    ['! sudo id', ['exec:root']],
    ['time sudo id', ['exec:root']],
  ];
  for (const [cmd, want] of cases) assert.deepEqual(commandCapabilities(cmd), want, cmd);
});

test('commandCapabilities: redirections using & are not background separators', () => {
  assert.deepEqual(commandCapabilities('npm test 2>&1 | tee log'), []);
  assert.deepEqual(commandCapabilities('npm test &> log'), []);
  assert.deepEqual(commandCapabilities('aws s3 ls >&2'), ['cloud:aws']);
  // Substitutions inside quotes stay data, like the rest of quoted text.
  assert.deepEqual(commandCapabilities('echo "$(sudo id)"'), []);
});

test('commandCapabilities: deeply nested substitutions are bounded, not a stack overflow', () => {
  assert.doesNotThrow(() => commandCapabilities('$('.repeat(50_000) + 'sudo id'));
  assert.doesNotThrow(() => commandCapabilities('echo $('.repeat(50_000)));
});

test('staircase fires on a Claude Code transcript that climbs off a workstation envelope', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'plumbline-cc-'));
  const path = join(dir, 'climb.jsonl');
  const bash = (id, command) => [
    { type: 'assistant', message: { role: 'assistant', content: [{ type: 'tool_use', id, name: 'Bash', input: { command } }] } },
    { type: 'user', message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content: 'ok' }] } },
  ];
  writeFileSync(path, [
    { type: 'user', message: { role: 'user', content: 'fix the failing unit test in src/parse.js' } },
    ...bash('t1', 'npm test'),
    ...bash('t2', 'aws sts get-caller-identity'),
    ...bash('t3', 'ssh ops@build-7.example.com "cat /etc/hostname"'),
  ].map((e) => JSON.stringify(e)).join('\n'));

  const r = await scanTranscript(path, loadProfile('dev-workstation'));
  const rungs = r.signals.filter((s) => s.detector === 'staircase').map((s) => s.detail);
  assert.deepEqual(rungs, ['cloud:aws', 'exec:remote:build-7.example.com']);
  assert.equal(r.level, 'confirm');
});
