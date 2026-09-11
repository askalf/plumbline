/**
 * Report rendering.
 *
 * Two properties here are security properties, not cosmetics:
 *
 *  1. The report is SELF-CONTAINED. A security artifact that fetches a font or
 *     a script at open time phones somewhere every time a reviewer reads it,
 *     and stops rendering the moment it is opened on the air-gapped box where
 *     it matters most.
 *
 *  2. Trajectory text is ESCAPED. Paths, hosts and task strings come from a log
 *     the monitored agent writes. A renderer that interpolates them raw hands
 *     that agent script execution in the reviewer's browser - the monitored
 *     process attacking its own monitor's reader.
 *
 * And one honesty property: the reachability caveat must be ON the artifact.
 * An exported verdict that leaves its caveat behind in the terminal is worse
 * than the terminal output, because it looks authoritative.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { assessTrajectory } from '../src/index.mjs';
import { renderSessionReport, renderScanReport, escapeHtml } from '../src/report.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const corpus = (name) => readFileSync(join(here, '..', 'corpus', name), 'utf8');
const AT = { generatedAt: '2026-01-01T00:00:00.000Z', command: 'plumbline replay x.jsonl --report' };

/**
 * Anything that would make the browser reach out, or run something.
 *
 * Scoped to REAL TAGS and the stylesheet, not to raw text. A first version
 * grepped the whole document for `src=` and `onerror=`, and failed on its own
 * escaping test: the payload it had just correctly neutered still contained
 * those characters as visible text. Escaped text cannot fetch anything, so
 * matching it is a false positive that would train someone to weaken the test.
 */
function externalReference(html) {
  const tag = /<([a-z][^>]*)>/gi;
  let m;
  while ((m = tag.exec(html)) !== null) {
    const attrs = m[1];
    if (/^script\b/i.test(attrs)) return '<script>';
    if (/\son\w+\s*=/i.test(attrs)) return `event handler: ${attrs.slice(0, 60)}`;
    const ref = /\b(?:src|href|xlink:href|poster|action|formaction)\s*=\s*(['"]?)([^'">\s]*)\1/i.exec(attrs);
    // A scheme means it leaves the file. data: does not.
    if (ref && /^[a-z][a-z0-9+.-]*:/i.test(ref[2]) && !/^data:/i.test(ref[2])) return ref[2];
  }
  for (const style of html.matchAll(/<style>([\s\S]*?)<\/style>/gi)) {
    const css = /@import|url\(\s*['"]?(?!data:)/i.exec(style[1]);
    if (css) return `css: ${css[0]}`;
  }
  return null;
}

function sessionReport(name) {
  return renderSessionReport(assessTrajectory(corpus(name)), AT);
}

test('a session report reaches for nothing on the network', () => {
  for (const name of ['exploitgym.jsonl', 'evasion-residual-floor.jsonl', 'benign-repo-triage.jsonl']) {
    const html = sessionReport(name);
    const hit = externalReference(html);
    assert.equal(hit, null, `${name} report contains an external reference: ${hit}`);
  }
});

test('a scan report reaches for nothing on the network', () => {
  const summary = {
    profile: 'dev-workstation', sessions_assessed: 2, sessions_skipped: 0, tool_calls: 40,
    by_level: { observe: 2, warn: 0, confirm: 0, halt: 0 }, flagged: 0, flagged_ratio: 0,
    clean_ratio: 1, by_detector: {}, top: [],
    reachability: { adapter: 'claude-code', reachable_in_sessions: { siphon: 2 }, blind_spots: [], absent_from_corpus: [], clean_rate_is_meaningful: true },
  };
  const html = renderScanReport(summary, { skipped: [] }, AT);
  assert.equal(externalReference(html), null);
});

test('trajectory text cannot inject markup - the agent does not get the reader\'s browser', () => {
  // A path and a task an agent could choose freely. If either lands unescaped,
  // opening the report runs the agent's markup.
  const nasty = '</td></table><script>alert(1)</script>';
  const jsonl = [
    JSON.stringify({ v: 1, session: 's<img src=x onerror=alert(1)>', seq: 0, action: 'session.declare',
      envelope: { task: `build "the" thing ${nasty}`, capabilities: [`fs:${nasty}`], egress: { mode: 'allowlist', allow: [nasty] } } }),
    JSON.stringify({ v: 1, session: 's<img src=x onerror=alert(1)>', seq: 1, action: 'fs.read',
      target: { path: `/home/runner/.aws/credentials` }, outcome: 'ok' }),
    JSON.stringify({ v: 1, session: 's<img src=x onerror=alert(1)>', seq: 2, action: 'http.request',
      target: { host: `evil${nasty}.example`, external: true }, outcome: 'ok' }),
  ].join('\n');

  const html = renderSessionReport(assessTrajectory(jsonl), AT);

  assert.ok(!html.includes('<script>alert(1)</script>'), 'raw script tag reached the output');
  assert.ok(!html.includes('<img src=x'), 'raw img tag reached the output');
  // The payload SHOULD appear as escaped text, and that text contains the
  // literal strings `src=` and `onerror=`. The property is that no REAL tag
  // carries them.
  assert.equal(externalReference(html), null, 'the payload reached a real tag');
  // The text itself must still be visible, escaped - dropping it silently would
  // hide the very path a reviewer needs to see.
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), 'the text should appear, escaped');
});

test('escapeHtml covers the five characters that matter', () => {
  assert.equal(escapeHtml(`<a href="x" title='y'>&</a>`),
    '&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('the reachability caveat travels with the verdict, on the artifact', () => {
  // The floor corpus: clean, with three detectors that could not fire. The
  // report must not let a reader mistake that for proven-safe.
  const report = assessTrajectory(corpus('evasion-semantic-floor.jsonl'));
  assert.equal(report.level, 'observe');
  const html = renderSessionReport(report, AT);

  assert.match(html, /could not check/i, 'the caveat block must be present');
  for (const id of report.reachability.starved) {
    assert.ok(html.includes(id), `starved detector ${id} must be named on the report`);
  }
  assert.match(html, /indistinguishable from the outside/i, 'a clean verdict must carry the reason the caveat matters');
});

test('a report with nothing starved says so, without overclaiming', () => {
  const html = renderSessionReport(assessTrajectory(corpus('detector-exercise.jsonl')), AT);
  assert.match(html, /necessary, not sufficient/i,
    'even a fully-fed report must not imply that reachable means checked');
});

test('a scan whose clean rate is not meaningful says that above the number', () => {
  const summary = {
    profile: 'agent', sessions_assessed: 10, sessions_skipped: 0, tool_calls: 100,
    by_level: { observe: 10, warn: 0, confirm: 0, halt: 0 }, flagged: 0, flagged_ratio: 0,
    clean_ratio: 1, by_detector: {}, top: [],
    reachability: {
      adapter: 'forge', reachable_in_sessions: { staircase: 10 },
      blind_spots: [{ detector: 'ratchet', fields: ['outcome.denied'], reason: 'no refused call was seen in this corpus' }],
      absent_from_corpus: [], clean_rate_is_meaningful: false,
    },
  };
  const html = renderScanReport(summary, { skipped: [] }, AT);
  assert.match(html, /not a safety claim/i);
  assert.ok(html.includes('ratchet'), 'the structurally dead detector must be named');
  assert.match(html, /structurally dead/i);
});

test('drift is rendered to a consistent precision', () => {
  // 0.9182 beside 1 in one column reads as two different units.
  const html = sessionReport('exploitgym.jsonl');
  const cells = [...html.matchAll(/<td class="num">(\d[\d.]*)<\/td>/g)].map((m) => m[1]);
  const drifts = cells.filter((c) => c.includes('.'));
  assert.ok(drifts.length > 0, 'expected drift cells');
  for (const d of drifts) {
    assert.match(d, /^\d\.\d{2}$/, `drift ${d} is not two decimal places`);
  }
});

test('rendering is deterministic for a fixed timestamp', () => {
  assert.equal(sessionReport('exploitgym.jsonl'), sessionReport('exploitgym.jsonl'));
});

test('an empty scan says "no sessions", not "0.0% clean"', () => {
  // The first-run failure mode: someone points scan at the wrong directory. A
  // 0.0%-clean headline reads as an alarm about their agent when it is actually
  // a path problem.
  const summary = {
    profile: 'agent', sessions_assessed: 0, sessions_skipped: 0, tool_calls: 0,
    by_level: { observe: 0, warn: 0, confirm: 0, halt: 0 }, flagged: 0, flagged_ratio: 0,
    clean_ratio: 0, by_detector: {}, top: [],
    reachability: { adapter: 'claude-code', reachable_in_sessions: {}, blind_spots: [], absent_from_corpus: [], clean_rate_is_meaningful: true },
  };
  const html = renderScanReport(summary, { skipped: [] }, AT);
  assert.match(html, /no sessions/i);
  assert.ok(!html.includes('0.0%'), 'must not headline a clean rate it has no sessions for');
  assert.match(html, /--adapter/, 'and should point at the likely cause');
  assert.ok(!/NaN/.test(html), 'no NaN anywhere');
});
