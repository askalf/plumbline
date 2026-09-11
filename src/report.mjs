/**
 * Self-contained HTML reports.
 *
 * `plumbline scan` answers a question people are curious about before they are
 * worried: what did my coding agent actually do? That answer currently exists
 * only as terminal text, which nobody keeps and nobody can hand to anyone else.
 * This renders it as one HTML file with no external anything - no CDN, no font
 * fetch, no script that phones home - so it survives being emailed, attached to
 * a ticket, or opened from a USB stick on a machine with no network.
 *
 * Two rules the renderer exists to enforce:
 *
 *  1. THE CAVEAT TRAVELS WITH THE VERDICT. A clean report and a report from a
 *     monitor that could not see anything look identical from the outside, and
 *     an artifact that leaves the reachability caveat in the terminal it came
 *     from is worse than the terminal output - it looks authoritative. Every
 *     report here carries what could NOT be checked, in the same type size as
 *     what could.
 *
 *  2. TRAJECTORY TEXT IS UNTRUSTED. Paths, hosts, task strings and session ids
 *     come from a log written by the monitored agent. They are escaped on the
 *     way in, never interpolated raw: a tool that renders an attacker-chosen
 *     filename into executable markup is a tool that hands the agent the
 *     reviewer's browser. There is no script tag in the output at all, which
 *     makes the property testable rather than a matter of care.
 */

const LEVEL_ORDER = ['observe', 'warn', 'confirm', 'halt'];

/** Escape for HTML text and double-quoted attributes alike. */
export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const pct = (n) => `${(n * 100).toFixed(1)}%`;
/** Two places everywhere a drift is shown: 0.9182 and 1 in the same column read as different units. */
const d2 = (n) => Number(n).toFixed(2);
const esc = escapeHtml;

const STYLE = `
:root {
  --ground: #0e1418; --panel: #131c22; --raised: #17222a;
  --ink: #e9eff3; --ink-2: #b3c2cb; --muted: #6f8492; --line: #24323a;
  --brass: #c9a227; --steel: #5f8296; --warn: #c9a227; --confirm: #d08a3e; --halt: #c94b3f;
  --mono: ui-monospace, "SF Mono", "DejaVu Sans Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; padding: 32px 20px 64px; background: var(--ground); color: var(--ink);
  font-family: var(--sans); font-size: 15px; line-height: 1.55; }
.wrap { max-width: 940px; margin: 0 auto; }
h1 { font-size: 1.4rem; margin: 0 0 4px; letter-spacing: -0.02em; }
h2 { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.12em;
  color: var(--muted); margin: 34px 0 12px; font-weight: 600; }
a { color: var(--brass); }
.mark { font-family: var(--mono); font-weight: 600; letter-spacing: -0.03em; }
.mark .dot { color: var(--brass); }
.sub { color: var(--muted); font-size: 0.85rem; font-family: var(--mono); }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 18px 20px; margin-bottom: 14px; }
.verdict { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; }
.big { font-size: 1.9rem; font-weight: 700; letter-spacing: 0.02em; font-family: var(--mono); }
.lv-observe { color: var(--steel); } .lv-warn { color: var(--warn); }
.lv-confirm { color: var(--confirm); } .lv-halt { color: var(--halt); }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th, td { text-align: left; padding: 7px 10px 7px 0; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase;
  letter-spacing: 0.08em; }
td.num, th.num { text-align: right; font-family: var(--mono); }
code, .m { font-family: var(--mono); font-size: 0.85em; color: var(--ink-2); }
.kv { display: grid; grid-template-columns: 150px 1fr; gap: 4px 16px; font-size: 0.88rem; }
.kv dt { color: var(--muted); } .kv dd { margin: 0; font-family: var(--mono); word-break: break-word; }
.caveat { border-left: 3px solid var(--brass); background: var(--raised); padding: 14px 18px;
  border-radius: 0 8px 8px 0; margin-bottom: 14px; }
.caveat h3 { margin: 0 0 6px; font-size: 0.95rem; }
.caveat p { margin: 0 0 8px; color: var(--ink-2); font-size: 0.9rem; }
.caveat ul { margin: 6px 0 0; padding-left: 20px; color: var(--ink-2); font-size: 0.88rem; }
.pill { display: inline-block; font-family: var(--mono); font-size: 0.72rem; padding: 2px 8px;
  border: 1px solid var(--line); border-radius: 999px; color: var(--ink-2); margin: 0 6px 6px 0; }
.bar { display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: var(--raised);
  margin: 10px 0 6px; }
.bar span { display: block; }
.foot { color: var(--muted); font-size: 0.78rem; margin-top: 40px; border-top: 1px solid var(--line);
  padding-top: 14px; }
svg { display: block; width: 100%; height: auto; }
@media (max-width: 620px) { .kv { grid-template-columns: 1fr; } body { padding: 20px 14px 48px; } }
`;

function page(title, bodyHtml, meta) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>${STYLE}</style>
</head><body><div class="wrap">
${bodyHtml}
<p class="foot">
  Generated by <span class="mark">plumbline<span class="dot">.</span></span>
  &mdash; ${esc(meta.generatedAt)} &mdash; <code>${esc(meta.command)}</code><br>
  Read-only and out of band: this scores a trajectory after the fact and never blocked anything.
  A level is evidence for a human, not a verdict.<br>
  This file contains hosts, paths and task text taken from your own logs. Read it before sharing it.
</p>
</div></body></html>
`;
}

/** The block that must appear on every report, whatever the verdict. */
function caveatBlock({ starved = [], partial = [], envelopeWarnings = [], blindSpots = [], clean }) {
  const items = [];
  for (const id of starved) {
    items.push(`<li><code>${esc(id)}</code> could not fire &mdash; nothing in this trajectory carried the fields it reads</li>`);
  }
  for (const id of partial) {
    items.push(`<li><code>${esc(id)}</code> ran with some branches unreachable</li>`);
  }
  for (const b of blindSpots) {
    items.push(`<li><code>${esc(b.detector)}</code> is <strong>structurally dead</strong> for this adapter &mdash; ${esc(b.reason)}</li>`);
  }
  for (const w of envelopeWarnings) {
    items.push(`<li>envelope <code>${esc(w.field)}</code>: ${esc(w.note)}</li>`);
  }

  if (items.length === 0) {
    return `<div class="caveat">
  <h3>Every detector could fire here</h3>
  <p>No detector was starved of the fields it reads, and the declared envelope does not
  disable any of them. That is necessary, not sufficient: a detector can have everything
  it needs and still not meet its activation thresholds.</p>
</div>`;
  }

  return `<div class="caveat">
  <h3>What this report could not check</h3>
  <p>${clean
    ? 'A clean result and a detector that never had the data to look are indistinguishable from the outside. This one is not clean-and-proven; it is clean-and-partial, and here is the part:'
    : 'Whatever was found, these were not looked for:'}</p>
  <ul>${items.join('\n  ')}</ul>
</div>`;
}

/** Step chart of drift over the trajectory, as inline SVG. */
function driftChart(timeline, thresholds) {
  const W = 960;
  const H = 210;
  const PAD_L = 34;
  const PAD_R = 12;
  const PAD_T = 12;
  const PAD_B = 26;
  const plotW = W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;
  const y = (d) => PAD_T + plotH * (1 - Math.max(0, Math.min(1, d)));

  if (timeline.length === 0) {
    return `<svg viewBox="0 0 ${W} 60" role="img" aria-label="No signals: drift stayed at zero">
  <text x="${PAD_L}" y="34" fill="#6f8492" font-family="ui-monospace, monospace" font-size="15">
    no signals - drift stayed at 0 for the whole trajectory
  </text></svg>`;
  }

  const x = timeline.length === 1
    ? () => PAD_L + plotW / 2
    : (i) => PAD_L + (plotW * i) / (timeline.length - 1);

  const bands = [
    { from: thresholds.halt, to: 1, fill: '#c94b3f' },
    { from: thresholds.confirm, to: thresholds.halt, fill: '#d08a3e' },
    { from: thresholds.warn, to: thresholds.confirm, fill: '#c9a227' },
  ].map((b) => `<rect x="${PAD_L}" y="${y(b.to)}" width="${plotW}" height="${y(b.from) - y(b.to)}" fill="${b.fill}" opacity="0.07"/>`);

  const rules = [thresholds.warn, thresholds.confirm, thresholds.halt].map((t) =>
    `<line x1="${PAD_L}" y1="${y(t)}" x2="${W - PAD_R}" y2="${y(t)}" stroke="#24323a" stroke-dasharray="3 4"/>
     <text x="4" y="${y(t) + 4}" fill="#6f8492" font-family="ui-monospace, monospace" font-size="10">${t}</text>`);

  // Step path: drift holds its value until the next scored action.
  let d = `M ${x(0)} ${y(0)}`;
  timeline.forEach((point, i) => {
    d += ` L ${x(i)} ${y(i === 0 ? 0 : timeline[i - 1].drift)} L ${x(i)} ${y(point.drift)}`;
  });
  d += ` L ${W - PAD_R} ${y(timeline[timeline.length - 1].drift)}`;

  const dots = timeline.map((p, i) => {
    const colour = { observe: '#5f8296', warn: '#c9a227', confirm: '#d08a3e', halt: '#c94b3f' }[p.level];
    return `<circle cx="${x(i)}" cy="${y(p.drift)}" r="3.5" fill="${colour}"><title>seq ${esc(p.seq)} - drift ${esc(d2(p.drift))} - ${esc(p.dominant.detector)}: ${esc(p.dominant.label)}</title></circle>`;
  });

  return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Drift over the trajectory, rising to ${esc(d2(timeline[timeline.length - 1].drift))}">
  ${bands.join('\n  ')}
  ${rules.join('\n  ')}
  <path d="${d}" fill="none" stroke="#c9a227" stroke-width="2" stroke-linejoin="round"/>
  ${dots.join('\n  ')}
  <text x="${PAD_L}" y="${H - 8}" fill="#6f8492" font-family="ui-monospace, monospace" font-size="10">seq ${esc(timeline[0].seq)}</text>
  <text x="${W - PAD_R}" y="${H - 8}" text-anchor="end" fill="#6f8492" font-family="ui-monospace, monospace" font-size="10">seq ${esc(timeline[timeline.length - 1].seq)}</text>
</svg>`;
}

/**
 * One trajectory, as a page. Takes the object `assess()` returns.
 */
export function renderSessionReport(report, { command = 'plumbline replay', generatedAt = new Date().toISOString(), source = null } = {}) {
  const env = report.envelope;
  const starved = report.reachability?.starved ?? [];
  const partial = report.reachability?.partial ?? [];

  const rows = report.timeline.map((p) => `<tr>
    <td class="num">${esc(p.seq)}</td>
    <td class="num">${esc(d2(p.drift))}</td>
    <td><span class="lv-${esc(p.level)}">${esc(p.level)}</span></td>
    <td><code>${esc(p.dominant.detector)}</code></td>
    <td>${esc(p.dominant.label)}${p.dominant.detail ? ` <span class="m">${esc(p.dominant.detail)}</span>` : ''}</td>
  </tr>`);

  const body = `
<h1><span class="mark">plumbline<span class="dot">.</span></span> trajectory report</h1>
<p class="sub">${esc(report.session ?? 'unnamed session')}${source ? ` &middot; ${esc(source)}` : ''}</p>

<div class="card">
  <div class="verdict">
    <span class="big lv-${esc(report.level)}">${esc(String(report.level).toUpperCase())}</span>
    <span class="m">drift ${esc(d2(report.drift))}</span>
    ${report.earliest_actionable !== null && report.earliest_actionable !== undefined
      ? `<span class="m">&middot; first actionable at seq ${esc(report.earliest_actionable)}</span>` : ''}
    <span class="m">&middot; ${esc(report.events)} events</span>
  </div>
</div>

<h2>Drift against the declared job</h2>
<div class="card">${driftChart(report.timeline, report.thresholds)}</div>

<h2>The intent envelope</h2>
<div class="card"><dl class="kv">
  <dt>task</dt><dd>${env.task ? esc(env.task) : '<span class="m">none declared</span>'}</dd>
  <dt>declared</dt><dd>${env.declared ? 'yes' : 'no &mdash; scored as undeclared, so everything reads off-envelope'}</dd>
  <dt>capabilities</dt><dd>${env.capabilities.length ? env.capabilities.map((c) => `<span class="pill">${esc(c)}</span>`).join('') : '<span class="m">none</span>'}</dd>
  <dt>egress</dt><dd>${esc(env.egress.mode)}${env.egress.allow.length ? ` &middot; ${env.egress.allow.map((h) => `<span class="pill">${esc(h)}</span>`).join('')}` : ''}</dd>
</dl></div>

${caveatBlock({ starved, partial, envelopeWarnings: report.envelope_warnings ?? [], clean: report.level === 'observe' })}

<h2>${rows.length > 0 ? 'What fired, in order' : 'Nothing fired'}</h2>
<div class="card">
${rows.length > 0
  ? `<table><thead><tr><th class="num">seq</th><th class="num">drift</th><th>level</th><th>detector</th><th>finding</th></tr></thead>
<tbody>${rows.join('\n')}</tbody></table>`
  : '<p class="sub">No detector produced a signal on this trajectory. Read the block above before taking that as safety.</p>'}
</div>`;

  return page(`plumbline - ${report.session ?? 'trajectory'}`, body, { command, generatedAt });
}

/**
 * A corpus of sessions, as a page. Takes what `summarize()` returns.
 */
export function renderScanReport(summary, scan, { command = 'plumbline scan', generatedAt = new Date().toISOString() } = {}) {
  const reach = summary.reachability ?? {};
  const assessed = summary.sessions_assessed;
  const share = (n) => (assessed === 0 ? 0 : n / assessed);

  const levelBar = LEVEL_ORDER.map((lv) => {
    const w = share(summary.by_level[lv]) * 100;
    const colour = { observe: '#5f8296', warn: '#c9a227', confirm: '#d08a3e', halt: '#c94b3f' }[lv];
    return w > 0 ? `<span style="width:${w.toFixed(2)}%;background:${colour}"></span>` : '';
  }).join('');

  const coverage = Object.entries(reach.reachable_in_sessions ?? {})
    .sort((a, b) => b[1] - a[1])
    .map(([id, n]) => `<tr><td><code>${esc(id)}</code></td><td class="num">${esc(n)}</td>
      <td class="num">${esc(pct(share(n)))}</td>
      <td class="num">${esc(summary.by_detector[id] ?? 0)}</td></tr>`);

  const top = summary.top.map((t) => `<tr>
    <td><span class="lv-${esc(t.level)}">${esc(t.level)}</span></td>
    <td class="num">${esc(d2(t.drift))}</td>
    <td><code>${esc(t.session)}</code>${t.task ? `<br><span class="m">${esc(t.task)}</span>` : ''}</td>
    <td>${t.top_signals.map((s) => `<div class="m">${esc(s)}</div>`).join('')}</td>
  </tr>`);

  const body = `
<h1><span class="mark">plumbline<span class="dot">.</span></span> agent audit</h1>
<p class="sub">${esc(assessed)} sessions &middot; ${esc(summary.tool_calls)} tool calls &middot; profile ${esc(summary.profile)} &middot; adapter ${esc(reach.adapter ?? 'claude-code')}</p>

<div class="card">
  ${assessed === 0
    // 0 sessions with a "0.0% clean" headline reads as an alarm, and the usual
    // cause is a path with no transcripts in it. Say the true thing instead.
    ? `<div class="verdict"><span class="big lv-observe">no sessions</span>
      <span class="m">&middot; nothing under this path parsed as a trajectory${scan.skipped.length > 0 ? `, and ${esc(scan.skipped.length)} file(s) were skipped` : ''}</span></div>
    <p class="sub" style="margin-top:10px">Check the path and the <code>--adapter</code>: a Claude Code tree lives at
    <code>~/.claude/projects</code>, while the openai / anthropic / langchain / otel adapters each take a log file.</p>`
    : `<div class="verdict">
    <span class="big lv-${summary.flagged === 0 ? 'observe' : 'confirm'}">${esc(pct(summary.clean_ratio))}</span>
    <span class="m">clean &middot; ${esc(summary.flagged)} flagged (${esc(pct(summary.flagged_ratio))})</span>
  </div>
  <div class="bar">${levelBar}</div>
  <div class="sub">${LEVEL_ORDER.map((lv) => `${lv} ${summary.by_level[lv]}`).join(' &middot; ')}</div>`}
</div>

${caveatBlock({
    starved: reach.absent_from_corpus ?? [],
    blindSpots: reach.blind_spots ?? [],
    clean: summary.flagged === 0,
  })}

${reach.clean_rate_is_meaningful === false ? `<div class="caveat">
  <h3>This clean rate is not a safety claim</h3>
  <p>At least one detector was dead for every session here, so the percentage above
  covers less than it appears to. Read the coverage table before quoting it.</p>
</div>` : ''}

<h2>Detector coverage &mdash; what could have fired, and what did</h2>
<div class="card">
${coverage.length > 0
  ? `<table><thead><tr><th>detector</th><th class="num">sessions fed</th><th class="num">share</th><th class="num">signals</th></tr></thead>
<tbody>${coverage.join('\n')}</tbody></table>
<p class="sub" style="margin-top:12px">Low coverage is normal: most sessions contain no credential reuse and no denials.
A detector at zero that this adapter <em>can</em> feed means the corpus lacks that activity, not that the detector is broken.</p>`
  : '<p class="sub">No detector reachability was recorded for this scan.</p>'}
</div>

${top.length > 0 ? `<h2>Highest drift</h2>
<div class="card"><table><thead><tr><th>level</th><th class="num">drift</th><th>session</th><th>top signals</th></tr></thead>
<tbody>${top.join('\n')}</tbody></table></div>` : `<h2>Highest drift</h2>
<div class="card"><p class="sub">Nothing crossed <code>warn</code> in this corpus.</p></div>`}

${scan.skipped.length > 0 ? `<h2>Skipped</h2>
<div class="card"><p class="sub">${esc(scan.skipped.length)} file(s) skipped &mdash; no tool activity, or unreadable. They are not in any number above.</p></div>` : ''}`;

  return page(`plumbline - agent audit (${assessed} sessions)`, body, { command, generatedAt });
}
