#!/usr/bin/env node
/**
 * plumbline CLI.
 *
 * Output is deliberately ASCII-only: these reports land in CI logs, Windows
 * consoles and pasted issue comments, and a box-drawing character that renders
 * as mojibake costs more than it adds.
 */

import { readFileSync } from 'node:fs';
import { assessTrajectory, DETECTOR_IDS, TrajectoryError } from './index.mjs';
import { loadProfile, listProfiles, scanCorpus, scanForgeDump, summarize } from './scan.mjs';

const USAGE = `plumbline - trajectory-level monitoring for autonomous agents

Usage:
  plumbline replay <trajectory.jsonl> [options]
  plumbline scan <dir|file> --profile=<name> [options]
  plumbline validate <trajectory.jsonl>
  plumbline detectors
  plumbline profiles

Options:
  --json            Emit the full assessment as JSON
  --evidence        Print the evidence bundle for every signal
  --only=a,b        Run only the named detectors
  --profile=NAME    Envelope profile for scan (${listProfiles().join(', ')})
  --adapter=NAME    claude-code (default) | forge
  --limit=N         Stop after N sessions (scan only)
  --quiet           Timeline only, no header or verdict
  --exit-code       Exit 1 when the verdict is confirm or halt (for CI)
  -h, --help        Show this message

Detectors: ${DETECTOR_IDS.join(', ')}
`;

function parseArgs(argv) {
  const opts = {
    json: false, evidence: false, only: null, quiet: false,
    exitCode: false, profile: null, limit: Infinity, adapter: 'claude-code',
  };
  const positional = [];
  for (const arg of argv) {
    if (arg === '--json') opts.json = true;
    else if (arg === '--evidence') opts.evidence = true;
    else if (arg === '--quiet') opts.quiet = true;
    else if (arg === '--exit-code') opts.exitCode = true;
    else if (arg === '-h' || arg === '--help') opts.help = true;
    else if (arg.startsWith('--only=')) opts.only = arg.slice(7).split(',').map((s) => s.trim()).filter(Boolean);
    else if (arg.startsWith('--profile=')) opts.profile = arg.slice(10);
    else if (arg.startsWith('--adapter=')) opts.adapter = arg.slice(10);
    else if (arg.startsWith('--limit=')) opts.limit = Number(arg.slice(8));
    else if (arg.startsWith('-')) throw new Error(`unknown option ${arg}`);
    else positional.push(arg);
  }
  return { opts, positional };
}

function printSummary(summary, scan) {
  const out = [''];
  out.push(`  profile          ${summary.profile}`);
  out.push(`  sessions         ${summary.sessions_assessed} assessed, ${summary.sessions_skipped} skipped (no tool activity)`);
  out.push(`  tool calls       ${summary.tool_calls}`);
  out.push('');
  out.push(`  observe          ${summary.by_level.observe}`);
  out.push(`  warn             ${summary.by_level.warn}`);
  out.push(`  confirm          ${summary.by_level.confirm}`);
  out.push(`  halt             ${summary.by_level.halt}`);
  out.push('');
  out.push(`  clean            ${(summary.clean_ratio * 100).toFixed(1)}%`);
  out.push(`  flagged          ${summary.flagged} (${(summary.flagged_ratio * 100).toFixed(1)}%)`);
  out.push('');

  const detectors = Object.entries(summary.by_detector).sort((a, b) => b[1] - a[1]);
  if (detectors.length > 0) {
    out.push('  signals by detector');
    for (const [id, n] of detectors) out.push(`    ${padRight(id, 14)}${n}`);
    out.push('');
  }

  if (summary.top.length > 0) {
    out.push('  highest drift');
    for (const t of summary.top) {
      out.push(`    ${padRight(t.level, 9)}${padRight(t.drift.toFixed(2), 6)}${t.session}  (${t.tool_calls} calls)`);
      if (t.task) out.push(`      task: ${t.task}`);
      for (const s of t.top_signals) out.push(`      - ${s}`);
    }
    out.push('');
  }

  if (scan.skipped.length > 0) {
    const errors = scan.skipped.filter((s) => s.reason !== 'no tool activity');
    if (errors.length > 0) {
      out.push(`  errors           ${errors.length}`);
      for (const e of errors.slice(0, 5)) out.push(`    ${e.path.replace(/^.*[\\/]/, '')}: ${e.reason}`);
      out.push('');
    }
  }

  return out.join('\n');
}

function pad(value, width) {
  const s = String(value);
  return s.length >= width ? s : ' '.repeat(width - s.length) + s;
}

function padRight(value, width) {
  const s = String(value);
  return s.length >= width ? s : s + ' '.repeat(width - s.length);
}

function printReport(report, opts) {
  const out = [];

  if (!opts.quiet) {
    out.push('');
    out.push(`  session   ${report.session ?? '(none)'}`);
    if (report.envelope.declared) {
      out.push(`  task      ${report.envelope.task ?? '(unstated)'}`);
      out.push(`  envelope  ${report.envelope.capabilities.join(', ') || '(none declared)'}`);
      out.push(`  egress    ${report.envelope.egress.allow.join(', ') || '(none declared)'}`);
    } else {
      out.push('  envelope  UNDECLARED - no session.declare event.');
      out.push('            Every capability reads as off-envelope; treat drift as unaudited.');
    }
    out.push(`  events    ${report.events}`);
    out.push('');
  }

  if (report.timeline.length === 0) {
    out.push('  no signals - trajectory stayed inside its envelope');
    out.push('');
    return out.join('\n');
  }

  out.push(`  ${padRight('seq', 6)}${padRight('drift', 8)}${padRight('level', 9)}${padRight('detector', 12)}finding`);
  out.push(`  ${'-'.repeat(72)}`);

  for (const step of report.timeline) {
    const marker = step.level === 'halt' ? ' <<< HALT' : '';
    const finding = step.dominant.detail
      ? `${step.dominant.label} - ${step.dominant.detail}`
      : step.dominant.label;
    out.push(
      `  ${padRight(step.seq, 6)}${padRight(step.drift.toFixed(2), 8)}${padRight(step.level, 9)}` +
        `${padRight(step.dominant.detector, 12)}${finding}${marker}`,
    );

    for (const signal of step.signals.slice(1)) {
      const extra = signal.detail ? `${signal.label} - ${signal.detail}` : signal.label;
      out.push(`  ${' '.repeat(23)}${padRight(signal.detector, 12)}${extra}`);
    }

    if (opts.evidence) {
      for (const signal of step.signals) {
        const json = JSON.stringify(signal.evidence, null, 2) ?? 'null';
        for (const line of json.split('\n')) out.push(`  ${' '.repeat(23)}| ${line}`);
      }
    }
  }

  if (!opts.quiet) {
    out.push('');
    const c = report.crossings;
    out.push(`  verdict   ${report.level.toUpperCase()} at drift ${report.drift.toFixed(2)}`);
    out.push(
      `  crossings warn ${c.warn ?? '-'}   confirm ${c.confirm ?? '-'}   halt ${c.halt ?? '-'}` +
        `   (thresholds ${report.thresholds.warn}/${report.thresholds.confirm}/${report.thresholds.halt})`,
    );
    if (report.earliest_actionable !== null) {
      const rungsLater = c.halt !== null ? c.halt - report.earliest_actionable : null;
      out.push(
        `  actionable seq ${report.earliest_actionable}` +
          (rungsLater !== null ? ` - ${rungsLater} steps before the halt threshold` : ''),
      );
    }
    out.push('');
  }

  return out.join('\n');
}

async function main() {
  const { opts, positional } = parseArgs(process.argv.slice(2));
  const [command, file] = positional;

  if (opts.help || !command) {
    process.stdout.write(USAGE);
    return 0;
  }

  if (command === 'detectors') {
    process.stdout.write(`${DETECTOR_IDS.join('\n')}\n`);
    return 0;
  }

  if (command === 'profiles') {
    process.stdout.write(`${listProfiles().join('\n')}\n`);
    return 0;
  }

  if (command === 'scan') {
    if (!file) {
      process.stderr.write('plumbline: scan requires a directory or file\n');
      return 2;
    }
    if (!opts.profile) {
      process.stderr.write(`plumbline: scan requires --profile=<${listProfiles().join('|')}>\n`);
      return 2;
    }
    let profile;
    try {
      profile = loadProfile(opts.profile);
    } catch (err) {
      process.stderr.write(`plumbline: ${err.message}\n`);
      return 2;
    }

    const isTTY = process.stderr.isTTY;
    const scan = opts.adapter === 'forge'
      ? await scanForgeDump(file, profile, { limit: opts.limit })
      : await scanCorpus(file, profile, {
        limit: opts.limit,
        onProgress: (done, total) => {
          if (isTTY && (done % 25 === 0 || done === total)) {
            process.stderr.write(`\rscanning ${done}/${total}...`);
          }
        },
      });
    if (isTTY) process.stderr.write('\r\x1b[K');

    const summary = summarize(scan);
    if (opts.json) {
      process.stdout.write(`${JSON.stringify({ summary, results: scan.results }, null, 2)}\n`);
    } else {
      process.stdout.write(`${printSummary(summary, scan)}\n`);
    }
    if (opts.exitCode && summary.by_level.confirm + summary.by_level.halt > 0) return 1;
    return 0;
  }

  if (command !== 'replay' && command !== 'validate') {
    process.stderr.write(`plumbline: unknown command "${command}"\n\n${USAGE}`);
    return 2;
  }

  if (!file) {
    process.stderr.write(`plumbline: ${command} requires a trajectory file\n`);
    return 2;
  }

  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    process.stderr.write(`plumbline: cannot read ${file} (${err.code ?? err.message})\n`);
    return 2;
  }

  let report;
  try {
    report = assessTrajectory(text, { only: opts.only });
  } catch (err) {
    if (err instanceof TrajectoryError) {
      process.stderr.write(`plumbline: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  if (command === 'validate') {
    process.stdout.write(`ok - ${report.events} events, session ${report.session}\n`);
    return 0;
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(`${printReport(report, opts)}\n`);
  }

  if (opts.exitCode && (report.level === 'confirm' || report.level === 'halt')) return 1;
  return 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`plumbline: ${err.stack ?? err.message}\n`);
    process.exitCode = 2;
  },
);
