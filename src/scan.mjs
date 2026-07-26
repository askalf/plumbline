/**
 * Batch scanning: run plumbline over a corpus of real agent sessions.
 *
 * This is the honest-numbers path. A detector set that has only ever seen its
 * own synthetic corpus is worthless; the question that matters is what it says
 * about hundreds of sessions that were genuinely fine.
 */

import { readdirSync, statSync, readFileSync } from 'node:fs';
import { join, extname, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeEvent } from './schema.mjs';
import { assess } from './index.mjs';
import { readTranscript, declareFor } from './adapters/claude-code.mjs';
import { readExecutions } from './adapters/forge.mjs';
import { DEPENDENCIES, classifyDeadDetectors } from './reachability.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

export function loadProfile(nameOrPath) {
  const candidates = [
    resolve(HERE, '..', 'profiles', `${nameOrPath}.json`),
    resolve(nameOrPath),
  ];
  for (const candidate of candidates) {
    try {
      return JSON.parse(readFileSync(candidate, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }
  throw new Error(`no such profile: ${nameOrPath}`);
}

export function listProfiles() {
  return readdirSync(resolve(HERE, '..', 'profiles'))
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''));
}

/** Recursively collect .jsonl files under a directory (or return the file itself). */
export function collectTranscripts(target, { limit = Infinity } = {}) {
  const found = [];
  const walk = (path) => {
    if (found.length >= limit) return;
    let st;
    try {
      st = statSync(path);
    } catch {
      return;
    }
    if (st.isFile()) {
      if (extname(path) === '.jsonl') found.push({ path, size: st.size });
      return;
    }
    if (!st.isDirectory()) return;
    let entries;
    try {
      entries = readdirSync(path);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (found.length >= limit) return;
      walk(join(path, entry));
    }
  };
  walk(target);
  return found;
}

/**
 * Assess one Claude Code transcript against a profile.
 * Returns null for transcripts with no tool activity - nothing to score.
 */
export async function scanTranscript(path, profile, { thresholds } = {}) {
  const { events, task, cwd, tools } = await readTranscript(path);
  if (events.length === 0) return null;

  const session = path.replace(/^.*[\\/]/, '').replace(/\.jsonl$/, '');
  const raw = [declareFor({ session, task, cwd, profile }), ...events];
  const normalized = raw.map((e, i) => normalizeEvent(e, { line: i + 1 }));
  const report = assess(normalized, { thresholds });

  return {
    path,
    session,
    task,
    cwd,
    tool_calls: events.length,
    tools,
    level: report.level,
    drift: report.drift,
    crossings: report.crossings,
    earliest_actionable: report.earliest_actionable,
    reachability: report.reachability,
    signals: report.signals.map((s) => ({
      detector: s.detector,
      seq: s.seq,
      label: s.label,
      detail: s.detail ?? null,
      severity: s.severity,
    })),
  };
}

/**
 * Scan a dumped forge executions JSONL file.
 *
 * One file, many sessions — the inverse of the Claude Code layout, which is why
 * this gets its own entry point rather than being folded into collectTranscripts.
 */
export async function scanForgeDump(file, profile, { limit = Infinity, thresholds } = {}) {
  const trajectories = await readExecutions(file, profile);
  const results = [];
  const skipped = [];

  for (const t of trajectories.slice(0, limit === Infinity ? undefined : limit)) {
    try {
      const normalized = t.events.map((e, i) => normalizeEvent(e, { line: i + 1 }));
      const report = assess(normalized, { thresholds });
      results.push({
        path: file,
        session: t.session,
        task: t.task,
        cwd: null,
        agent: t.agent,
        tool_calls: t.tool_calls,
        tools: {},
        level: report.level,
        drift: report.drift,
        crossings: report.crossings,
        earliest_actionable: report.earliest_actionable,
        reachability: report.reachability,
        signals: report.signals.map((s) => ({
          detector: s.detector,
          seq: s.seq,
          label: s.label,
          detail: s.detail ?? null,
          severity: s.severity,
        })),
      });
    } catch (err) {
      skipped.push({ path: `${file}#${t.session}`, reason: err.message });
    }
  }

  return { results, skipped, scanned: trajectories.length, profile: profile.name ?? 'custom' };
}

/** Scan a directory tree of transcripts. */
export async function scanCorpus(target, profile, { limit = Infinity, thresholds, onProgress } = {}) {
  const files = collectTranscripts(target, { limit });
  const results = [];
  const skipped = [];

  for (let i = 0; i < files.length; i++) {
    const { path, size } = files[i];
    try {
      const result = await scanTranscript(path, profile, { thresholds });
      if (result === null) skipped.push({ path, reason: 'no tool activity' });
      else results.push({ ...result, bytes: size });
    } catch (err) {
      skipped.push({ path, reason: err.message });
    }
    if (onProgress) onProgress(i + 1, files.length);
  }

  return { results, skipped, scanned: files.length, profile: profile.name ?? 'custom' };
}

/** Aggregate a scan into the numbers that belong in a README. */
export function summarize(scan, { adapter = 'claude-code' } = {}) {
  const byLevel = { observe: 0, warn: 0, confirm: 0, halt: 0 };
  const byDetector = {};
  let toolCalls = 0;

  // Corpus-level reachability. A detector is only genuinely live over a corpus
  // if at least one session could feed it — this is the number that decides
  // whether an aggregate clean rate means anything at all.
  const reachableIn = {};
  const census = {};
  let sessionsFullyReachable = 0;

  for (const r of scan.results) {
    byLevel[r.level] += 1;
    toolCalls += r.tool_calls;
    for (const s of r.signals) {
      byDetector[s.detector] = (byDetector[s.detector] ?? 0) + 1;
    }
    if (r.reachability) {
      if (r.reachability.trustworthy) sessionsFullyReachable += 1;
      for (const [id, info] of Object.entries(r.reachability.detectors)) {
        if (info.status !== 'starved') reachableIn[id] = (reachableIn[id] ?? 0) + 1;
      }
      for (const [field, n] of Object.entries(r.reachability.census)) {
        if (n > 0) census[field] = (census[field] ?? 0) + n;
      }
    }
  }

  const flagged = byLevel.warn + byLevel.confirm + byLevel.halt;
  const total = scan.results.length;

  const deadOverCorpus = Object.keys(DEPENDENCIES).filter((id) => !reachableIn[id]);
  const { blindSpots, absentFromCorpus } = classifyDeadDetectors(deadOverCorpus, adapter);

  return {
    profile: scan.profile,
    sessions_scanned: scan.scanned,
    sessions_assessed: total,
    sessions_skipped: scan.skipped.length,
    tool_calls: toolCalls,
    by_level: byLevel,
    flagged,
    flagged_ratio: total === 0 ? 0 : Number((flagged / total).toFixed(4)),
    clean_ratio: total === 0 ? 0 : Number((byLevel.observe / total).toFixed(4)),
    by_detector: byDetector,
    reachability: {
      /** Detectors no session in this corpus could feed. A clean rate does not cover these. */
      dead_over_corpus: deadOverCorpus,
      /** Dead because the ADAPTER cannot express the field. A permanent defect. */
      blind_spots: blindSpots,
      /** Dead because this corpus contains no such activity. Expected, not a defect. */
      absent_from_corpus: absentFromCorpus,
      adapter,
      /** Per detector, how many sessions could have fed it. */
      reachable_in_sessions: reachableIn,
      sessions_fully_reachable: sessionsFullyReachable,
      field_census: census,
      /**
       * The honest headline. A clean rate is only a safety claim when every
       * detector was reachable somewhere in the corpus.
       */
      clean_rate_is_meaningful: blindSpots.length === 0,
    },
    top: [...scan.results]
      .filter((r) => r.level !== 'observe')
      .sort((a, b) => b.drift - a.drift)
      .slice(0, 15)
      .map((r) => ({
        session: r.session,
        level: r.level,
        drift: r.drift,
        tool_calls: r.tool_calls,
        task: r.task ? r.task.slice(0, 80) : null,
        top_signals: r.signals
          .slice()
          .sort((a, b) => b.severity - a.severity)
          .slice(0, 3)
          .map((s) => `${s.detector}: ${s.label}${s.detail ? ` (${s.detail})` : ''}`),
      })),
  };
}
