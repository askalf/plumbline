/**
 * Harness hook: score the session as it runs, without being remembered.
 *
 * A monitor you have to remember to run is a monitor you ran once. `plumbline
 * hook` is the command a harness hook invokes: it reads the hook payload on
 * stdin, scores the transcript that payload names, and prints ONE line - only
 * when drift has crossed a level worth interrupting for. Silence is the normal
 * case and the point.
 *
 * Three rules it will not break, because a monitor that breaks the thing it
 * monitors gets uninstalled the same day:
 *
 *  1. IT NEVER BLOCKS. Exit status is always 0, whatever the verdict and
 *     whatever went wrong. plumbline is out-of-band by design - it scores after
 *     the fact and has no business stopping an agent mid-turn - and a non-zero
 *     exit from a Stop hook is a message back into the agent's loop.
 *  2. IT NEVER THROWS. A missing transcript, malformed JSON on stdin, a
 *     permission error: all of them are silent no-ops. The failure mode of a
 *     monitor should be "said nothing", never "broke the session".
 *  3. IT WRITES TO STDERR. Hook stdout is consumed by the harness; a verdict
 *     printed there is a verdict fed back into the model's context.
 */

import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { LEVELS } from './score.mjs';

/** What a harness hands a hook. Only `transcript_path` is load-bearing here. */
export function parseHookPayload(text) {
  let payload;
  try {
    payload = JSON.parse(String(text ?? ''));
  } catch {
    return null;
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const transcriptPath = typeof payload.transcript_path === 'string' && payload.transcript_path
    ? payload.transcript_path
    : null;
  return {
    transcriptPath,
    sessionId: typeof payload.session_id === 'string' ? payload.session_id : null,
    event: typeof payload.hook_event_name === 'string' ? payload.hook_event_name : null,
    cwd: typeof payload.cwd === 'string' ? payload.cwd : null,
  };
}

/** Is this verdict worth one line of the operator's attention? */
export function shouldReport(level, floor = 'warn') {
  return LEVELS.indexOf(level) >= LEVELS.indexOf(floor);
}

/**
 * One line, because it is printed into a working session. The dominant signal
 * and where to look - everything else is what `plumbline scan` is for.
 */
export function hookLine(result) {
  const worst = [...result.signals].sort((a, b) => b.severity - a.severity)[0];
  const where = worst ? ` - ${worst.detector}: ${worst.label}${worst.detail ? ` (${worst.detail})` : ''} [seq ${worst.seq}]` : '';
  return `plumbline: ${result.level} at drift ${result.drift.toFixed(2)}${where}`;
}

/**
 * Merge a hook command into a settings object, idempotently.
 *
 * Never replaces the event's existing hooks: a user who already has a Stop hook
 * doing something they care about must not silently lose it to a monitor they
 * installed to be helpful. Re-running is a no-op rather than a duplicate entry,
 * because an install command that grows the config every time it runs is one
 * people stop trusting to run.
 */
export function mergeHookConfig(settings, { event, command }) {
  const next = { ...(settings && typeof settings === 'object' && !Array.isArray(settings) ? settings : {}) };
  const hooks = { ...(next.hooks && typeof next.hooks === 'object' ? next.hooks : {}) };
  const forEvent = Array.isArray(hooks[event]) ? hooks[event].map((m) => ({ ...m })) : [];

  const already = forEvent.some((matcher) =>
    Array.isArray(matcher.hooks) && matcher.hooks.some((h) => h && h.command === command));
  if (already) return { settings: next, changed: false };

  forEvent.push({ matcher: '', hooks: [{ type: 'command', command }] });
  hooks[event] = forEvent;
  next.hooks = hooks;
  return { settings: next, changed: true };
}

/** Read a settings file that may not exist yet, refusing to guess at broken JSON. */
export function readSettings(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return { settings: {}, existed: false };
    throw err;
  }
  if (text.trim() === '') return { settings: {}, existed: true };
  try {
    return { settings: JSON.parse(text), existed: true };
  } catch (err) {
    // Overwriting a file we cannot parse would discard configuration the user
    // cannot get back. Refuse, and say which file.
    throw new Error(`${path} is not valid JSON (${err.message}) - fix or move it, then run this again`);
  }
}

/** Write settings, keeping one backup of whatever was there. */
export function writeSettings(path, settings, { backup = true } = {}) {
  mkdirSync(dirname(path), { recursive: true });
  let backupPath = null;
  if (backup && existsSync(path)) {
    backupPath = `${path}.plumbline-backup`;
    copyFileSync(path, backupPath);
  }
  writeFileSync(path, `${JSON.stringify(settings, null, 2)}\n`, 'utf8');
  return backupPath;
}

/** Where a flagged session's report goes, if the hook was asked for one. */
export function reportPathFor(dir, result) {
  const safe = String(result.session ?? 'session').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80);
  return join(dir, `${safe}.html`);
}
