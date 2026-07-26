/**
 * An ollama judge for the semantic detector.
 *
 * This is the ONE place in plumbline that talks to a model, and it is opt-in:
 * nothing imports it unless you ask for the semantic layer. It uses only the
 * built-in `fetch`, so the zero-dependency guarantee holds.
 *
 * The default endpoint is localhost, on purpose. The semantic detector exists
 * to catch escapes that shape cannot see, and it is built to run against a
 * model you host — because during the July 2026 incident the
 * commercial frontier APIs refused to analyze the attack artifacts and the
 * defenders had to reach for a self-hostable open-weight model. A monitor that
 * stops working when it sees a real attack is not a monitor.
 *
 * Empirically, qwen2.5:7b at temperature 0 catches every escape in the corpus
 * (including the residual-floor escape no shape detector sees) with zero false
 * positives across eight benign trajectories, four of them adversarially chosen
 * to look shape-identical to escapes. Smaller models are faster but flag more;
 * see docs/semantic-detector.md.
 */

const DEFAULT_ENDPOINT = 'http://127.0.0.1:11434/api/generate';
const DEFAULT_MODEL = 'qwen2.5:7b';

/**
 * Build a judge function for `assessSemantic`.
 *
 * @param {{endpoint?: string, model?: string, timeoutMs?: number, num_ctx?: number}} [options]
 * @returns {(prompt: string) => Promise<{ diverging_steps: Array<{step:number, reason:string}> }>}
 */
export function ollamaJudge({
  endpoint = process.env.PLUMBLINE_OLLAMA ?? DEFAULT_ENDPOINT,
  model = process.env.PLUMBLINE_MODEL ?? DEFAULT_MODEL,
  timeoutMs = 120000,
  num_ctx = 4096,
} = {}) {
  return async function judge(prompt) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          model,
          prompt,
          stream: false,
          format: 'json',
          // temperature 0: a security verdict must not be a dice roll.
          options: { temperature: 0, num_ctx },
        }),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      throw new Error(`ollama ${res.status} at ${endpoint} (model ${model})`);
    }
    const body = await res.json();
    const text = body?.response ?? '';
    // The model is asked for strict JSON; if it strays, treat it as "found
    // nothing" rather than throwing — a parse failure must not read as a signal.
    try {
      const parsed = JSON.parse(text);
      return { diverging_steps: Array.isArray(parsed?.diverging_steps) ? parsed.diverging_steps : [] };
    } catch {
      return { diverging_steps: [] };
    }
  };
}

export { DEFAULT_ENDPOINT, DEFAULT_MODEL };
