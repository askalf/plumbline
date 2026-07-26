/**
 * Fan-out correlation.
 *
 * The ExploitGym agents spread ~17,000 actions across a swarm of short-lived
 * sandboxes, which is why reconstructing the campaign took specialist forensics
 * rather than a log query. Any monitor scoped to a single instance sees a
 * handful of innocuous actions and nothing else.
 *
 * plumbline's unit is the logical session, so the swarm collapses back into one
 * trajectory. The spawn rate itself then becomes a signal when it exceeds what
 * the declared task plausibly needs.
 */

export const id = 'fanout';

const MAX_SEVERITY = 0.5;
const PER_EXCESS_INSTANCE = 0.1;

export function detect(events, envelope) {
  const budget = envelope.budget.max_instances;
  const seen = new Set();
  let firedAt = null;
  let peak = 0;

  for (const event of events) {
    if (!event.instance) continue;
    seen.add(event.instance);
    if (seen.size > budget && firedAt === null) firedAt = event.seq;
    peak = Math.max(peak, seen.size);
  }

  if (firedAt === null) return [];

  const excess = peak - budget;
  return [
    {
      detector: id,
      seq: firedAt,
      severity: Math.min(MAX_SEVERITY, PER_EXCESS_INSTANCE * excess),
      label: `fan-out: ${peak} ephemeral instances`,
      detail: `${excess} beyond the declared budget of ${budget}`,
      evidence: {
        instances_observed: peak,
        budget,
        excess,
        sample: [...seen].slice(0, 12),
      },
    },
  ];
}
