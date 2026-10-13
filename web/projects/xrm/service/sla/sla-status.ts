/**
 * What a ticket's SLA badge says, derived from the ticket's own SLA columns
 * (`resolution_due_at`, `resolved_at`, `sla_breached`, `sla_warned`,
 * `sla_calculation_status`, `sla_unresolved_reason`, `sla_policy_id`,
 * `status`). Pure, so the badge, a list cell or a spec can all share it.
 *
 * - `resolved` / `resolved_breached` — the ticket is resolved or closed.
 * - `not_calculated` — a policy is assigned but no deadline exists (D-517's
 *   `unresolved` status, with its reason, or no deadline at all).
 * - `breached` — the breach sweep has marked it.
 * - `overdue` — the deadline has passed but the sweep has not run yet (or the
 *   clock is paused, which the sweep deliberately skips).
 * - `warning` — the pre-breach warning sweep has marked it.
 * - `due` — running within its SLA.
 *
 * `null` when the ticket has no SLA at all (no policy, no deadline, no
 * calculation status): the badge renders nothing rather than inventing one.
 */
export type SlaBadgeKind =
  | 'resolved' | 'resolved_breached' | 'not_calculated' | 'breached' | 'overdue' | 'warning' | 'due';

export interface SlaBadgeState {
  kind: SlaBadgeKind;
  /** The deadline, when there is one. */
  dueAt: Date | null;
  /** `sla_unresolved_reason`, for `not_calculated`. */
  reason: string | null;
}

const CLOSED_STATUSES = new Set(['resolved', 'closed']);

function parseDate(value: unknown): Date | null {
  if (typeof value !== 'string' || value === '') return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function slaBadgeState(ticket: Record<string, unknown> | null, now: number): SlaBadgeState | null {
  if (!ticket) return null;
  const dueAt = parseDate(ticket['resolution_due_at']);
  const calc = ticket['sla_calculation_status'];
  const hasPolicy = ticket['sla_policy_id'] != null && ticket['sla_policy_id'] !== '';
  if (!hasPolicy && !dueAt && calc == null) return null;

  const breached = ticket['sla_breached'] === true;
  const resolved = ticket['resolved_at'] != null
    || (typeof ticket['status'] === 'string' && CLOSED_STATUSES.has(ticket['status']));
  if (resolved) return { kind: breached ? 'resolved_breached' : 'resolved', dueAt, reason: null };

  if (calc === 'unresolved') {
    const reason = ticket['sla_unresolved_reason'];
    return { kind: 'not_calculated', dueAt: null, reason: typeof reason === 'string' ? reason : null };
  }
  if (!dueAt) return { kind: 'not_calculated', dueAt: null, reason: null };
  if (breached) return { kind: 'breached', dueAt, reason: null };
  if (dueAt.getTime() < now) return { kind: 'overdue', dueAt, reason: null };
  if (ticket['sla_warned'] === true) return { kind: 'warning', dueAt, reason: null };
  return { kind: 'due', dueAt, reason: null };
}

/**
 * "in 3 hours" / "2 days ago", in `locale`. Minutes under an hour, hours
 * under a day, days beyond — the badge answers "how urgent", not "exactly
 * when" (the absolute time is in the badge's tooltip).
 */
export function relativeTime(target: Date, now: number, locale: string): string {
  const seconds = (target.getTime() - now) / 1000;
  const abs = Math.abs(seconds);
  const fmt = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
  if (abs < 3600) return fmt.format(Math.round(seconds / 60), 'minute');
  if (abs < 86400) return fmt.format(Math.round(seconds / 3600), 'hour');
  return fmt.format(Math.round(seconds / 86400), 'day');
}
