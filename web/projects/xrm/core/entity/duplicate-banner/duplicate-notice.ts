import { DuplicateMatchRef } from '@attome/base';
import { OnSave } from '@attome/xrm/core/admin/data';

/**
 * A15-T4: what the last save of a form found about likely duplicates.
 * `refused`: the server answered `409 duplicate_detected`; `action` then says
 * whether a reason lets the save through (`allow_with_reason`) or not
 * (`block`). Otherwise the save went through and `action` is `warn`.
 */
export interface DuplicateNotice {
  refused: boolean;
  action: Exclude<OnSave, 'off'>;
  /** The matched records the caller may read. */
  matches: DuplicateMatchRef[];
  /** Matches the caller may not read. */
  hidden: number;
}

/**
 * The `duplicate_warnings` / `hidden_duplicates` a successful create or
 * update carries under a `warn` rule (both omitted when there are none), as
 * a notice; `null` when the save matched nothing.
 */
export function duplicateWarningsOf(response: unknown): DuplicateNotice | null {
  if (!response || typeof response !== 'object') return null;
  const body = response as { duplicate_warnings?: unknown; hidden_duplicates?: unknown };
  const matches = Array.isArray(body.duplicate_warnings) ? body.duplicate_warnings as DuplicateMatchRef[] : [];
  const hidden = typeof body.hidden_duplicates === 'number' ? body.hidden_duplicates : 0;
  if (!matches.length && !hidden) return null;
  return { refused: false, action: 'warn', matches, hidden };
}
