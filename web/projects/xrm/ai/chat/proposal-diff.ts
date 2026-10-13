/**
 * What a confirmation card shows for a persisted proposal: one row per field
 * the action would touch, with the record's current value beside the proposed
 * one where the action changes an existing record.
 *
 * Built from the proposal's stored `arguments` (display only — confirming sends
 * the hash, never these, I-13) and, optionally, the record as the user can
 * currently read it. Every value is rendered as plain text.
 */
export interface DiffRow {
  field: string;
  /** `undefined` when there is no current value to compare (a create, or the read was refused). */
  current?: string;
  proposed: string;
  changed: boolean;
}

export interface ProposalSummary {
  /** The entity and record the action targets, when it names them. */
  entity?: string;
  recordId?: string;
  rows: DiffRow[];
}

/** Plain text for any JSON value — never markup. */
export function displayValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/** The field values an action proposes, by action shape. */
function proposedFields(actionId: string, args: Record<string, unknown>): Record<string, unknown> {
  switch (actionId) {
    case 'record.create':
    case 'record.update':
      return asObject(args['values']);
    case 'record.update_field':
      return typeof args['field'] === 'string' ? { [args['field']]: args['value'] } : {};
    default: {
      // Anything else: show every argument except the target's identity.
      const { entity: _entity, record_id: _record, ...rest } = args;
      return rest;
    }
  }
}

export function summarizeProposal(
  actionId: string,
  argumentsValue: unknown,
  current: Record<string, unknown> | null,
): ProposalSummary {
  const args = asObject(argumentsValue);
  const fields = proposedFields(actionId, args);
  const compare = current !== null && actionId !== 'record.create';
  return {
    entity: typeof args['entity'] === 'string' ? args['entity'] : undefined,
    recordId: typeof args['record_id'] === 'string' ? args['record_id'] : undefined,
    rows: Object.keys(fields)
      .sort()
      .map((field) => {
        const proposed = displayValue(fields[field]);
        const now = compare && field in current ? displayValue(current[field]) : undefined;
        return { field, current: now, proposed, changed: now === undefined || now !== proposed };
      }),
  };
}

/** Actions whose card compares against the record's current values. */
export function wantsCurrentRecord(actionId: string): boolean {
  return actionId === 'record.update' || actionId === 'record.update_field';
}
