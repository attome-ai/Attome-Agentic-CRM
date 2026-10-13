/**
 * U7 Phase A — the pure half of Assign/Share: principal kinds, the request
 * body each route takes for one, and the bulk-assign outcome summary.
 */
import type { CreateRecordShareBody, ReassignOwnerBody, ShareCapability } from './record-sharing.service';

export type RecordAccessMode = 'assign' | 'share';
export type PrincipalKind = 'user' | 'team';

export interface Principal {
  kind:  PrincipalKind;
  id:    string;
  /** What the route resolves the principal by: a user's email, a team's name. */
  label: string;
}

/**
 * Where the picker searches for each kind, and the field it shows. The share
 * routes resolve a principal by `user_email` / `team_name` (`shares.rs`'s
 * `resolve_principal`), so that is exactly the field the picker displays and
 * sends back.
 */
export const PRINCIPAL_SOURCES: Record<PrincipalKind, { entity: string; displayField: string }> = {
  user: { entity: 'user_account', displayField: 'email' },
  team: { entity: 'team',       displayField: 'name' },
};

/** `{ user_email }` or `{ team_name }` — exactly one, as the routes require. */
export function principalRef(principal: Principal): { user_email?: string; team_name?: string } {
  return principal.kind === 'user' ? { user_email: principal.label } : { team_name: principal.label };
}

export function reassignBody(entity: string, recordId: string, principal: Principal): ReassignOwnerBody {
  return { entity, record_id: recordId, ...principalRef(principal) };
}

export function shareBody(
  entity: string,
  recordId: string,
  principal: Principal,
  capability: ShareCapability,
): CreateRecordShareBody {
  return { entity, record_id: recordId, capability, ...principalRef(principal) };
}

/** One record's result in a bulk Assign — the route is per record and each
 * call is atomic on its own, so a batch is a list of independent outcomes. */
export interface AssignOutcome {
  recordId: string;
  ok:       boolean;
  error?:   string;
}

export function summarizeAssign(outcomes: readonly AssignOutcome[]): {
  succeeded: number;
  failed:    AssignOutcome[];
} {
  const failed = outcomes.filter(o => !o.ok);
  return { succeeded: outcomes.length - failed.length, failed };
}
