import { OfflineQueueService, QueuedOp } from './offline-queue.service';
import { OfflineStore } from './offline-store';

/** One allowed move, as the offline profile lists it (B18-T13). */
export interface OfflineTransition {
  from_state: string;
  to_state: string;
  name: string;
  guard_expression: string | null;
  language: string;
  required_privilege: string | null;
  requires_approval: boolean;
}

/** An entity's state model, as the offline profile lists it. */
export interface OfflineStateModel {
  name: string;
  state_field: string;
  initial_state: string;
  transitions: OfflineTransition[];
}

/** The parts of the offline profile the device keeps. */
export interface OfflineProfileBundle {
  bundle_version: string;
  max_days_offline: number | null;
  entities: { entity: string; state_model: OfflineStateModel | null }[];
}

/**
 * Evaluates a guard on the device: true or false, or `null` when it cannot
 * (no evaluator for the language yet), in which case the server decides on
 * push, as it always checks the move again.
 */
export type GuardEvaluator = (expression: string, language: string, record: Record<string, unknown>) => boolean | null;

/** Where the profile is kept in the store's `meta`. */
export const PROFILE_KEY = 'profile';

/** The record's current state: its state field, else the initial state. Pure. */
export function currentState(model: OfflineStateModel, record: Record<string, unknown>): string {
  const value = record[model.state_field];
  return value == null || value === '' ? model.initial_state : String(value);
}

/**
 * The moves the device offers from the record's state: those leaving it,
 * without one needing an approval while offline (only the server starts an
 * approval), and without one whose guard the device evaluated as false. Pure.
 */
export function availableTransitions(
  model: OfflineStateModel,
  record: Record<string, unknown>,
  online: boolean,
  evaluate?: GuardEvaluator,
): OfflineTransition[] {
  const from = currentState(model, record);
  return model.transitions.filter(t =>
    t.from_state === from
    && (online || !t.requires_approval)
    && !(t.guard_expression && evaluate && evaluate(t.guard_expression, t.language, record) === false));
}

/** The queued change for a move: an update of the state field only. Pure. */
export function transitionOp(
  entity: string,
  id: string,
  rowVersion: number | undefined,
  model: OfflineStateModel,
  record: Record<string, unknown>,
  to: string,
): Omit<QueuedOp, 'seq' | 'client_op_id'> {
  return {
    kind: 'update',
    entity,
    id,
    base_row_version: rowVersion,
    changed: { [model.state_field]: to },
    base_values: { [model.state_field]: currentState(model, record) },
  };
}

/**
 * B18-T13: takes a move offline. Refused when the model does not offer it
 * from the record's state; otherwise queued as an update of the state field,
 * which the push runs through the server's mutation path (the transition and
 * its guard are checked again, and the entity's triggers fire after the
 * commit).
 */
export async function queueTransition(
  queue: OfflineQueueService,
  model: OfflineStateModel,
  change: { entity: string; id: string; rowVersion?: number; record: Record<string, unknown>; to: string },
  online: boolean,
  evaluate?: GuardEvaluator,
): Promise<QueuedOp> {
  const allowed = availableTransitions(model, change.record, online, evaluate).some(t => t.to_state === change.to);
  if (!allowed) throw new Error('transition_not_allowed');
  return queue.enqueue(transitionOp(change.entity, change.id, change.rowVersion, model, change.record, change.to));
}

/** The entity's state model from the stored profile, or `null`. */
export async function storedStateModel(store: OfflineStore, entity: string): Promise<OfflineStateModel | null> {
  const profile = await store.get<OfflineProfileBundle>('meta', PROFILE_KEY);
  return profile?.entities.find(e => e.entity === entity)?.state_model ?? null;
}
