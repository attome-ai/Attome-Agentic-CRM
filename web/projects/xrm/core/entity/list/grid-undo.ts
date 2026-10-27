/**
 * B6-T4: the editable grid's unsaved state and its undo history, pure. A
 * batch is one user action: a cell edit, a paste, a fill or an added row.
 * Undo takes back the last batch; undo all returns to how the session
 * started. Saving ends the session's history, since saved changes are the
 * records' own history from then on.
 */
import type { EntityRecord } from '@attome/xrm';

/** Pending values by row id, then field. */
export type PendingValues = Record<string, Record<string, unknown>>;

/** The grid's unsaved state. */
export interface GridState {
  pending: PendingValues;
  /** Rows added in the grid and not yet saved, with their defaults. */
  added: EntityRecord[];
}

export const EMPTY_STATE: GridState = { pending: {}, added: [] };

/** The id an added row carries until it is saved. */
export const NEW_ROW_PREFIX = 'new-';

export function isNewRow(id: string): boolean {
  return id.startsWith(NEW_ROW_PREFIX);
}

/** A new row's placeholder record: `defaults` as its data. */
export function newRow(seq: number, defaults: Record<string, unknown>): EntityRecord {
  return { id: `${NEW_ROW_PREFIX}${seq}`, row_version: 0, data: { ...defaults } } as unknown as EntityRecord;
}

/** The states before each batch, oldest first. */
export interface History {
  past: GridState[];
}

/** `history` with `before` (the state before a batch) recorded. */
export function record(history: History, before: GridState): History {
  return { past: [...history.past, before] };
}

/** The state before the last batch and the history without it; `null` when there is none. */
export function undoLast(history: History): { state: GridState; history: History } | null {
  const state = history.past[history.past.length - 1];
  return state ? { state, history: { past: history.past.slice(0, -1) } } : null;
}

/** The state the session started with and an empty history; `null` when nothing was done. */
export function undoAll(history: History): { state: GridState; history: History } | null {
  const state = history.past[0];
  return state ? { state, history: { past: [] } } : null;
}

/** `state` with `field` of row `rowId` set to `next`, or cleared when it equals `original`. */
export function withValue(
  state: GridState,
  rowId: string,
  field: string,
  next: unknown,
  original: unknown,
  same: (a: unknown, b: unknown) => boolean,
): GridState {
  const row = { ...(state.pending[rowId] ?? {}) };
  if (same(original, next)) delete row[field];
  else row[field] = next;
  const pending = { ...state.pending };
  if (Object.keys(row).length) pending[rowId] = row;
  else delete pending[rowId];
  return { ...state, pending };
}
