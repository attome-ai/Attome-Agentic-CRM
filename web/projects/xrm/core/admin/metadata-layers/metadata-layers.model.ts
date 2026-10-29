// Y11-T15: the wire shapes of `/api/v1/admin/metadata/*` layer routes
// (attome-api `model_admin/layers.rs`). Values are metadata JSON, kept
// `unknown` here: the generated `Object` schema is `Record<string, never>`.

/** `entity` (key: logical name) or `attribute` (key: `<entity>.<field>`). */
export type LayeredKind = 'entity' | 'attribute';

/** `platform`, `app` or `customer`. */
export type LayerName = 'platform' | 'app' | 'customer';

export interface LayerValue {
  layer: LayerName;
  /** The app that set it; empty for the platform and the customer. */
  app: string;
  value: unknown;
}

/** A property across the layers, in merge order, and the layer that wins. */
export interface PropertyStack {
  property: string;
  winner: LayerName;
  values: LayerValue[];
}

export interface ResetChange {
  property: string;
  current: unknown;
  /** `null` when no lower layer recorded a value: the property stays as it is. */
  after: unknown | null;
}

/** A reset, or its preview (no `reset_id`). */
export interface ResetResult {
  reset_id: string | null;
  changes: ResetChange[];
}

export type ConflictChoice = 'keep_customer' | 'take_platform' | 'combine';

export interface LayerConflict {
  id: string;
  object_kind: LayeredKind;
  object_key: string;
  property: string;
  old_platform: unknown | null;
  new_platform: unknown | null;
  customer: unknown | null;
  status: 'open' | 'resolved';
  resolution: ConflictChoice | null;
  resolved_by: string | null;
  resolved_at: string | null;
  created_at: string;
}

/** `metadata.propose_conflict_resolution`'s result (Y11-T8): a proposal only. */
export type ConflictProposal =
  | { status: 'proposed'; choice: ConflictChoice; value: unknown | null; reasoning: string; conflict_id: string }
  | { status: 'declined'; reason: string; conflict_id: string };

/** A metadata value as one line of text. */
export function showValue(value: unknown): string {
  if (value === null || value === undefined) return '';
  return typeof value === 'string' ? value : JSON.stringify(value);
}
