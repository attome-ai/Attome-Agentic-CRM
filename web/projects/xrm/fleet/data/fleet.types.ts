/**
 * Wire types of the fleet console (`/api/v1/fleet/**`, D-792), mirrored by
 * hand from `crates/engine/attome-fleet/src/routes/{deployments,reports,rollouts}.rs`,
 * `publish.rs` (`PlanSummary`) and `changesets.rs` (`ChangesetFile`,
 * `ChangesetRef`).
 *
 * The fleet routes are deliberately left out of the published `openapi.json`
 * (they exist only in a developer debug build with the gate open), so these
 * stay hand-written: there is no generated type to switch to. A Rust
 * `Option<T>` is always serialized, as `null` when empty.
 *
 * The release-report types at the bottom are the CUSTOMER's shapes
 * (`attome_core::release_report`, `attome-api/src/admin/release_report.rs`):
 * the console proxies those reads unchanged.
 */

export const FLEET_ENVIRONMENTS = ['dev', 'test', 'prod'] as const;
export type FleetEnvironment = typeof FLEET_ENVIRONMENTS[number];

/** Wave order of a publish: canary first, broad last. */
export const FLEET_RINGS = ['canary', 'early', 'broad'] as const;
export type FleetRing = typeof FLEET_RINGS[number];

/** `DriftView.status`. */
export const DRIFT_STATUSES = ['never_observed', 'schema_dirty', 'in_sync', 'diverged'] as const;

/** `RolloutView.status`. */
export const ROLLOUT_STATUSES = ['planned', 'in_progress', 'completed', 'halted', 'cancelled'] as const;

/** `WaveView.state`. */
export const WAVE_STATES = ['pending', 'in_progress', 'healthy', 'unhealthy'] as const;

/** `TargetView.status`. */
export const TARGET_STATUSES = [
  'pending', 'planned', 'approval_pending', 'applying', 'applied', 'failed', 'skipped',
] as const;

/** `ActionView.outcome`. */
export const ACTION_OUTCOMES = ['ok', 'refused', 'failed'] as const;

/** One row of `ObservationView.ledger_head`. */
export interface LedgerHeadEntry {
  layer:        string;
  scope:        string;
  changeset_id: string;
  seq:          number;
  status:       string;
}

/** `ObservationView` — the latest probe of a deployment. */
export interface ObservationView {
  application_version:   string | null;
  git_revision:          string | null;
  schema_version:        number | null;
  schema_dirty:          boolean | null;
  configuration_version: string | null;
  ready:                 boolean | null;
  open_items:            number | null;
  last_report_id:        string | null;
  last_release_at:       string | null;
  /** `[{layer, scope, changeset_id, seq, status}]` (an untyped JSON value on the wire). */
  ledger_head:           unknown;
  pending_approvals:     number | null;
  /** `timeout`, `tls`, `connect_failed`, `auth_refused`, `not_ready`, … or null. */
  error_code:            string | null;
  observed_at:           string;
}

/** `DriftView` — D-261's three outcomes against the console's own build. */
export interface DriftView {
  /** `never_observed`, `schema_dirty`, `in_sync` or `diverged`. */
  status:      string;
  /** Confirmed different: `schema_version`, `application_version`. */
  fields:      string[];
  /** Not observable: `image_digest`, `config_hash`, … */
  unconfirmed: string[];
}

/** `DeploymentView` — never carries the secret, only its last four characters. */
export interface DeploymentView {
  id:                 string;
  project_code:       string;
  label:              string;
  environment:        string;
  ring:               string;
  base_url:           string;
  maintenance_window: string | null;
  is_active:          boolean;
  has_credential:     boolean;
  s2s_client_id:      string | null;
  s2s_key_id:         string | null;
  secret_last4:       string | null;
  secret_rotated_at:  string | null;
  created_at:         string;
  updated_at:         string;
  row_version:        number;
  observation:        ObservationView | null;
  drift:              DriftView;
}

/** `CredentialBody` — the rollout S2S credential from the customer's S2S screen. */
export interface CredentialBody {
  s2s_client_id: string;
  s2s_key_id:    string;
  secret:        string;
}

/** `RegisterDeploymentBody`; a credential here needs a fresh step-up. */
export interface RegisterDeploymentBody {
  project_code:        string;
  label:               string;
  environment?:        FleetEnvironment;
  ring?:               FleetRing;
  base_url:            string;
  maintenance_window?: string | null;
  credential?:         CredentialBody | null;
}

/** `UpdateDeploymentBody`; an empty `maintenance_window` clears it. */
export interface UpdateDeploymentBody {
  row_version:         number;
  label?:              string;
  environment?:        FleetEnvironment;
  ring?:               FleetRing;
  base_url?:           string;
  maintenance_window?: string;
  is_active?:          boolean;
}

/** `SetCredentialBody` (the credential fields are flattened into it). */
export interface SetCredentialBody extends CredentialBody {
  row_version: number;
  /** One signed call with the new credential before it is stored (server default true). */
  verify?:     boolean;
}

/** `POST /api/v1/fleet/sync` (202). */
export interface SyncQueued {
  /** `false` when a sync of the whole fleet is already queued or running. */
  queued: boolean;
}

/** `ActionView` — one row of the console's append-only action log. */
export interface ActionView {
  id:             string;
  actor_ref:      string;
  deployment_ref: string | null;
  rollout_ref:    string | null;
  action:         string;
  remote_method:  string | null;
  remote_path:    string | null;
  remote_status:  number | null;
  /** `ok`, `refused` or `failed`. */
  outcome:        string;
  detail:         Record<string, unknown>;
  created_at:     string;
}

/** `ChangesetFile` — one closed changeset under `fleet.changesets_dir`. */
export interface ChangesetFile {
  id:          string;
  layer:       string;
  scope:       string;
  seq:         number;
  name:        string;
  title:       string;
  checksum:    string;
  /** Relative to `fleet.changesets_dir`, `/`-separated. */
  path:        string;
  /** The document's own checksum matches its content. */
  checksum_ok: boolean;
}

/** `ChangesetRef` — what a rollout stores; never the document body. */
export interface ChangesetRef {
  id:       string;
  checksum: string;
  path:     string;
}

/** `WaveView`. */
export interface WaveView {
  name:           string;
  /** `pending`, `in_progress`, `healthy` or `unhealthy`. */
  state:          string;
  deployment_ids: string[];
}

/** `RolloutView`. */
export interface RolloutView {
  id:          string;
  title:       string;
  /** `planned`, `in_progress`, `completed`, `halted` or `cancelled`. */
  status:      string;
  changesets:  ChangesetRef[];
  waves:       WaveView[];
  /** Index of the current wave. */
  cursor:      number;
  created_by:  string;
  created_at:  string;
  updated_at:  string;
  row_version: number;
}

/** `PlanSummary` — counts the console keeps of a customer's plan (never record values). */
export interface PlanSummary {
  changesets:         number;
  already_applied:    number;
  /** `ref` of every changeset the customer's planner blocked. */
  blocked:            string[];
  applicable:         boolean;
  risky_operations:   number;
  expand_apply_ids:   string[];
  contract_apply_ids: string[];
  /** `expand` or `contract`: the phase the next apply sends. */
  phase:              string;
}

/** `TargetView` — one customer in a rollout. */
export interface TargetView {
  id:                 string;
  rollout_id:         string;
  deployment_id:      string;
  deployment_label:   string;
  project_code:       string;
  environment:        string;
  /** Shown before Apply; a warning, not a block. */
  maintenance_window: string | null;
  wave:               number;
  /** `pending`, `planned`, `approval_pending`, `applying`, `applied`, `failed` or `skipped`. */
  status:             string;
  plan_summary:       PlanSummary | null;
  backup_ref:         string | null;
  remote_apply_ids:   string[];
  remote_approval_id: string | null;
  /** The customer's approval page while `approval_pending`. A person approves there; the console never does. */
  approval_url:       string | null;
  error_code:         string | null;
  updated_at:         string;
  row_version:        number;
}

/** `RolloutDetail`. */
export interface RolloutDetail {
  rollout: RolloutView;
  targets: TargetView[];
}

/** `StartRolloutBody`. */
export interface StartRolloutBody {
  title:          string;
  changeset_ids:  string[];
  deployment_ids: string[];
}

/** `ApplyTargetBody`; `backup_ref` is required for a `prod` deployment. */
export interface ApplyTargetBody {
  row_version: number;
  backup_ref?: string | null;
}

/** `RowVersionBody` (skip, halt, resume, cancel). */
export interface RowVersionBody {
  row_version: number;
}

/** `POST …/rollouts/{id}/refresh` (202). */
export interface StepsQueued {
  queued: number;
}

/** `DecideItemBody` (Accept, Dismiss): the item's `row_version`. */
export interface DecideItemBody {
  row_version: number;
}

/** `UseMineItemBody`: the item's `row_version` and, for a record conflict, the record's. */
export interface UseMineItemBody {
  row_version:         number;
  record_row_version?: number | null;
}

// ── The customer's release-report shapes (proxied unchanged) ────────────────

/** The customer's `ReleaseReport`. */
export interface FleetReleaseReport {
  id:                  string;
  apply_ids:           string[];
  /** Platform version and the changesets of the release. */
  release:             string;
  /** `boot | admin | replay | change`. */
  source:              string;
  /** `building | ready`. */
  status:              string;
  items_total:         number;
  items_open:          number;
  backup_ref:          string | null;
  backup_retain_until: string | null;
  created_at:          string;
  ready_at:            string | null;
  notified_at:         string | null;
  row_version:         number;
}

/** A conflict's values: the customer's (kept), ours, and the record's business key. */
export interface FleetConflictValues {
  theirs: unknown;
  ours:   unknown;
  key?:   unknown;
}

/** The customer's `ReportItemView` (`ReportItem` flattened, plus the values). */
export interface FleetReportItem {
  id:                 string;
  report_ref:         string;
  kind:               string;
  actionable:         boolean;
  status:             string;
  entity_logicalname: string;
  field_logicalname:  string | null;
  record_id:          string | null;
  object_kind:        string | null;
  object_ref:         string | null;
  detail:             Record<string, unknown>;
  has_values:         boolean;
  changeset_id:       string | null;
  op_seq:             number | null;
  decided_by:         string | null;
  decided_at:         string | null;
  superseded_by:      string | null;
  created_at:         string;
  row_version:        number;
  values?:            FleetConflictValues | null;
  /** The values exist but the rollout user may not read this field. */
  values_hidden?:     boolean;
}

/** `OpenItemView` — one open item somewhere in the fleet. */
export interface OpenItemView {
  deployment_id:    string;
  deployment_label: string;
  project_code:     string;
  report_id:        string;
  item:             FleetReportItem;
}

/** The customer's report statuses (`ReportFilter.status`). */
export const FLEET_REPORT_STATUSES = ['building', 'ready'] as const;

/** The customer's item statuses (`ItemFilter.status`). */
export const FLEET_ITEM_STATUSES = [
  'open', 'info', 'accepted', 'used_mine', 'restored', 'dismissed', 'superseded', 'expired',
] as const;

/** The customer's item kinds (`ItemFilter.kind`). */
export const FLEET_ITEM_KINDS = [
  'conflict', 'conversion_nulled', 'field_deleted',
  'customer_object_adjusted', 'customer_object_removed',
  'breaking_api_change', 'choice_removed_in_use', 'required_empty',
] as const;

/** The three item decisions the console can send. */
export type ItemDecision = 'accept' | 'use-mine' | 'dismiss';
