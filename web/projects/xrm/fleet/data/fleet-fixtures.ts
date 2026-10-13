import type {
  DeploymentView, FleetReportItem, RolloutDetail, TargetView,
} from './fleet.types';

/*
 * Test data for the fleet console specs only. Not exported from the entry
 * point's public API, so it never reaches a bundle.
 */

export function fixtureDeployment(id: string, patch: Partial<DeploymentView> = {}): DeploymentView {
  return {
    id, project_code: 'BMD', label: `Customer ${id}`, environment: 'prod', ring: 'broad',
    base_url: 'https://bmd.example', maintenance_window: null, is_active: true, has_credential: true,
    s2s_client_id: 'client', s2s_key_id: 'key', secret_last4: 'abcd', secret_rotated_at: null,
    created_at: '2026-10-01T10:00:00Z', updated_at: '2026-10-01T10:00:00Z', row_version: 1,
    observation: {
      application_version: '1.2.0', git_revision: null, schema_version: 543, schema_dirty: false,
      configuration_version: null, ready: true, open_items: 2, last_report_id: null, last_release_at: null,
      ledger_head: [], pending_approvals: 0, error_code: null, observed_at: '2026-10-01T10:05:00Z',
    },
    drift: { status: 'in_sync', fields: [], unconfirmed: ['image_digest', 'config_hash'] },
    ...patch,
  };
}

export function fixtureItem(id: string, patch: Partial<FleetReportItem> = {}): FleetReportItem {
  return {
    id, report_ref: 'r1', kind: 'conflict', actionable: true, status: 'open',
    entity_logicalname: 'contact', field_logicalname: 'email', record_id: 'rec-1',
    object_kind: null, object_ref: null, detail: {}, has_values: true, changeset_id: null, op_seq: null,
    decided_by: null, decided_at: null, superseded_by: null, created_at: '2026-10-01T10:00:00Z',
    row_version: 3, values: { theirs: 'a@customer.example', ours: 'b@example' }, values_hidden: false,
    ...patch,
  };
}

export function fixtureTarget(id: string, patch: Partial<TargetView> = {}): TargetView {
  return {
    id, rollout_id: 'ro1', deployment_id: 'd1', deployment_label: 'Customer d1', project_code: 'BMD',
    environment: 'prod', maintenance_window: 'Fri 22:00-02:00', wave: 0, status: 'planned',
    plan_summary: {
      changesets: 2, already_applied: 0, blocked: [], applicable: true, risky_operations: 1,
      expand_apply_ids: ['a1'], contract_apply_ids: [], phase: 'expand',
    },
    backup_ref: null, remote_apply_ids: [], remote_approval_id: null, approval_url: null,
    error_code: null, updated_at: '2026-10-01T10:00:00Z', row_version: 1,
    ...patch,
  };
}

export function fixtureRollout(status = 'in_progress', targets: TargetView[] = [fixtureTarget('t1')]): RolloutDetail {
  return {
    rollout: {
      id: 'ro1', title: 'October release', status,
      changesets: [{ id: 'c1', checksum: 'x', path: 'platform/0001.json' }],
      waves: [{ name: 'canary', state: 'in_progress', deployment_ids: ['d1'] }],
      cursor: 0, created_by: 'u1', created_at: '2026-10-01T09:00:00Z', updated_at: '2026-10-01T09:00:00Z',
      row_version: 4,
    },
    targets,
  };
}
