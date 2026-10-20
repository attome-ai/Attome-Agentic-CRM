import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';

// ── Response types (mirror attome-workflow/src/model.rs exactly) ─────────────────

export interface DefinitionListItem {
  id:                 string;
  logicalname:        string;
  name:               string;
  is_active:          boolean;
  published_version:  number | null;
  created_at:         string;
  /** Solution 7 (D-785): the owning layer, typed from the generated `DefinitionListItem`. */
  owner_layer?: ApiComponents['schemas']['DefinitionListItem']['owner_layer'];
}

export interface VersionSummary {
  id:             string;
  version_number: number;
  status:         string;
  published_at:   string | null;
  row_version:    number;
}

export interface DefinitionDetail {
  id:          string;
  logicalname: string;
  name:        string;
  is_active:   boolean;
  row_version: number;
  created_at:  string;
  updated_at:  string;
  versions:    VersionSummary[];
  /** Solution 7 (D-785): the owning layer, typed from the generated `DefinitionDetail`. */
  owner_layer?: ApiComponents['schemas']['DefinitionDetail']['owner_layer'];
}

export interface VersionDetail {
  id:             string;
  definition_id:  string;
  version_number: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  graph:          any;
  status:         string;
  published_at:   string | null;
  row_version:    number;
  created_at:     string;
}

// ── Request bodies ─────────────────────────────────────────────────────────────

export interface CreateDefinitionBody {
  logicalname: string;
  name:        string;
}

export interface UpdateDefinitionBody {
  name?:       string;
  is_active?:  boolean;
  row_version: number;
}

export interface CreateVersionBody {
  graph?: unknown;
}

export interface UpdateVersionGraphBody {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  graph:       any;
  row_version: number;
}

// ── Graph shape (mirrors attome-workflow/src/graph.rs) ────────────────────────────

export interface GraphNode {
  id:   string;
  type: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  config: Record<string, any>;
  /** Editor-owned metadata only — position on canvas. Opaque to the engine. */
  ports: { x: number; y: number };
}

export interface GraphEdge {
  from_node: string;
  from_port: string;
  to_node:   string;
  to_port:   string;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** Mirrors `attome_workflow::node_types::NodeType` exactly — see that module's
 *  registry for the authoritative port list; this is the editor's own copy
 *  so the canvas can render/validate ports without a round trip. */
export interface NodeTypePort { name: string; portType: string; required?: boolean }
export interface NodeTypeSpec {
  type:    string;
  label:   string;
  inputs:  NodeTypePort[];
  outputs: NodeTypePort[];
  isEntry?: boolean;
}

export const NODE_TYPES: NodeTypeSpec[] = [
  { type: 'trigger', label: 'Trigger', isEntry: true, inputs: [], outputs: [{ name: 'out', portType: 'any' }] },
  { type: 'condition', label: 'Condition', inputs: [{ name: 'value', portType: 'any', required: true }],
    outputs: [{ name: 'true', portType: 'any' }, { name: 'false', portType: 'any' }] },
  { type: 'create_record', label: 'Create Record', inputs: [{ name: 'data', portType: 'json', required: true }],
    outputs: [{ name: 'record', portType: 'record_id' }] },
  { type: 'update_record', label: 'Update Record',
    inputs: [{ name: 'record_id', portType: 'record_id', required: true }, { name: 'data', portType: 'json', required: true }],
    outputs: [{ name: 'record', portType: 'record_id' }] },
  { type: 'send_notification', label: 'Send Notification', inputs: [{ name: 'variables', portType: 'json' }],
    outputs: [{ name: 'out', portType: 'any' }] },
  { type: 'approval', label: 'Approval', inputs: [{ name: 'payload', portType: 'json' }],
    outputs: [{ name: 'approved', portType: 'any' }, { name: 'rejected', portType: 'any' }] },
  { type: 'wait', label: 'Wait / Delay', inputs: [{ name: 'in', portType: 'any' }], outputs: [{ name: 'out', portType: 'any' }] },
  { type: 'wait_for_event', label: 'Wait for Event', inputs: [{ name: 'in', portType: 'any' }],
    outputs: [{ name: 'event', portType: 'json' }] },
  { type: 'sub_workflow', label: 'Sub-Workflow', inputs: [{ name: 'input', portType: 'json' }],
    outputs: [{ name: 'output', portType: 'json' }] },
  { type: 'webhook', label: 'Webhook / HTTP Call', inputs: [{ name: 'body', portType: 'json' }],
    outputs: [{ name: 'response', portType: 'json' }] },
  { type: 'split', label: 'Split (parallel)', inputs: [{ name: 'in', portType: 'any', required: true }],
    outputs: [{ name: 'out', portType: 'any' }] },
  { type: 'join', label: 'Join', inputs: [{ name: 'in', portType: 'any', required: true }],
    outputs: [{ name: 'out', portType: 'any' }] },
  { type: 'restore_record', label: 'Restore Record',
    inputs: [{ name: 'record_id', portType: 'record_id', required: true }],
    outputs: [{ name: 'record', portType: 'record_id' }] },
  // A15-T9: "if a duplicate exists".
  { type: 'duplicate_check', label: 'If a Duplicate Exists',
    inputs: [{ name: 'record_id', portType: 'record_id', required: true }],
    outputs: [{ name: 'found', portType: 'json' }, { name: 'none', portType: 'json' }] },
  // M11-T1: set the record's owner by a strategy.
  { type: 'assign', label: 'Assign Owner',
    inputs: [{ name: 'record_id', portType: 'record_id', required: true }],
    outputs: [{ name: 'record', portType: 'record_id' }] },
  // E8-T2: a step another module contributes (a journey's send email).
  { type: 'module_step', label: 'Module Step', inputs: [{ name: 'input', portType: 'json' }],
    outputs: [{ name: 'output', portType: 'json' }] },
];

export function nodeTypeSpec(type: string): NodeTypeSpec | undefined {
  return NODE_TYPES.find(t => t.type === type);
}

// ── Per-node-type config schema ───────────────────────────────────────────────
//
// Mirrors what each executor in `attome_workflow::scheduler` (plus
// `trigger_index::rebuild_entry_rows` for `trigger`) actually reads out of
// `node.config` — same "editor keeps its own copy of the registry" contract
// as NODE_TYPES above. This drives the inspector's generated form so a graph
// author does not have to know the key names; it is *not* a validator, and it
// never narrows what the node may carry: the editor preserves any config key
// outside this schema untouched and exposes it through the raw-JSON escape
// hatch. When an executor learns a new config key, add it here.

export type NodeConfigKind =
  | 'text'      // free string
  | 'textarea'  // multi-line string
  | 'number'    // JSON number (integer in every current case)
  | 'bool'      // JSON boolean
  | 'select'    // closed string enum
  | 'json'      // arbitrary JSON subtree, edited as text
  | 'entity'    // string logicalname, with an entity-name datalist
  | 'workflow'; // string logicalname, with a workflow-definition datalist

export interface NodeConfigField {
  key:   string;
  label: string;
  kind:  NodeConfigKind;
  /** The value the executor falls back to when the key is absent. Shown as a
   *  placeholder / preselected option; never written into config on its own. */
  default?: string | number | boolean;
  /** The executor fails the node at run time when this key is missing. */
  required?: boolean;
  options?: { value: string; label: string }[];
  hint?:    string;
  /** Render only while another field's effective value is one of these. */
  showIf?: { key: string; in: string[] };
}

export const NODE_CONFIG_SCHEMA: Record<string, NodeConfigField[]> = {
  // trigger_index::rebuild_entry_rows
  trigger: [
    { key: 'trigger_type', label: 'Trigger type', kind: 'select', default: 'manual',
      options: [
        { value: 'manual',   label: 'Manual / API start' },
        { value: 'create',   label: 'Entity created' },
        { value: 'update',   label: 'Entity updated' },
        { value: 'delete',   label: 'Entity deleted' },
        { value: 'restore',  label: 'Entity restored' },
        { value: 'merge',    label: 'Records merged' },
        { value: 'schedule', label: 'Schedule' },
      ] },
    { key: 'entity_logicalname', label: 'Entity', kind: 'entity',
      showIf: { key: 'trigger_type', in: ['create', 'update', 'delete', 'restore', 'merge'] },
      hint: 'Logical name of the entity whose writes start this workflow.' },
    // Both keys are folded into workflow_trigger_index.condition by
    // `trigger_index::entry_condition` and enforced at dispatch
    // (`entity_trigger`, M06 G3): `condition` narrows by record_id/operation,
    // `expression` is a attome-rules boolean evaluated against the record. Gated
    // to create/update, the only trigger types they apply to.
    { key: 'condition', label: 'Match condition', kind: 'json',
      showIf: { key: 'trigger_type', in: ['create', 'update'] },
      hint: 'Optional. Only {"record_id": "<uuid>"} and {"operation": "create"|"update"} '
          + 'are understood; other keys are ignored.' },
    { key: 'expression', label: 'Start only when', kind: 'text',
      showIf: { key: 'trigger_type', in: ['create', 'update'] },
      hint: 'Optional rules expression evaluated against the record (e.g. amount > 1000). '
          + 'Only a true result starts the workflow; publishing rejects an expression '
          + 'that does not compile or is not true/false.' },
    // M1-T1: an update trigger starts only when one of these attributes changed.
    { key: 'attributes', label: 'Only when these change', kind: 'json',
      showIf: { key: 'trigger_type', in: ['update'] },
      hint: 'Optional JSON array of attribute names, e.g. ["stage", "amount"].' },
    // M1-T2: `schedule_trigger` starts the flow once per slot.
    { key: 'schedule', label: 'Schedule', kind: 'json',
      showIf: { key: 'trigger_type', in: ['schedule'] },
      hint: '{"every_minutes": 15}, {"daily_at": "09:00", "weekdays": [1,2,3,4,5]} or '
          + '{"cron": "0 9 * * 1-5"}, in the deployment time zone.' },
  ],
  // scheduler::eval_condition
  condition: [
    { key: 'field', label: 'Field path', kind: 'text',
      hint: 'Dot path into the input value (e.g. data.status). Blank compares the whole value.' },
    { key: 'op', label: 'Operator', kind: 'select', default: 'eq',
      options: [
        { value: 'eq',       label: 'equals' },
        { value: 'neq',      label: 'not equals' },
        { value: 'gt',       label: 'greater than (numeric)' },
        { value: 'lt',       label: 'less than (numeric)' },
        { value: 'contains', label: 'contains (string / array)' },
        { value: 'truthy',   label: 'is truthy' },
      ] },
    { key: 'value', label: 'Compare to', kind: 'json',
      showIf: { key: 'op', in: ['eq', 'neq', 'gt', 'lt', 'contains'] },
      hint: 'JSON literal — "draft" for a string, 10 for a number, true for a boolean.' },
  ],
  // scheduler::execute_entity_write
  create_record: [
    { key: 'entity', label: 'Entity', kind: 'entity', required: true,
      hint: 'Column values come from the wired "data" input, not from config.' },
  ],
  update_record: [
    { key: 'entity', label: 'Entity', kind: 'entity', required: true,
      hint: 'Target row comes from the wired "record_id" input, values from "data".' },
  ],
  // scheduler::execute_duplicate_check
  duplicate_check: [
    { key: 'entity', label: 'Entity', kind: 'entity', required: true,
      hint: 'The record comes from the wired "record_id" input; "found" lists the matches under the entity\'s duplicate rules.' },
  ],
  // scheduler::execute_assign
  assign: [
    { key: 'entity', label: 'Entity', kind: 'entity', required: true,
      hint: 'The record comes from the wired "record_id" input; its owner is set.' },
    { key: 'strategy', label: 'Strategy', kind: 'select', default: 'round_robin',
      options: [
        { value: 'round_robin',  label: 'Round robin' },
        { value: 'least_loaded', label: 'Fewest records' },
        { value: 'skills',       label: 'Skills match' },
        { value: 'territory',    label: 'Territory owner' },
        { value: 'rule',         label: 'Rules' },
      ] },
    { key: 'team_ref', label: 'Team ID', kind: 'text', hint: 'Candidates: members of this team.' },
    { key: 'queue_ref', label: 'Queue ID', kind: 'text', hint: 'Candidates: members of this work queue.' },
    { key: 'role_ref', label: 'Role ID', kind: 'text', hint: 'Candidates: holders of this role.' },
    { key: 'skills', label: 'Required skills', kind: 'json',
      showIf: { key: 'strategy', in: ['skills'] }, hint: 'A list of skill names, e.g. ["Arabic", "Billing"].' },
    { key: 'territory_field', label: 'Territory attribute', kind: 'text', default: 'territory_ref',
      showIf: { key: 'strategy', in: ['territory'] } },
    { key: 'rules', label: 'Rules', kind: 'json', showIf: { key: 'strategy', in: ['rule'] },
      hint: 'A list of {"field", "equals", "user"}; the first match wins.' },
    { key: 'fallback_queue_ref', label: 'Fallback queue ID', kind: 'text',
      hint: 'When nobody fits, the next member of this queue gets the record.' },
  ],
  // scheduler::execute_restore_record
  restore_record: [
    { key: 'entity', label: 'Entity', kind: 'entity', required: true,
      hint: 'The deleted record comes from the wired "record_id" input; one already live is left as it is.' },
  ],
  // scheduler::execute_send_notification
  send_notification: [
    { key: 'template_key', label: 'Template key', kind: 'text', default: 'workflow.generic' },
    { key: 'subject',   label: 'Subject',   kind: 'text' },
    { key: 'body_text', label: 'Body text', kind: 'textarea',
      hint: 'Template variables come from the wired "variables" input.' },
    { key: 'locale', label: 'Locale', kind: 'text', default: 'en' },
    { key: 'recipient_user_ref', label: 'Recipient user ID', kind: 'text',
      hint: 'User UUID. Leave blank and tick Global to broadcast instead.' },
    { key: 'is_global', label: 'Global (all users)', kind: 'bool', default: false },
  ],
  // scheduler::execute_approval
  approval: [
    { key: 'action_type', label: 'Action type', kind: 'text', default: 'workflow.approval',
      hint: 'attome_approval action key the request is filed under.' },
    { key: 'ttl_hours', label: 'Expires after (hours)', kind: 'number', default: 72,
      hint: 'On expiry the node takes the "rejected" port.' },
  ],
  // scheduler::execute_wait
  wait: [
    { key: 'delay_seconds', label: 'Delay (seconds)', kind: 'number', default: 0 },
    { key: 'resume_at', label: 'Resume at', kind: 'text',
      hint: 'RFC-3339 UTC timestamp. When set it overrides the delay entirely.' },
  ],
  // scheduler::execute_wait_for_event
  wait_for_event: [
    { key: 'entity_logicalname', label: 'Entity', kind: 'entity',
      hint: 'Blank waits on any entity event.' },
    // Unlike the trigger's, this condition IS evaluated —
    // `entity_trigger::wait_condition_matches`, which understands exactly two
    // keys and ignores everything else. Spelled out here because "condition"
    // reads like a general field matcher and is not one.
    { key: 'condition', label: 'Match condition', kind: 'json',
      hint: 'Optional. Only {"record_id": "<uuid>"} and {"operation": "create"|"update"} '
          + 'are understood; either or both may be omitted. Other keys are ignored — '
          + 'filter on field values with a Condition node instead.' },
  ],
  // scheduler::execute_sub_workflow
  sub_workflow: [
    { key: 'definition_logicalname', label: 'Workflow', kind: 'workflow', required: true,
      hint: 'Must have a published version. Nesting is capped at 20 levels deep.' },
  ],
  // scheduler::execute_webhook
  webhook: [
    { key: 'url', label: 'URL', kind: 'text', required: true },
    { key: 'method', label: 'Method', kind: 'select', default: 'POST',
      options: ['POST', 'GET', 'PUT', 'PATCH', 'DELETE'].map(m => ({ value: m, label: m })) },
  ],
  // scheduler::execute_module_step (E8-T2)
  module_step: [
    { key: 'handler', label: 'Step', kind: 'text', required: true,
      hint: 'The registered step key, such as marketing.send_email.' },
    { key: 'config', label: 'Step settings', kind: 'json' },
    { key: 'retry_after_seconds', label: 'Retry a blocked step after (seconds)', kind: 'number', default: 3600 },
  ],
  // scheduler::join_mode_and_threshold
  join: [
    { key: 'mode', label: 'Mode', kind: 'select', default: 'all',
      options: [
        { value: 'all',    label: 'All branches' },
        { value: 'any',    label: 'Any one branch' },
        { value: 'n_of_m', label: 'N of M branches' },
      ] },
    { key: 'n', label: 'N (threshold)', kind: 'number', default: 1,
      showIf: { key: 'mode', in: ['n_of_m'] },
      hint: 'How many inbound branches must settle before this join fires. Clamped to the number of wired branches.' },
  ],
};

export function nodeConfigFields(type: string): NodeConfigField[] {
  return NODE_CONFIG_SCHEMA[type] ?? [];
}

// ── Instances (mirrors instance_admin.rs) ───────────────────────────────────────

export interface InstanceListItem {
  id:                    string;
  definition_version_id: string;
  status:                string;
  started_at:            string;
  completed_at:          string | null;
  correlation_entity_id: string | null;
}

export interface NodeRunSummary {
  node_id:       string;
  status:        string;
  attempt_count: number;
  last_error:    string | null;
  started_at:    string | null;
  completed_at:  string | null;
}

export interface InstanceDetail {
  id:                    string;
  definition_version_id: string;
  status:                string;
  started_at:            string;
  completed_at:          string | null;
  started_by:            string | null;
  correlation_entity_id: string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  context:               any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  node_data:              any;
  row_version:           number;
  node_runs:             NodeRunSummary[];
}

export interface StartInstanceBody {
  definition_logicalname: string;
  context?: unknown;
  correlation_entity_id?: string;
}

// ── Simulate / dry-run (mirrors attome-workflow/src/model.rs's Simulate* types) ────

export interface SimulateRequestBody {
  trigger_payload?: unknown;
  /** node id -> "approved" | "rejected", for any `approval` node the run reaches. */
  approval_decisions?: Record<string, string>;
}

export interface SimulateNodeTrace {
  node_id:      string;
  node_type:    string;
  /** `succeeded` | `skipped` | `waiting` | `failed`. */
  status:       string;
  taken_port:   string | null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  output:       any;
  would_have:   string | null;
  error:        string | null;
}

export interface SimulateResponse {
  /** `completed` | `would_wait` | `failed`. */
  status: string;
  trace:  SimulateNodeTrace[];
}

@Injectable({ providedIn: 'root' })
export class WorkflowAdminService {
  private readonly api = inject(ApiService);

  /** One-based, like every offset list (D-347, D-793) — `getAllPages`' default. */
  listDefinitions(isActive?: boolean): Observable<DefinitionListItem[]> {
    return this.api.getAllPages<DefinitionListItem>(
      '/api/v1/workflow/definitions',
      isActive === undefined ? {} : { is_active: String(isActive) },
    );
  }

  createDefinition(body: CreateDefinitionBody): Observable<DefinitionDetail> {
    return this.api.post<DefinitionDetail>('/api/v1/workflow/definitions', body);
  }

  getDefinition(id: string): Observable<DefinitionDetail> {
    return this.api.get<DefinitionDetail>(`/api/v1/workflow/definitions/${id}`);
  }

  updateDefinition(id: string, body: UpdateDefinitionBody): Observable<DefinitionDetail> {
    return this.api.patch<DefinitionDetail>(`/api/v1/workflow/definitions/${id}`, body);
  }

  deleteDefinition(id: string): Observable<void> {
    return this.api.delete(`/api/v1/workflow/definitions/${id}`);
  }

  createVersion(definitionId: string, body: CreateVersionBody = {}): Observable<VersionDetail> {
    return this.api.post<VersionDetail>(`/api/v1/workflow/definitions/${definitionId}/versions`, body);
  }

  getVersion(definitionId: string, versionId: string): Observable<VersionDetail> {
    return this.api.get<VersionDetail>(`/api/v1/workflow/definitions/${definitionId}/versions/${versionId}`);
  }

  updateVersionGraph(definitionId: string, versionId: string, body: UpdateVersionGraphBody): Observable<VersionDetail> {
    return this.api.patch<VersionDetail>(
      `/api/v1/workflow/definitions/${definitionId}/versions/${versionId}`, body,
    );
  }

  publishVersion(definitionId: string, versionId: string): Observable<VersionDetail> {
    return this.api.post<VersionDetail>(
      `/api/v1/workflow/definitions/${definitionId}/versions/${versionId}/publish`, {},
    );
  }

  simulateVersion(definitionId: string, versionId: string, body: SimulateRequestBody = {}): Observable<SimulateResponse> {
    return this.api.post<SimulateResponse>(
      `/api/v1/workflow/definitions/${definitionId}/versions/${versionId}/simulate`, body,
    );
  }

  /** One-based, like `/workflow/definitions` above (D-347). */
  listInstances(status?: string): Observable<InstanceListItem[]> {
    return this.api.getAllPages<InstanceListItem>(
      '/api/v1/workflow/instances',
      status ? { status } : {},
    );
  }

  getInstance(id: string): Observable<InstanceDetail> {
    return this.api.get<InstanceDetail>(`/api/v1/workflow/instances/${id}`);
  }

  cancelInstance(id: string, rowVersion: number): Observable<unknown> {
    return this.api.post(`/api/v1/workflow/instances/${id}/cancel`, { row_version: rowVersion });
  }

  startInstance(body: StartInstanceBody): Observable<{ id: string }> {
    return this.api.post<{ id: string }>('/api/v1/workflow/instances', body);
  }
}
