import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService, Page } from '@attome/base';

// Wire shapes mirror `crates/engine/attome-project/src/model.rs`'s two aggregation
// responses (`GET /project/{id}/summary`, `GET /project/{id}/work-items/rollup`)
// field-for-field — verified directly against the generated OpenAPI schema
// (`ProjectSummaryResponse`/`WorkItemRollupRow` in openapi.json) rather than
// imported from `ApiComponents['schemas']` in `@attome/base`: that generated
// file currently fails to compile (a pre-existing duplicate `list_pages`
// identifier from the in-flight Content Management work, unrelated to this
// feature — see `angular/projects/base/src/lib/generated/api-types.ts`).
// Switch these back to `ApiComponents['schemas'][...]` once that's fixed.
export interface ProjectSummary {
  project_id: string;
  /** PM-maintained (not auto-scored), and only set once someone has — can
   *  be `null` on a brand-new project. */
  health: string | null;
  weighted_progress_pct: number;
  points_completed: number;
  points_total: number;
  points_blocked: number;
  work_items_done: number;
  work_items_actionable: number;
  budget_amount: number | null;
  budget_consumed: number | null;
  budget_consumed_pct: number | null;
  /** `None` when the caller cannot read `project_resource_rate` — see
   *  `summary.rs::actual_cost`'s own doc comment. */
  actual_cost: number | null;
  open_risks_total: number;
  open_risks_critical: number;
  pending_change_requests_total: number;
  pending_change_requests_customer_facing: number;
  forecast_date: string | null;
  forecast_buffer_days: number | null;
  /** The most recently captured baseline (`POST /project/{id}/baseline`)
   *  these variance/EVM fields are computed against — `null` when none has
   *  ever been captured. See `crates/engine/attome-project/src/variance.rs`'s
   *  module doc for exactly what each field does and does not measure. */
  baseline_id: string | null;
  baseline_label: string | null;
  baseline_captured_at: string | null;
  scope_item_count_variance: number | null;
  schedule_variance_days: number | null;
  budget_at_completion: number | null;
  planned_value: number | null;
  earned_value: number | null;
  cost_performance_index: number | null;
  schedule_performance_index: number | null;
  estimate_at_completion: number | null;
  estimate_to_complete: number | null;
  variance_at_completion: number | null;
}

export interface CaptureBaselineRequest {
  label: string;
  /** `initial` | `change_request` | `manual` — defaults server-side to `manual`. */
  trigger?: string;
}

export interface CaptureBaselineResponse {
  baseline_id: string;
  project_id: string;
  label: string;
  trigger: string;
  captured_at: string;
  item_count: number;
}

/** `POST /project/change-request/{id}/approve|reject`. */
export interface ChangeRequestDecisionResponse {
  change_request_id: string;
  project_id: string;
  status: string;
  row_version: number;
  /** `true` when this call only submitted a pending four-eyes approval
   *  request (HTTP 202) rather than deciding the request immediately. */
  approval_pending: boolean;
  approval_request_id: string | null;
}

/** `POST /project/timesheet/{id}/submit|approve|reject`. */
export interface TimesheetDecisionResponse {
  timesheet_id: string;
  status: string;
  row_version: number;
  approval_pending: boolean;
  approval_request_id: string | null;
}

export interface WorkItemRollupRow {
  id: string;
  name: string;
  parent_work_item_id: string | null;
  item_type: string;
  status: string;
  owner_id: string | null;
  start_date: string | null;
  due_date: string | null;
  sequence: number | null;
  /** This row's own `points` value — meaningful only when it's a leaf; a
   *  phase/parent row's `points_total` (its descendant rollup) is what
   *  actually drives progress, never this field. */
  points_own: number;
  points_completed: number;
  points_total: number;
  points_blocked: number;
  progress_pct: number;
  /** On the critical path (CPM over the dependencies). */
  is_critical_path?: boolean;
  total_float_days?: number | null;
}

/** V1-T1: one dependency between work items. */
export interface GanttDependency {
  predecessor_id: string;
  successor_id: string;
  dependency_type: string;
  lag_days: number | null;
}

/** V1-T1: one item's planned dates in the latest baseline. */
export interface GanttBaselineItem {
  work_item_id: string;
  planned_start: string | null;
  planned_due: string | null;
}

/** V1-T1: what the Gantt chart draws (`GET /project/{id}/gantt`). */
export interface GanttView {
  items: WorkItemRollupRow[];
  dependencies: GanttDependency[];
  baseline: { baseline_id: string; label: string | null; captured_at: string | null; items: GanttBaselineItem[] } | null;
}

@Injectable({ providedIn: 'root' })
export class ProjectService {
  private readonly api = inject(ApiService);

  getSummary(projectId: string): Observable<ProjectSummary> {
    return this.api.get<ProjectSummary>(`/api/v1/project/${projectId}/summary`);
  }

  getWorkItemRollup(projectId: string): Observable<Page<WorkItemRollupRow>> {
    return this.api.get<Page<WorkItemRollupRow>>(`/api/v1/project/${projectId}/work-items/rollup`);
  }

  getGantt(projectId: string): Observable<GanttView> {
    return this.api.get<GanttView>(`/api/v1/project/${projectId}/gantt`);
  }

  /** `POST /project/{id}/baseline` — 200 when a baseline with this label
   *  already existed (returned as-is), 201 when a new one was captured; the
   *  body shape is identical either way, so callers that only care about the
   *  resulting snapshot don't need the status code. */
  captureBaseline(projectId: string, req: CaptureBaselineRequest): Observable<CaptureBaselineResponse> {
    return this.api.post<CaptureBaselineResponse>(`/api/v1/project/${projectId}/baseline`, req);
  }

  approveChangeRequest(id: string): Observable<ChangeRequestDecisionResponse> {
    return this.api.post<ChangeRequestDecisionResponse>(`/api/v1/project/change-request/${id}/approve`, {});
  }

  rejectChangeRequest(id: string): Observable<ChangeRequestDecisionResponse> {
    return this.api.post<ChangeRequestDecisionResponse>(`/api/v1/project/change-request/${id}/reject`, {});
  }

  submitTimesheet(id: string): Observable<TimesheetDecisionResponse> {
    return this.api.post<TimesheetDecisionResponse>(`/api/v1/project/timesheet/${id}/submit`, {});
  }

  approveTimesheet(id: string): Observable<TimesheetDecisionResponse> {
    return this.api.post<TimesheetDecisionResponse>(`/api/v1/project/timesheet/${id}/approve`, {});
  }

  rejectTimesheet(id: string): Observable<TimesheetDecisionResponse> {
    return this.api.post<TimesheetDecisionResponse>(`/api/v1/project/timesheet/${id}/reject`, {});
  }
}
