import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import { QueryColumnDef } from './types';

/** D-429 (+ chart, migration 0447) — how a view renders. Kind-specific
 * settings live in `view_metadata`. */
export type ViewKind = 'list' | 'kanban' | 'calendar' | 'timeline' | 'chart';

/** D-429 — `kanban` view_metadata: columns = the state field's choice values,
 * card template = the view's own `table_definition` columns. `wip_limits` is
 * advisory only — never enforced server-side; a drag past the limit is only
 * ever refused by the transition endpoint itself, never by this UI. */
export interface KanbanViewMetadata {
  state_field: string;
  wip_limits?: Record<string, number | null>;
}

/** D-429 — `calendar`/`timeline` view_metadata. */
export interface CalendarViewMetadata {
  start_field: string;
  end_field: string;
  color_field?: string | null;
}

export type ChartType = 'line' | 'area' | 'bar' | 'column' | 'donut' | 'pie' | 'funnel';
export type ChartAggregation = 'sum' | 'avg' | 'count' | 'count_distinct' | 'min' | 'max' | 'median';
export type ChartDateBucket = 'day' | 'week' | 'month' | 'quarter' | 'year';
export type ChartSort = 'x_asc' | 'x_desc' | 'value_asc' | 'value_desc';

export interface ChartSeries {
  field:       string;
  aggregation: ChartAggregation;
  label:       string;
  label_ar?:   string | null;
  color?:      string | null;
}

/** `kind = "chart"` view_metadata (migration 0447, D-429 follow-up) — mirrors
 * `chart_view_metadata::ChartViewMetadata` exactly (`attome-api`). Validated
 * server-side by `chart_view_metadata::validate` on every create/update. */
export interface ChartViewMetadata {
  chart_type:  ChartType;
  x_field:     string;
  x_bucket?:   ChartDateBucket | null;
  y_fields:    ChartSeries[];
  group_by_field?: string | null;
  sort?:       ChartSort | null;
  limit?:      number | null;
  other_bucket?: boolean;
  stacked?:    boolean;
  cumulative?: boolean;
  percent_of_total?: boolean;
  moving_average_window?: number | null;
  threshold?: { value: number; label?: string | null } | null;
  show_legend?: boolean;
  number_format?: {
    decimals?: number | null;
    currency_code?: string | null;
    unit_suffix?: string | null;
  } | null;
}

export interface ViewDetail {
  id: string;
  name: string;
  icon: string;
  entity_logical_name: string;
  entity_name: string;
  sql_query_ref: string;
  query_name: string;
  table_definition: QueryColumnDef[];
  is_default: boolean;
  is_active: boolean;
  kind: ViewKind;
  view_metadata: Record<string, unknown>;
  scope: 'system' | 'personal' | 'shared';
  owner_ref: string | null;
  /** Solution 7 (D-785): which layer owns this view — platform, product, project or customer. */
  owner_layer: string;
}

export interface ViewBody {
  name: string;
  icon: string;
  entity_logical_name: string;
  sql_query_ref: string;
  table_definition: QueryColumnDef[];
  is_default: boolean;
  kind?: ViewKind;
  view_metadata?: Record<string, unknown>;
}

export interface AvailableView {
  id: string;
  name: string;
  icon: string;
  is_default: boolean;
  kind: ViewKind;
  view_metadata: Record<string, unknown>;
  scope: 'system' | 'personal' | 'shared';
  /** `true` only for a `personal`/`shared` row the caller themselves owns —
   * drives whether the list toolbar offers edit/delete/share for it. Never
   * used for enforcement; the mutating routes re-check ownership server-side. */
  is_mine: boolean;
}

/** `POST /api/v1/views` (self-service "save as my view", D-429) — always
 * reuses an existing, already-privilege-gated `sql_query_ref`; a self-service
 * caller cannot author SQL. `entity` is the logicalname, not a resolved id
 * (the server resolves it), matching what a list screen already has on hand. */
export interface CreatePersonalViewBody {
  name: string;
  icon: string;
  entity: string;
  sql_query_ref: string;
  table_definition: QueryColumnDef[];
  kind?: ViewKind;
  view_metadata?: Record<string, unknown>;
}

/** `PATCH /api/v1/views/{id}` — owner-only, `entity`/`sql_query_ref` are
 * immutable once a personal view exists. */
export interface UpdatePersonalViewBody {
  name: string;
  icon: string;
  table_definition: QueryColumnDef[];
  kind?: ViewKind;
  view_metadata?: Record<string, unknown>;
}

@Injectable({ providedIn: 'root' })
export class ViewAdminService {
  private readonly api = inject(ApiService);

  // ── Admin (system-scope) CRUD ───────────────────────────────────────────
  list(): Observable<ViewDetail[]> { return this.api.getAllPages<ViewDetail>('/api/v1/admin/views'); }
  get(id: string): Observable<ViewDetail> { return this.api.get<ViewDetail>(`/api/v1/admin/views/${id}`); }
  create(body: ViewBody): Observable<ViewDetail> { return this.api.post<ViewDetail>('/api/v1/admin/views', body); }
  update(id: string, body: ViewBody): Observable<ViewDetail> {
    return this.api.patch<ViewDetail>(`/api/v1/admin/views/${id}`, body);
  }
  delete(id: string): Observable<void> { return this.api.delete(`/api/v1/admin/views/${id}`); }

  // ── Self-service ─────────────────────────────────────────────────────────
  listAvailable(entity: string): Observable<AvailableView[]> {
    return this.api.get<AvailableView[]>(`/api/v1/views?entity=${encodeURIComponent(entity)}`);
  }

  /** "Save as my view" — creates a personal (owner-only) view. */
  createMine(body: CreatePersonalViewBody): Observable<ViewDetail> {
    return this.api.post<ViewDetail>('/api/v1/views', body);
  }

  updateMine(id: string, body: UpdatePersonalViewBody): Observable<ViewDetail> {
    return this.api.patch<ViewDetail>(`/api/v1/views/${id}`, body);
  }

  deleteMine(id: string): Observable<void> { return this.api.delete(`/api/v1/views/${id}`); }

  /** Promotes a personal view to `shared` — visible to any caller who holds
   * the underlying query's privilege, same gate a system view uses. Audited
   * server-side (`AuditOperation::PermissionChange`, `event_name:
   * 'view_shared'`). Owner-only; a non-owner gets a 404 (D-429). */
  share(id: string): Observable<ViewDetail> {
    return this.api.post<ViewDetail>(`/api/v1/views/${id}/share`, {});
  }
}
