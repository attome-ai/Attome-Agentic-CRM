import { inject, Injectable } from '@angular/core';
import { map, Observable, of, switchMap } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityRecordResponse, EntityService } from '@attome/xrm/core/entity';

// R-10 (M26-dashboard-remediation) — the `@attome/xrm/dashboard/data` entry
// point: services and wire types only, no components (D-314). Every raw
// `/api/v1/attome-dashboard/...` string that used to live inline in
// `page-editor.component.ts`, `dashboard-editor.component.ts`,
// `dashboard.actions.ts`, `dashboard-template-gallery.component.ts`,
// `dashboard-viewer.component.ts` moved here, so the bespoke lifecycle/
// health-check/widget-registry routes have exactly one client-side owner.
// Response shapes come from the generated OpenAPI contract
// (`ApiComponents['schemas'][...]`, `@attome/base`) rather than hand-mirrored
// interfaces.

export type HealthCheckResponse = ApiComponents['schemas']['HealthCheckResponse'];
export type BrokenWidgetRef     = ApiComponents['schemas']['BrokenWidgetRef'];
export type TransitionResponse  = ApiComponents['schemas']['TransitionResponse'];
export type PublishResponse     = ApiComponents['schemas']['PublishResponse'];
export type CloneResponse       = ApiComponents['schemas']['CloneResponse'];
export type RestoreResponse     = ApiComponents['schemas']['RestoreResponse'];
export type WidgetDescriptor    = ApiComponents['schemas']['WidgetDescriptor'];
export type DuplicateResponse   = ApiComponents['schemas']['DuplicateResponse'];
export type ResolveVariablesResponse = ApiComponents['schemas']['ResolveVariablesResponse'];
export type ValidateConfigResponse   = ApiComponents['schemas']['ValidateConfigResponse'];
// Dashboard 10/10 Phase 1 (D-520, D-521, D-527).
export type DraftTreeResponse   = ApiComponents['schemas']['DraftTree'];
export type TreeRecord          = ApiComponents['schemas']['TreeRecord'];
export type NewPageBody         = ApiComponents['schemas']['NewPageBody'];
export type CreatedPage         = ApiComponents['schemas']['CreatedPage'];
export type RepairedRootSection = ApiComponents['schemas']['RepairedRootSection'];
export type PublishedDashboard  = ApiComponents['schemas']['PublishedDashboard'];
export type ActivateResponse    = ApiComponents['schemas']['ActivateResponse'];
// Dashboard 10/10 Phase 2 (D-522, D-523, D-525).
export type WidgetInputs        = ApiComponents['schemas']['WidgetInputs'];
export type WidgetDataResponse  = ApiComponents['schemas']['WidgetDataResponse'];
export type PageDataResponse    = ApiComponents['schemas']['PageDataResponse'];
export type PageWidgetResult    = ApiComponents['schemas']['PageWidgetResult'];
export type StructuredBucket    = ApiComponents['schemas']['StructuredBucket'];
export type BucketKey           = ApiComponents['schemas']['BucketKey'];
export type KpiMetric           = ApiComponents['schemas']['KpiMetric'];
export type KpiPoint            = ApiComponents['schemas']['KpiPoint'];
export type RenderKind          = ApiComponents['schemas']['RenderKind'];
export type MeasureFn           = ApiComponents['schemas']['MeasureFn'];
export type DateBucket          = ApiComponents['schemas']['DateBucket'];
// Dashboard 10/10 Phase 3.
export type WidgetRecordsInputs   = ApiComponents['schemas']['WidgetRecordsInputs'];
export type WidgetRecordsResponse = ApiComponents['schemas']['WidgetRecordsResponse'];
export type WidgetExplanation     = ApiComponents['schemas']['WidgetExplanation'];
export type MetricLineageNode     = ApiComponents['schemas']['MetricLineageNode'];
export type GateIssue             = ApiComponents['schemas']['GateIssue'];

/** One declared `dashboard_parameter` as the executed definition carries
 * it — the filter bar is built from these, never from live rows, so a
 * published dashboard's filter bar is part of what was published (D-543). */
export interface DashboardParameter {
  id: string;
  name: string;
  name_ar: string | null;
  page_id: string | null;
  parameter_type: 'date_range' | 'choice' | 'text' | 'number' | 'entity_lookup';
  default_value: string | null;
}

export type DashboardLifecycleAction =
  | 'submit-review' | 'approve' | 'reject' | 'publish' | 'unpublish' | 'archive' | 'start-revision';

/** What a viewer of a dashboard is shown (D-521): an immutable published
 * version, a legacy dashboard marked published with no version (rendered
 * from its live tree, never pinned), or nothing. */
export type PublishedState = 'published' | 'none';

/** One `attome_dashboard`'s full page/section/widget tree — `loadTree`'s return
 * shape. `sections` spans every page (not just one), and `widgetsBySection`
 * is keyed by section id across the whole tree, so a caller that already has
 * the tree can switch the selected page with no further network round trip. */
export interface DashboardTree {
  dashboard: EntityRecordResponse;
  pages:     EntityRecord[];
  sections:  EntityRecord[];
  widgetsBySection: ReadonlyMap<string, EntityRecord[]>;
}

/** `loadPublished`'s return shape: the published snapshot already mapped into
 * the same tree shape the draft uses, plus the parameter declarations it was
 * published with. Widgets never execute client-side: each one's data comes
 * from `pageData`/`widgetData`, which resolve the definition on the server. */
export interface PublishedView {
  state:         PublishedState;
  versionId:     string | null;
  versionNumber: number | null;
  tree:          DashboardTree | null;
  parameters:    DashboardParameter[];
}

/** One page's own section/widget tree — `loadPageWidgets`'s return shape.
 * `dashboardId` is `null` for a page no dashboard owns yet (created through
 * the retired many-to-many page link and not reconciled, D-520): the editor has
 * nothing to load it through. `needsRootSection` reports a page with no
 * section, which the editor repairs explicitly — no read path writes (D-527). */
export interface PageWidgetTree {
  page:             EntityRecordResponse;
  dashboardId:      string | null;
  rootSectionId:    string | null;
  needsRootSection: boolean;
  widgets:          EntityRecord[];
}

const sequenceOf = (r: EntityRecord): number => Number(r.data['sequence'] ?? 0);

function toEntityRecord(rec: { id: string; row_version: number; data: Record<string, unknown> }, entityId = ''): EntityRecord {
  return {
    id: rec.id,
    entity_id: entityId,
    data: rec.data,
    row_version: rec.row_version,
    created_at: String(rec.data['created_at'] ?? ''),
    updated_at: String(rec.data['modified_at'] ?? ''),
  };
}

function groupWidgets(widgets: EntityRecord[]): Map<string, EntityRecord[]> {
  const bySection = new Map<string, EntityRecord[]>();
  for (const w of widgets) {
    const sectionId = String(w.data['section_id'] ?? '');
    const list = bySection.get(sectionId) ?? [];
    list.push(w);
    bySection.set(sectionId, list);
  }
  for (const list of bySection.values()) list.sort((a, b) => sequenceOf(a) - sequenceOf(b));
  return bySection;
}

/** `GET .../tree` -> the tree shape every dashboard screen already renders. */
export function draftTreeToDashboardTree(tree: DraftTreeResponse): DashboardTree {
  const dashboard: EntityRecordResponse = {
    id: tree.dashboard.id,
    entity_id: '',
    data: tree.dashboard.data as Record<string, unknown>,
    row_version: tree.dashboard.row_version,
  };
  const widgets = tree.widgets.map(w => toEntityRecord(w as TreeRecordShape));
  return {
    dashboard,
    pages:    tree.pages.map(p => toEntityRecord(p as TreeRecordShape)),
    sections: tree.sections.map(s => toEntityRecord(s as TreeRecordShape)),
    widgetsBySection: groupWidgets(widgets),
  };
}

interface TreeRecordShape { id: string; row_version: number; data: Record<string, unknown> }
type SnapshotNode = Record<string, unknown>;

const without = (node: SnapshotNode, keys: string[]): SnapshotNode =>
  Object.fromEntries(Object.entries(node).filter(([k]) => !keys.includes(k)));

const asNodes = (value: unknown): SnapshotNode[] =>
  Array.isArray(value) ? value.filter((v): v is SnapshotNode => !!v && typeof v === 'object') : [];

/** A published snapshot (`layout.rs::pages_snapshot` — pages with nested
 * `sections[] {breakpoints, widgets, children}`) flattened into the draft
 * tree shape. Parent/owner ids the snapshot only encodes by nesting
 * (`page_id`, `parent_section_id`, `section_id`) are written back onto each
 * record so the viewer's existing per-page filtering keeps working. */
export function snapshotToDashboardTree(dashboardId: string, snapshot: unknown): DashboardTree {
  const root = (snapshot && typeof snapshot === 'object' ? snapshot : {}) as SnapshotNode;
  const fields = without(root, ['pages', 'dependencies', 'metric_dependencies', 'parameters', 'variables']);
  const pages: EntityRecord[] = [];
  const sections: EntityRecord[] = [];
  const widgets: EntityRecord[] = [];

  const walkSections = (nodes: SnapshotNode[], pageId: string, parentId: string | null): void => {
    for (const node of nodes) {
      const sectionId = String(node['id']);
      sections.push(toEntityRecord({
        id: sectionId, row_version: 0,
        data: { ...without(node, ['widgets', 'children', 'breakpoints']), page_id: pageId, parent_section_id: parentId },
      }));
      for (const w of asNodes(node['widgets'])) {
        widgets.push(toEntityRecord({ id: String(w['id']), row_version: 0, data: { ...w, section_id: sectionId } }));
      }
      walkSections(asNodes(node['children']), pageId, sectionId);
    }
  };

  for (const page of asNodes(root['pages'])) {
    const pageId = String(page['id']);
    pages.push(toEntityRecord({
      id: pageId, row_version: 0, data: { ...without(page, ['sections']), dashboard_id: dashboardId },
    }));
    walkSections(asNodes(page['sections']), pageId, null);
  }

  return {
    dashboard: { id: dashboardId, entity_id: '', data: fields, row_version: 0 },
    pages,
    sections,
    widgetsBySection: groupWidgets(widgets),
  };
}

const PARAMETER_TYPES = new Set(['date_range', 'choice', 'text', 'number', 'entity_lookup']);

/** `snapshot.parameters[]` -> the typed declarations the filter bar renders. */
export function snapshotParameters(snapshot: unknown): DashboardParameter[] {
  const rows = (snapshot && typeof snapshot === 'object')
    ? asNodes((snapshot as SnapshotNode)['parameters'])
    : [];
  const text = (value: unknown): string | null => typeof value === 'string' ? value : null;
  return rows
    .filter(row => typeof row['id'] === 'string' && typeof row['name'] === 'string')
    .map(row => ({
      id: String(row['id']),
      name: String(row['name']),
      name_ar: text(row['name_ar']),
      page_id: text(row['page_id']),
      parameter_type: (PARAMETER_TYPES.has(String(row['parameter_type']))
        ? row['parameter_type'] : 'text') as DashboardParameter['parameter_type'],
      default_value: text(row['default_value']),
    }));
}

@Injectable({ providedIn: 'root' })
export class DashboardService {
  private readonly api      = inject(ApiService);
  private readonly entities = inject(EntityService);

  /** The dashboard's whole draft tree in one call (`GET .../tree`, D-520):
   * the dashboard record, every page it owns through `dashboard_id`, every
   * section and widget under them, each with its `row_version`. Editor-only —
   * the route answers 404 to a caller without record Update. Never writes. */
  loadTree(dashboardId: string): Observable<DashboardTree> {
    return this.api.get<DraftTreeResponse>(`/api/v1/attome-dashboard/${dashboardId}/tree`).pipe(
      map(draftTreeToDashboardTree),
    );
  }

  /** What viewers see (`GET .../published`, D-521) — record Read only. */
  loadPublished(dashboardId: string): Observable<PublishedView> {
    return this.api.get<PublishedDashboard>(`/api/v1/attome-dashboard/${dashboardId}/published`).pipe(
      map((res): PublishedView => {
        const state = res.state as PublishedState;
        const hasSnapshot = state !== 'none' && res.snapshot != null;
        return {
          state,
          versionId: res.version_id ?? null,
          versionNumber: res.version_number ?? null,
          tree: hasSnapshot ? snapshotToDashboardTree(dashboardId, res.snapshot) : null,
          parameters: hasSnapshot ? snapshotParameters(res.snapshot) : [],
        };
      }),
    );
  }

  /** One page's section/widget tree, read through its owning dashboard's
   * tree route. No section is ever provisioned here: a page without one comes
   * back with `needsRootSection` for the editor to repair explicitly. */
  loadPageWidgets(pageId: string): Observable<PageWidgetTree> {
    return this.entities.get('dashboard_page', pageId).pipe(
      switchMap(page => {
        const dashboardId = page.data['dashboard_id'];
        if (typeof dashboardId !== 'string' || !dashboardId) {
          return of<PageWidgetTree>({ page, dashboardId: null, rootSectionId: null, needsRootSection: false, widgets: [] });
        }
        return this.loadTree(dashboardId).pipe(
          map((tree): PageWidgetTree => {
            const sections = tree.sections.filter(s => s.data['page_id'] === pageId);
            const root = sections.find(s => s.data['parent_section_id'] == null) ?? sections[0];
            const widgets = sections
              .flatMap(s => tree.widgetsBySection.get(s.id) ?? [])
              .sort((a, b) => sequenceOf(a) - sequenceOf(b));
            return { page, dashboardId, rootSectionId: root?.id ?? null, needsRootSection: !root, widgets };
          }),
        );
      }),
    );
  }

  /** `POST .../pages` — the page and its root grid section in one
   * transaction, owned by `dashboardId` (D-520/D-527). */
  createPage(dashboardId: string, body: NewPageBody): Observable<CreatedPage> {
    return this.api.post<CreatedPage>(`/api/v1/attome-dashboard/${dashboardId}/pages`, body);
  }

  /** `POST .../pages/{pageId}/root-section` — the explicit repair for a page
   * with no section; 409 when it already has one. */
  repairRootSection(dashboardId: string, pageId: string): Observable<RepairedRootSection> {
    return this.api.post<RepairedRootSection>(`/api/v1/attome-dashboard/${dashboardId}/pages/${pageId}/root-section`, {});
  }

  /**
   * One of the bespoke lifecycle transitions (`attome-dashboard::lifecycle`)
   * — always a `row_version`-guarded POST, never the generic entity PATCH
   * (the transition needs the per-dashboard advisory lock and an audit
   * write). `publish`'s response carries extra D-195 four-eyes fields
   * (`approval_pending`, `approval_request_id`, `version_id`,
   * `version_number`); a caller that needs them reads the response as
   * `PublishResponse` at the call site.
   *
   * **Not `If-Match`.** These bespoke routes take `row_version` in the JSON
   * body (`crates/engine/attome-dashboard/src/lifecycle.rs::TransitionBody`).
   */
  transition(
    id: string,
    action: DashboardLifecycleAction,
    rowVersion: number,
    body: Record<string, unknown> = {},
  ): Observable<TransitionResponse> {
    return this.api.post<TransitionResponse>(
      `/api/v1/attome-dashboard/${id}/${action}`,
      { row_version: rowVersion, ...body },
    );
  }

  /** `POST /api/v1/attome-dashboard/{id}/clone` — no request body; the clone is
   * owned by the caller once created (R-04). */
  clone(id: string): Observable<CloneResponse> {
    return this.api.post<CloneResponse>(`/api/v1/attome-dashboard/${id}/clone`, {});
  }

  /** `POST /api/v1/attome-dashboard/{id}/versions/{versionId}/restore` — writes
   * the version into the draft only (D-521); what viewers see is unchanged. */
  restoreVersion(id: string, versionId: string): Observable<RestoreResponse> {
    return this.api.post<RestoreResponse>(`/api/v1/attome-dashboard/${id}/versions/${versionId}/restore`, {});
  }

  /** `POST .../versions/{versionId}/activate` — makes a stored version live
   * (rollback). 202 with `approval_pending` when four-eyes gated. */
  activateVersion(id: string, versionId: string, rowVersion: number): Observable<ActivateResponse> {
    return this.api.post<ActivateResponse>(
      `/api/v1/attome-dashboard/${id}/versions/${versionId}/activate`,
      { row_version: rowVersion },
    );
  }

  /** `GET /api/v1/attome-dashboard/{id}/health-check` — read-only diagnostic
   * over the dashboard's widgets' `query_id` refs (`health.rs`). */
  healthCheck(id: string): Observable<HealthCheckResponse> {
    return this.api.get<HealthCheckResponse>(`/api/v1/attome-dashboard/${id}/health-check`);
  }

  /** `POST .../widgets/{widgetId}/data` (D-522, D-543) — one widget's data,
   * computed on the server from the published definition (or the draft when
   * `inputs.preview` is set, which needs record Update). The client sends
   * values only — parameter values, cross-filter values — never a query, a
   * view, a filter or an aggregation, so no number is ever computed here. */
  widgetData(dashboardId: string, widgetId: string, inputs: WidgetInputs = {}): Observable<WidgetDataResponse> {
    return this.api.post<WidgetDataResponse>(
      `/api/v1/attome-dashboard/${dashboardId}/widgets/${widgetId}/data`,
      inputs,
    );
  }

  /** `POST .../widgets/{widgetId}/records` (Phase 3.1) — the exact records
   * behind a value or bucket, from the same resolved context as the number,
   * with an exact total and a keyset cursor. 422 for a widget that is not
   * exactly drillable. */
  widgetRecords(dashboardId: string, widgetId: string, inputs: WidgetRecordsInputs): Observable<WidgetRecordsResponse> {
    return this.api.post<WidgetRecordsResponse>(
      `/api/v1/attome-dashboard/${dashboardId}/widgets/${widgetId}/records`,
      inputs,
    );
  }

  /** `POST .../widgets/{widgetId}/explain` (Phase 3.2) — how the number is
   * calculated: measures, filters with their origins, timezone, scope,
   * freshness; for a governed KPI its metric, target and lineage. */
  widgetExplain(dashboardId: string, widgetId: string, inputs: WidgetInputs = {}): Observable<WidgetExplanation> {
    return this.api.post<WidgetExplanation>(
      `/api/v1/attome-dashboard/${dashboardId}/widgets/${widgetId}/explain`,
      inputs,
    );
  }

  /** `POST .../pages/{pageId}/data` — every widget on one page in a single
   * request (at most four execute at once on the server); a widget that fails
   * carries its own `error` instead of failing the page. */
  pageData(dashboardId: string, pageId: string, inputs: WidgetInputs = {}): Observable<PageDataResponse> {
    return this.api.post<PageDataResponse>(
      `/api/v1/attome-dashboard/${dashboardId}/pages/${pageId}/data`,
      inputs,
    );
  }

  /** `POST /api/v1/attome-dashboard/widget/duplicate` — defaults to duplicating
   * in place (same section) when `targetSectionId` is omitted. */
  duplicateWidget(widgetId: string, targetSectionId?: string): Observable<DuplicateResponse> {
    return this.api.post<DuplicateResponse>('/api/v1/attome-dashboard/widget/duplicate', {
      widget_id: widgetId,
      target_section_id: targetSectionId,
    });
  }

  /** `GET /api/v1/attome-dashboard/widget-types` — the widget descriptors for a
   * builder palette. Only types the viewer can render, unless
   * `includeUnsupported` (D-525). */
  widgetTypes(includeUnsupported = false): Observable<WidgetDescriptor[]> {
    const query = includeUnsupported ? '?include_unsupported=true' : '';
    return this.api.get<WidgetDescriptor[]>(`/api/v1/attome-dashboard/widget-types${query}`);
  }

  /** `POST /api/v1/attome-dashboard/{id}/resolve-variables` — resolves
   * `@current_user`/`@current_date`/... plus declared `dashboard_variable`/
   * `dashboard_parameter` defaults, in `context.rs`'s documented
   * precedence (declared defaults -> built-ins -> URL overrides). Consumed by
   * `DashboardViewerComponent` (M26 R-15) to seed the filter bar's initial
   * values instead of reading `dashboard_parameter` defaults client-side. */
  resolveVariables(
    id: string,
    pageId?: string,
    urlOverrides: Record<string, string> = {},
  ): Observable<ResolveVariablesResponse> {
    return this.api.post<ResolveVariablesResponse>(`/api/v1/attome-dashboard/${id}/resolve-variables`, {
      page_id: pageId,
      url_overrides: urlOverrides,
    });
  }

  /** `POST /api/v1/attome-dashboard/widget/validate-config` — the sanctioned
   * pre-save check for a `declarative_widget`'s `config` blob
   * (`declarative_widget.rs`'s own doc comment: generic entity CRUD has no
   * per-field business-validation hook). Never rejects with a non-2xx for a
   * structurally invalid config — `valid: false` plus `errors` is the normal
   * response shape; only auth/transport failures throw. */
  validateWidgetConfig(config: unknown, widgetType?: string): Observable<ValidateConfigResponse> {
    return this.api.post<ValidateConfigResponse>(
      '/api/v1/attome-dashboard/widget/validate-config',
      widgetType ? { config, widget_type: widgetType } : { config },
    );
  }
}
