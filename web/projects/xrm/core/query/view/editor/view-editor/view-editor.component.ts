import { ChangeDetectionStrategy, Component, computed, inject, input, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Location, NgTemplateOutlet } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { AdminService, EntityMeta } from '@attome/xrm/core/admin/data';
import { switchMap } from 'rxjs';
import { QueryAdminService, QueryDetail, QueryMeta } from '@attome/xrm/core/query/data';
import { QueryColumnDef } from '@attome/xrm/core/query/data';
import { ViewAdminService, ViewBody, ViewDetail, ViewKind } from '@attome/xrm/core/query/data';
import {
  EDITABLE_VIEW_KINDS, EMPTY_VIEW_KIND_DRAFT, ViewKindDraft, buildViewMetadata, draftFromMetadata,
} from './view-kind-metadata';
import {
  CHART_AGGREGATIONS, CHART_DATE_BUCKETS, CHART_MAX_SERIES, CHART_SORTS, CHART_TYPES, ChartDraft, ChartSeriesDraft,
  emptySeries,
} from './chart-metadata';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

interface ColumnDraft extends QueryColumnDef { key: number; }
let nextKey = 0;

@Component({
  selector: 'xrm-view-editor', standalone: true, imports: [OwnerLayerBadgeComponent, FormsModule, NgTemplateOutlet, RouterLink, TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../../../../styles/xrm-form.css', '../../../query-page.css', './view-editor.component.css'],
  templateUrl: './view-editor.component.html',
})
export class ViewEditorComponent implements OnInit {
  private readonly api = inject(ViewAdminService); private readonly queryApi = inject(QueryAdminService);
  private readonly adminApi = inject(AdminService); private readonly router = inject(Router);
  private readonly location = inject(Location); private readonly lang = inject(LangService);
  readonly id = input.required<string>(); get isNew(): boolean { return !this.id() || this.id() === 'new'; }
  readonly entities = signal<EntityMeta[]>([]); readonly queries = signal<QueryMeta[]>([]); readonly columns = signal<ColumnDraft[]>([]);
  readonly loading = signal(true); readonly loadError = signal(''); readonly saveError = signal(''); readonly describeError = signal(''); readonly saving = signal(false); readonly describing = signal(false);
  // Signals rather than plain fields because `applyQuery()` writes them from an
  // HTTP response — see loadSelectedQuery(). Under OnPush the originating
  // (ngModelChange) event's check has long finished by the time that response
  // lands, so a plain field would leave the query name/SQL/privilege inputs
  // showing the previously selected query. `[(ngModel)]` two-way-binds a
  // WritableSignal directly (ɵɵtwoWayProperty unwraps it, ɵɵtwoWayBindingSet
  // calls .set()), so the templates below are unchanged apart from the call
  // parentheses on one-way reads.
  readonly name = signal(''); readonly icon = signal('las la-table'); readonly entityId = signal('');
  readonly queryId = signal(''); readonly isDefault = signal(false); readonly createNewQuery = signal(false);
  readonly queryName = signal(''); readonly sqlQuery = signal(''); readonly requiredPrivilege = signal(''); readonly isReport = signal(false);
  // U13 (D-429) — how the view renders, and the kind-specific settings
  // `view_admin.rs` validates. Saved on every create/update: the admin PATCH
  // defaults an omitted `kind` to `list`, so leaving it out would silently
  // turn a kanban/calendar/timeline view back into a list.
  readonly kind = signal<ViewKind>('list');
  /** Solution 7 (D-785): the loaded view's owner layer, for the read-only badge. */
  readonly ownerLayer = signal<string | null>(null);
  readonly kindDraft = signal<ViewKindDraft>({ ...EMPTY_VIEW_KIND_DRAFT });
  private storedMetadata: Record<string, unknown> = {};
  readonly kindOptions = EDITABLE_VIEW_KINDS;
  readonly columnNames = computed(() => this.columns().map(column => column.name));
  readonly chartTypes = CHART_TYPES; readonly chartAggregations = CHART_AGGREGATIONS;
  readonly chartDateBuckets = CHART_DATE_BUCKETS; readonly chartSorts = CHART_SORTS;
  readonly canAddSeries = computed(() => this.kindDraft().chart.series.length < CHART_MAX_SERIES);

  setKindDraft(key: Exclude<keyof ViewKindDraft, 'chart'>, value: string): void {
    this.kindDraft.update(draft => ({ ...draft, [key]: value }));
  }

  setChart<K extends keyof Omit<ChartDraft, 'series'>>(key: K, value: ChartDraft[K]): void {
    this.kindDraft.update(draft => ({ ...draft, chart: { ...draft.chart, [key]: value } }));
  }

  setSeries<K extends keyof ChartSeriesDraft>(index: number, key: K, value: ChartSeriesDraft[K]): void {
    this.kindDraft.update(draft => ({
      ...draft,
      chart: { ...draft.chart, series: draft.chart.series.map((s, i) => (i === index ? { ...s, [key]: value } : s)) },
    }));
  }

  addSeries(): void {
    if (!this.canAddSeries()) return;
    this.kindDraft.update(draft => ({ ...draft, chart: { ...draft.chart, series: [...draft.chart.series, emptySeries()] } }));
  }

  removeSeries(index: number): void {
    this.kindDraft.update(draft => ({
      ...draft, chart: { ...draft.chart, series: draft.chart.series.filter((_, i) => i !== index) },
    }));
  }

  ngOnInit(): void {
    this.adminApi.listEntities().subscribe(e => this.entities.set(e));
    this.queryApi.listQueries().subscribe(q => this.queries.set(q));
    if (this.isNew) { this.createNewQuery.set(true); this.loading.set(false); return; }
    this.api.get(this.id()).subscribe({
      next: view => { this.applyView(view); this.loadQuery(view.sql_query_ref, true); },
      error: (e: ApiError) => { this.loadError.set(e.message); this.loading.set(false); },
    });
  }

  private applyView(view: ViewDetail): void {
    this.ownerLayer.set(view.owner_layer);
    this.name.set(view.name); this.icon.set(view.icon || 'las la-table'); this.entityId.set(view.entity_logical_name); this.queryId.set(view.sql_query_ref);
    this.isDefault.set(view.is_default); this.createNewQuery.set(false);
    this.kind.set(view.kind ?? 'list'); this.storedMetadata = view.view_metadata ?? {};
    this.kindDraft.set(draftFromMetadata(this.kind(), view.view_metadata));
    this.columns.set(view.table_definition.map(column => ({ ...column, key: ++nextKey })));
  }
  private applyQuery(query: QueryDetail): void {
    this.queryId.set(query.id); this.queryName.set(query.name); this.sqlQuery.set(query.sql_query);
    this.requiredPrivilege.set(query.required_privilege ?? ''); this.isReport.set(query.is_report);
  }
  private loadQuery(id: string, initial = false): void {
    if (!id) { if (initial) this.loading.set(false); return; }
    this.queryApi.getQuery(id).subscribe({
      next: query => { this.applyQuery(query); if (initial) this.loading.set(false); },
      error: (e: ApiError) => { if (initial) this.loadError.set(e.message); else this.saveError.set(e.message); this.loading.set(false); },
    });
  }
  loadSelectedQuery(): void { if (!this.createNewQuery()) this.loadQuery(this.queryId()); }
  useExistingQuery(): void { this.createNewQuery.set(false); this.queryId.set(''); this.queryName.set(''); this.sqlQuery.set(''); this.requiredPrivilege.set(''); this.isReport.set(false); }
  useNewQuery(): void { this.createNewQuery.set(true); this.queryId.set(''); this.queryName.set(''); this.sqlQuery.set(''); this.requiredPrivilege.set(''); this.isReport.set(false); }
  cancel(): void { this.location.back(); }

  updateColumns(): void {
    if (!this.sqlQuery().trim()) { this.describeError.set('SQL statement is required.'); return; }
    this.describeError.set(''); this.describing.set(true);
    this.queryApi.describeQuery(this.sqlQuery().trim()).subscribe({
      next: described => {
        const old = new Map(this.columns().map(column => [column.name, column]));
        this.columns.set(described.map(column => old.get(column.name) ?? {
          key: ++nextKey, name: column.name,
          display_name: column.name.replace(/_/g, ' ').replace(/\b\w/g, value => value.toUpperCase()),
          data_type: column.data_type, is_visible: true, is_sortable: false, is_searchable: false,
          is_clickable: false, route_template: '',
        }));
        this.describing.set(false);
      },
      error: (e: ApiError) => { this.describeError.set(e.message); this.describing.set(false); },
    });
  }

  save(): void {
    if (!this.name().trim() || !this.entityId() || !this.queryName().trim() || !this.sqlQuery().trim()) {
      this.saveError.set('View name, entity, query name and SQL statement are required.'); return;
    }
    const metadata = buildViewMetadata(this.kind(), this.kindDraft(), this.storedMetadata);
    if (!metadata.ok) { this.saveError.set(this.lang.translate(metadata.errorKey)); return; }
    this.saveError.set(''); this.saving.set(true);
    const queryBody = {
      name: this.queryName().trim(), sql_query: this.sqlQuery().trim(),
      required_privilege: this.requiredPrivilege().trim() || undefined, is_report: this.isReport(),
    };
    const queryRequest = this.createNewQuery()
      ? this.queryApi.createQuery(queryBody)
      : this.queryApi.updateQuery(this.queryId(), queryBody);
    queryRequest.pipe(switchMap(query => {
      this.applyQuery(query); this.createNewQuery.set(false);
      const table_definition = this.columns().map(({ key, ...column }) => column);
      const body: ViewBody = {
        name: this.name().trim(), icon: this.icon().trim() || 'las la-table', entity_logical_name: this.entityId(), sql_query_ref: query.id,
        table_definition, is_default: this.isDefault(),
        kind: this.kind(), view_metadata: metadata.metadata,
      };
      return this.isNew ? this.api.create(body) : this.api.update(this.id(), body);
    })).subscribe({
      next: view => { this.saving.set(false); this.applyView(view); if (this.isNew) void this.router.navigate(['/xrm/admin/views', view.id]); },
      error: (e: ApiError) => { this.saveError.set(e.message); this.saving.set(false); },
    });
  }
}
