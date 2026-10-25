import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input,
  OnDestroy, output, signal, untracked, viewChild,
} from '@angular/core';
import type { Type } from '@angular/core';
import { NgComponentOutlet } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { firstValueFrom } from 'rxjs';
import type { Observable, Subscription } from 'rxjs';
import { ApiError, CurrencyService, LangService, LiveChannel, TranslatePipe } from '@attome/base';
import type { LiveRecords } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityRecord, FieldType, ListFilter, LookupMeta } from '@attome/xrm';
import { EntityService, type DeleteImpact } from '../services/entity.service';
import { logicalToUrlPath } from '../services/entity-url.utils';
import { EntityRouteRegistry } from '../entity-route-registry.service';
import type { SelectionAction } from '../entity-route-registry.service';
import {
  AvailableView, CreatePersonalViewBody, QueryColumnDef, QueryService, ViewAdminService, ViewKind,
} from '@attome/xrm/core/query/data';
import { ListBase } from '@attome/xrm/core/generic/base';
import { ChoicePillComponent, ChoicePillStyle } from '@attome/xrm/core/generic/components';
import {
  ColumnFilterDraft, DateOperator, FilterKind, NumberOperator, QueryFilter, TEXT_OPERATORS, TextOperator,
  NUMBER_OPERATORS, DATE_OPERATORS, columnFilterToQueryFilters, deserializeColumnFilters, draftOperator, splitExportFilters,
  draftValue, draftValueTo, fieldTypeToFilterKind, isColumnFilterDraftActive, isValuelessOperator,
  serializeColumnFilters,
} from './column-filters';
import { BulkTagComponent } from '../record-tags/bulk-tag.component';

import { BulkJobRunner, isBulkTerminal } from './bulk-job-runner.service';
import { liveRows } from './live-rows';
// Deferred: the dialog's chunk loads the first time bulk edit is opened
// (`@defer` in the template), which keeps it out of the shared entity chunk
// every bespoke form loads (scripts/chunk-budget.mjs). Referenced only by the
// `imports` array, the `@defer` block and a type position, so it stays deferrable.
import { BulkEditDialogComponent } from './bulk-edit-dialog.component';
// Deferred the same way (U12 Phase A, D-607): the advanced-find builder loads
// the first time it is opened.
import { AdvancedFindPanelComponent } from './advanced-find-panel.component';
import { viewFilters } from './advanced-find';
// U7 Phase A — admin-only Assign on the selection; renders nothing for a
// non-admin, and its dialog is itself deferred.
import { RecordAccessActionsComponent } from '../record-access/record-access-actions.component';
import { ImageThumbComponent } from '../field/image-thumb/image-thumb.component';
import { ListCardsComponent, SwipeAction, mobileOptions } from './list-cards.component';
import { EmptyStateComponent, type EmptyReason } from './empty-state.component';
import { RecordTemplatePickerComponent } from '../record-template/record-template-picker.component';
import { RecordTypePickerComponent } from '../record-type-picker/record-type-picker.component';

/** A lowercase or uppercase hyphenated UUID. */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A18-T9: how long "Deleted. Undo" stays offered. */
export const UNDO_SECONDS = 8;

/** A fresh id for one delete operation. */
function newOperationId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `op-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

// `Col`/filter re-exports live in `column-filters.ts` now (C-28) — nothing
// outside this file's own template needs the filter grammar through the
// component barrel, so it is imported here, not re-exported. Bulk-edit's own
// pure helpers and dialog state now live in `bulk-edit-dialog.component.ts`.

/** B17-T6: phones, below 600 px. `null` where there is no window (tests, SSR). */
function phoneQuery(): MediaQueryList | null {
  return typeof globalThis.matchMedia === 'function' ? globalThis.matchMedia('(max-width: 599.98px)') : null;
}

// ── Column descriptor ─────────────────────────────────────────────────────────

export interface Col {
  name:         string;
  display_name: string;
  type:         string;
  sortable:     boolean;
  is_clickable: boolean;
  route_template: string;
  /** Logical name of the entity a `type: 'lookup'` column points to — makes
   * the cell clickable by default (routes to that record's form) unless the
   * view's own `is_clickable`/`route_template` already claims the column. */
  lookup_target_entity?: string | null;
  options?:     { label: string; value: string }[];
  /** Per-value color/icon presentation hints for a `type: 'choice'` column —
   * absent for every other column, or a choice column with no configured
   * styles. Drives `xrm-choice-pill`'s decorated rendering in the template. */
  choice_styles?: Record<string, ChoicePillStyle> | null;
}

/** Expands an internal route template from a query result row. */
export function resolveRouteTemplate(
  template: string,
  row: Record<string, unknown>,
): string | null {
  if (!template.startsWith('/')) return null;

  let missing = false;
  const route = template.replace(/\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/g, (_match, name: string) => {
    const value = row[name];
    if (value === null || value === undefined) {
      missing = true;
      return '';
    }
    return encodeURIComponent(String(value));
  });
  if (missing || /\{\{[^}]+\}\}/.test(route)) return null;

  // Backward compatibility for definitions created with the old `{id}` hint.
  const legacyId = row['id'];
  if (route.includes('{id}')) {
    if (legacyId === null || legacyId === undefined) return null;
    return route.replaceAll('{id}', encodeURIComponent(String(legacyId)));
  }
  return route;
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/**
 * ISO-8601 date (`2026-08-07`) or timestamp (`2026-08-07T17:34:59.339617+00:00`)
 * — the shape PostgreSQL values reach the grid in through `query/execute`.
 */
const ISO_DATE_RE =
  /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

/**
 * Renders a cell timestamp as `dd-mm-yyyy hh:mm`, or `dd-mm-yyyy` for a
 * date-only value. Returns `null` for anything that is not an ISO-8601 date/timestamp,
 * so the caller can fall through to its plain-string handling.
 *
 * Keyed off the value's shape rather than the column's declared type on
 * purpose: a seeded default query carries no admin-authored
 * `table_definition`, and `query_exec.rs::infer_columns` then reports *every*
 * column as `text` — which is why `created_at`/`updated_at` were reaching the
 * grid as raw `2026-08-07T17:34:59.339617+00:00`.
 */
export function formatDateCell(raw: string): string | null {
  const parts = ISO_DATE_RE.exec(raw);
  if (!parts) return null;

  const [, year, month, day, hours, minutes] = parts;
  // A date-only value carries no zone. Formatting it through `Date` would
  // parse it as UTC midnight and shift it a day backwards for any viewer
  // west of UTC, so take the literal components instead.
  if (hours === undefined) return `${day}-${month}-${year}`;

  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return `${day}-${month}-${year} ${hours}:${minutes}`;
  const local = (n: number) => String(n).padStart(2, '0');
  return `${local(date.getDate())}-${local(date.getMonth() + 1)}-${date.getFullYear()} `
    + `${local(date.getHours())}:${local(date.getMinutes())}`;
}

// ── Component ─────────────────────────────────────────────────────────────────

/**
 * U9 (D-605) — the visible text of a stored rich-text value, for a grid
 * cell. `DOMParser` builds an inert document: nothing in it runs or loads
 * (no script, no image fetch), and only `textContent` is read back.
 */
export function richTextToPlainText(html: string): string {
  if (!html) return '';
  // A space before every tag keeps adjacent blocks' words apart ('<p>a</p><p>b</p>'
  // reads 'a b', not 'ab'); the whitespace collapse below removes the surplus.
  const doc = new DOMParser().parseFromString(html.replace(/</g, ' <'), 'text/html');
  return (doc.body.textContent ?? '').replace(/\s+/g, ' ').trim();
}

@Component({
  selector:    'attome-metadata-list',
  standalone:  true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:     [
    FormsModule, NgComponentOutlet, RouterLink, TranslatePipe, ChoicePillComponent, BulkEditDialogComponent,
    AdvancedFindPanelComponent, RecordAccessActionsComponent, ImageThumbComponent, BulkTagComponent,
    ListCardsComponent, RecordTypePickerComponent, RecordTemplatePickerComponent, EmptyStateComponent,
  ],
  host: { '(document:click)': 'handleDocumentClick($event)' },
  templateUrl: './entity-list.component.html',
  styleUrl:    './entity-list.component.css',
})
export class EntityListComponent extends ListBase<EntityRecord> implements OnDestroy {
  // ── Inputs / outputs ───────────────────────────────────────────────────────
  readonly entityName = input.required<string>();
  /** `loading()` held back 300 ms: a fast load goes straight from nothing to
   * the rows instead of flashing a "Loading…" row (or overlay) first. */
  readonly showLoading = signal(false);
  readonly pageSize   = input(50);
  readonly compact    = input(false);
  /** Filters imposed by an embedding component (for example a parent-record
   * relationship). They are always sent to the server and are not exposed in
   * the removable column-filter UI. */
  readonly fixedFilters = input<readonly ListFilter[]>([]);
  /** Optional view selected by an embedding component instead of the URL. */
  readonly initialViewId = input<string | null>(null);
  /** Embedded grids must not read or rewrite their parent form's query string. */
  readonly syncUrl = input(true);
  /** Embedded/special-purpose grids can lock their configured view. */
  readonly showViewSelection = input(true);
  /** U13 — restricts the view picker to these kinds (`null` = every view).
   * The entity list page passes the list-rendered kinds and offers the others
   * (kanban/calendar/timeline) through its own view-kind switcher. */
  readonly viewKindFilter = input<readonly ViewKind[] | null>(null);
  /** Creating records is opt-in so relationship grids do not offer the wrong action. */
  readonly allowCreate = input(false);
  readonly showRelationshipActions = input(false);

  /** A27-T4: the record type chosen on the New button (`null`: none). */
  readonly newClick  = output<string | null>();
  readonly editClick = output<EntityRecord>();
  readonly addRelationshipClick = output<void>();
  readonly removeRelationshipClick = output<readonly string[]>();

  // ── Services ───────────────────────────────────────────────────────────────
  private readonly entitySvc = inject(EntityService);
  private readonly querySvc  = inject(QueryService);
  private readonly viewSvc   = inject(ViewAdminService);
  private readonly router    = inject(Router);
  private readonly lang      = inject(LangService);
  private readonly routeReg  = inject(EntityRouteRegistry);
  private readonly dialogSvc = inject(DialogService);
  private readonly bulkJobs  = inject(BulkJobRunner);
  private readonly currency  = inject(CurrencyService);

  // D-490 — a signal over the viewer's preferred display currency, read by
  // `currencyCellDisplay`/`currencyIcon` below; reading it from a template
  // method re-renders on a preference change the same way a direct binding
  // would (Angular's OnPush + signals integration).
  private readonly preferredCurrency = this.currency.preferredCurrency;

  // ── State ──────────────────────────────────────────────────────────────────
  readonly columns_ = signal<Col[]>([]);
  readonly total    = signal(0);
  /** A13-T2: the total is an estimate. */
  readonly totalEstimated = signal(false);
  readonly viewId  = signal<string | null>(null);
  readonly availableViews = signal<AvailableView[]>([]);
  readonly viewMenuOpen = signal(false);
  readonly canEditView = signal(false);
  /** D-429 — the query that actually produced the current page, straight off
   * `query/execute`'s own response metadata (not derived from `viewId()`,
   * which can be `null` for an unsaved/default resolution). "Save as my
   * view" reuses this id rather than authoring a new query — a self-service
   * caller can never create `sql_query` rows. */
  readonly currentQueryId = signal<string | null>(null);
  /** The untransformed column list from the last `query/execute` response —
   * `columns_`/`Col[]` below is this component's own render shape; personal
   * views are saved with the wire shape (`QueryColumnDef[]`) instead, same
   * as the admin view editor sends. */
  private rawColumns: QueryColumnDef[] = [];
  /** Every column name the current query returns, hidden ones included —
   * the advanced-find picker's whitelist (D-607). */
  readonly queryColumnNames = signal<string[]>([]);
  readonly savingPersonalView = signal(false);

  readonly currentPage   = signal(1);
  readonly sortColumn    = signal('');
  readonly sortDirection = signal<'asc' | 'desc'>('asc');
  readonly searchDraft   = signal('');
  private searchTerm     = '';
  private searchTimer: ReturnType<typeof setTimeout> | null = null;
  private loadSub: Subscription | null = null;

  readonly filterDrafts     = signal<Record<string, ColumnFilterDraft>>({});
  readonly activeFilters    = signal<Record<string, ColumnFilterDraft>>({});
  readonly openColumnFilter = signal<string | null>(null);
  readonly selectedRecordIds = signal<Set<string>>(new Set());
  /** B4-T4: `?tag=<id>` from the tag page: only records carrying that tag. */
  readonly tagFilter = signal<string | null>(null);
  private readonly live = inject(LiveChannel);
  /** A13-T4: records created since the list loaded, shown as a banner. */
  readonly newRows = signal(0);
  /** A13-T4: more changed than the live channel lists; reload to see them. */
  readonly liveOverflow = signal(false);

  /** A18-T9: the delete that can still be undone, for {@link UNDO_SECONDS}. */
  readonly undoOffer = signal<{ operationId: string; count: number } | null>(null);
  private undoTimer: ReturnType<typeof setTimeout> | null = null;

  /** U12 Phase A (D-607) — the advanced-find conditions in force, as wire
   * filters: set by the builder's Apply, or by opening a view that saved
   * some in `view_metadata.filters`. ANDed with the column filters. */
  readonly advancedFilters      = signal<QueryFilter[]>([]);
  readonly advancedFindOpen     = signal(false);
  /** Set by the first "Advanced find" click; renders the deferred builder. */
  readonly advancedFindRequested = signal(false);

  // ── Computed ───────────────────────────────────────────────────────────────

  readonly columns = computed<Col[]>(() => this.columns_());

  /** B17-T6: a phone-sized screen shows the list as cards. */
  readonly isPhone = signal(phoneQuery()?.matches ?? false);
  private readonly phoneListener = (e: MediaQueryListEvent) => this.isPhone.set(e.matches);
  /** B17-T6: the open view's phone settings (`view_metadata.mobile`). */
  readonly mobile = computed(() => mobileOptions(this.activeView()?.view_metadata));
  readonly cardColumns = computed(() => this.columns().map(c => c.name));
  readonly rtl = computed(() => this.lang.isRtl());
  readonly activeView = computed(() => this.availableViews().find(view => view.id === this.viewId()));
  readonly pickerViews = computed(() => {
    const kinds = this.viewKindFilter();
    const views = this.availableViews();
    return kinds ? views.filter(view => kinds.includes(view.kind)) : views;
  });

  readonly totalPages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize())));

  readonly rangeStart = computed(() =>
    this.total() === 0 ? 0 : (this.currentPage() - 1) * this.pageSize() + 1
  );

  readonly rangeEnd = computed(() =>
    Math.min(this.currentPage() * this.pageSize(), this.total())
  );

  readonly showSelectionMode = computed(() => this.selectedRecordIds().size > 0);

  // ── Entity-specific selection actions ──────────────────────────────────────

  private readonly routeOverride = computed(() => this.routeReg.get(this.entityName()));

  readonly showDeleteAction = computed(() => !this.routeOverride()?.hideDeleteAction);

  /** The entity's registered per-column cell renderers (`EntityRouteOverride.cellRenderers`). */
  private readonly cellRenderers = computed(() => this.routeOverride()?.cellRenderers ?? null);

  /** The registered renderer for `col`, or `null` for the stock cell. */
  cellRenderer(col: Col): Type<unknown> | null {
    return this.cellRenderers()?.[col.name] ?? null;
  }

  /** Latches for the duration of a bulk action so it cannot be double-fired.
   * `BulkEditDialogComponent` (C-28) drives this too, through its
   * `busyChange` output, for the duration of its own apply. */
  readonly bulkActionRunning = signal(false);
  /** Set by the first "Bulk edit" click; renders the deferred dialog. */
  readonly bulkEditRequested = signal(false);
  private readonly bulkEditDialog = viewChild<BulkEditDialogComponent>('bulkEditDialog');
  private bulkEditOpenPending = false;

  /** Live view of the current selection for `<xrm-bulk-edit-dialog>`'s
   * `recordIds` input — a `computed` (not a template array literal) so it
   * only produces a new array when the selection actually changes. */
  readonly selectedRecordIdList = computed(() => [...this.selectedRecordIds()]);

  /**
   * Raw data of the selected records, or `null` when the selection cannot be
   * fully resolved from the current page.
   *
   * Selection survives paging (`selectAllOnPage` unions into the existing
   * set), so a selection spanning pages holds ids whose rows are no longer
   * loaded. An action that decides visibility from row state would then be
   * judging the selection from the visible slice alone — `null` makes every
   * such action fall back to "shown but disabled", the same posture as a
   * mixed selection.
   */
  private readonly selectedRows = computed<Record<string, unknown>[] | null>(() => {
    const ids  = this.selectedRecordIds();
    const rows = this.records().filter(r => ids.has(r.id)).map(r => r.data);
    return rows.length === ids.size ? rows : null;
  });

  readonly selectionActions = computed<SelectionAction[]>(() => {
    const actions = this.routeOverride()?.selectionActions ?? [];
    const rows    = this.selectedRows();
    // Unresolvable selection: show every action, all disabled by
    // `isSelectionActionEnabled` below, rather than hiding the toolbar.
    if (rows === null) return actions;
    return actions.filter(a => a.isVisible?.(rows) ?? true);
  });

  isSelectionActionEnabled(action: SelectionAction): boolean {
    if (this.bulkActionRunning()) return false;
    const rows = this.selectedRows();
    if (rows === null) return false;
    return action.isEnabled?.(rows) ?? true;
  }

  readonly activeFilterCount = computed(() =>
    Object.values(this.activeFilters()).filter(d => this.isFilterDraftActive(d)).length
      + this.advancedFilters().length
  );

  /** AK4-T1: an empty list is either filtered to nothing or has no records. */
  readonly emptyReason = computed<EmptyReason>(() =>
    this.activeFilterCount() > 0 || this.tagFilter() !== null || this.searchDraft().trim() !== ''
      ? 'filtered' : 'none');

  readonly activeFilterSummary = computed(() =>
    this.lang.translate('entityList.filterCount', { count: this.activeFilterCount() })
  );

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  constructor() {
    super();
    phoneQuery()?.addEventListener('change', this.phoneListener);
    effect(onCleanup => {
      if (!this.loading()) { this.showLoading.set(false); return; }
      const timer = setTimeout(() => this.showLoading.set(true), 300);
      onCleanup(() => clearTimeout(timer));
    });
    // A13-T4: this entity's record changes while the list is open: rows on
    // the page reload in place, new records wait behind a banner.
    effect(onCleanup => {
      const entity = this.entityName();
      untracked(() => {
        this.newRows.set(0);
        this.liveOverflow.set(false);
        const unwatch = this.live.watch(entity);
        const sub = this.live.records.subscribe(frame => this.onLiveRecords(entity, frame));
        onCleanup(() => { unwatch(); sub.unsubscribe(); });
      });
    });
    // Opens the dialog once its deferred chunk has rendered it.
    effect(() => {
      const dialog = this.bulkEditDialog();
      if (dialog && this.bulkEditOpenPending) {
        this.bulkEditOpenPending = false;
        untracked(() => dialog.openDialog());
      }
    });
    effect(() => {
      this.entityName();
      this.fixedFilters();
      this.initialViewId();
      untracked(() => {
        this.columns_.set([]);
        this.records.set([]);
        this.total.set(0);
        this.viewId.set(null);
        this.availableViews.set([]);
        this.canEditView.set(false);
        this.currentQueryId.set(null);
        this.rawColumns = [];
        this.currentPage.set(1);
        this.sortColumn.set('');
        this.sortDirection.set('asc');
        // This component is created through NgComponentOutlet, so its injected
        // ActivatedRoute is not reliably the route that owns the visible list
        // URL. Read the router's actual URL instead.
        const currentUrl = this.router.parseUrl(this.router.url);
        const urlFilters = this.syncUrl()
          ? deserializeColumnFilters(currentUrl.queryParamMap.get('filters'))
          : {};
        this.filterDrafts.set(urlFilters);
        this.activeFilters.set(urlFilters);
        const tag = this.syncUrl() ? currentUrl.queryParamMap.get('tag') : null;
        this.tagFilter.set(tag && UUID_PATTERN.test(tag) ? tag : null);
        this.advancedFilters.set([]);
        this.advancedFindOpen.set(false);
        this.searchDraft.set('');
        this.searchTerm = '';
        if (this.searchTimer) { clearTimeout(this.searchTimer); this.searchTimer = null; }
        this.selectedRecordIds.set(new Set());
        this.loadAvailableViews();
      });
    });
  }

  // ── Click-outside handler ──────────────────────────────────────────────────

  handleDocumentClick(event: Event): void {
    const target = event.target;
    if (!(target instanceof Element)) { this.closeColumnFilter(); return; }
    if (target.closest('[data-view-picker]')) return;
    this.viewMenuOpen.set(false);
    if (target.closest('[data-filter-shell]')) return;
    this.closeColumnFilter();
  }

  // ── Data loading ───────────────────────────────────────────────────────────

  refresh(): void { this.load(); }

  onViewChange(viewId: string): void {
    this.viewId.set(viewId);
    this.applyViewFilters(viewId);
    this.currentPage.set(1);
    if (this.syncUrl()) this.writeViewToUrl(viewId);
    this.load();
  }

  toggleViewMenu(event: Event): void {
    event.stopPropagation();
    this.viewMenuOpen.update(open => !open);
  }

  selectView(viewId: string): void {
    this.viewMenuOpen.set(false);
    if (viewId !== this.viewId()) this.onViewChange(viewId);
  }

  // ── Personal views (D-429) ────────────────────────────────────────────────

  /** "Save as my view": names, then persists, the CURRENT list's column set
   * (and kind — always `list` from this toolbar; kanban/calendar/timeline
   * views are authored through admin studio) as a personal view bound to
   * the same query this list is already running. Never authors a new query
   * — a self-service caller cannot; `ViewAdminService.createMine` re-checks
   * server-side that the caller may execute `currentQueryId()` regardless. */
  async saveAsMyView(): Promise<void> {
    const queryId = this.currentQueryId();
    if (!queryId || this.savingPersonalView()) return;
    const name = await this.dialogSvc.prompt({
      title: this.lang.translate('entityList.saveAsMyView'),
      placeholder: this.lang.translate('entityList.myViewNamePlaceholder'),
      confirmText: this.lang.translate('entityList.save'),
    });
    if (!name?.trim()) return;

    this.savingPersonalView.set(true);
    const filters = this.advancedFilters();
    const body: CreatePersonalViewBody = {
      name: name.trim(),
      icon: this.activeView()?.icon || 'las la-table',
      entity: this.entityName(),
      sql_query_ref: queryId,
      table_definition: this.rawColumns,
      kind: 'list',
      // U12 Phase A (D-607): the advanced-find conditions travel with the
      // view as metadata; the server validates them here and `query/execute`
      // re-checks them for whoever opens the view.
      ...(filters.length ? { view_metadata: { filters } } : {}),
    };
    this.viewSvc.createMine(body).subscribe({
      next: created => {
        this.savingPersonalView.set(false);
        this.availableViews.update(views => [...views, {
          id: created.id, name: created.name, icon: created.icon, is_default: false,
          kind: created.kind, view_metadata: created.view_metadata,
          scope: created.scope, is_mine: true,
        }]);
        this.selectView(created.id);
      },
      error: (err: ApiError) => {
        this.savingPersonalView.set(false);
        this.dialogSvc.error({ title: this.lang.translate('entityList.saveAsMyView'), message: err.message });
      },
    });
  }

  /** Promotes the active personal view to `shared` — visible to any other
   * caller who holds the underlying query's privilege, same gate a system
   * view uses. Owner-only server-side; this button only ever renders for the
   * owner's own row (`activeView()?.is_mine`). */
  async sharePersonalView(): Promise<void> {
    const view = this.activeView();
    if (!view || view.scope !== 'personal' || !view.is_mine) return;
    const confirmed = await this.dialogSvc.confirm({
      message: this.lang.translate('entityList.shareViewConfirm', { name: view.name }),
      variant: 'primary',
      confirmText: this.lang.translate('entityList.share'),
    });
    if (!confirmed) return;
    this.viewSvc.share(view.id).subscribe({
      next: () => this.loadAvailableViews(),
      error: (err: ApiError) =>
        this.dialogSvc.error({ title: this.lang.translate('entityList.share'), message: err.message }),
    });
  }

  /** Deletes the active personal view (owner-only, only ever offered for a
   * `personal` row the caller owns) and falls back to the entity's default
   * view. */
  async deletePersonalView(): Promise<void> {
    const view = this.activeView();
    if (!view || view.scope !== 'personal' || !view.is_mine) return;
    const confirmed = await this.dialogSvc.confirm({
      message: this.lang.translate('entityList.deleteViewConfirm', { name: view.name }),
      variant: 'danger',
      confirmText: this.lang.translate('entityList.deleteSelected'),
    });
    if (!confirmed) return;
    this.viewSvc.deleteMine(view.id).subscribe({
      next: () => {
        this.viewId.set(null);
        this.loadAvailableViews();
      },
      error: (err: ApiError) =>
        this.dialogSvc.error({ title: this.lang.translate('entityList.deleteSelected'), message: err.message }),
    });
  }

  private loadAvailableViews(): void {
    this.loading.set(true);
    this.error.set(null);
    const requestedViewId = this.initialViewId()
      ?? (this.syncUrl() ? this.router.parseUrl(this.router.url).queryParamMap.get('view') : null);
    this.viewSvc.listAvailable(this.entityName()).subscribe({
      next: views => {
        this.availableViews.set(views);
        const requested = requestedViewId ? views.find(view => view.id === requestedViewId) : undefined;
        const selected = requested ?? views.find(view => view.is_default) ?? views[0];
        this.viewId.set(selected?.id ?? null);
        if (selected) this.applyViewFilters(selected.id);
        if (selected) this.load();
        else {
          this.loading.set(false);
          this.error.set(this.lang.translate('entityList.noAccessibleViews'));
        }
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }

  /** A13-T4: applies one live frame for `entity`. */
  onLiveRecords(entity: string, frame: LiveRecords): void {
    const outcome = liveRows(entity, frame, new Set(this.records().map(r => r.id)));
    if (outcome.overflow) this.liveOverflow.set(true);
    if (outcome.created) this.newRows.update(n => n + outcome.created);
    if (outcome.reload) this.load();
  }

  /** A13-T4: loads the list again, taking in the new records. */
  showNewRows(): void {
    this.newRows.set(0);
    this.liveOverflow.set(false);
    this.load();
  }

  private load(): void {
    // A slower earlier request (previous sort/page/filter/search) arriving
    // after a faster later one would otherwise overwrite fresher results —
    // cancel it instead of letting both races land.
    this.loadSub?.unsubscribe();
    this.loading.set(true);
    this.error.set(null);

    this.loadSub = this.querySvc.execute({
      view_id:       this.viewId() ?? undefined,
      page:          this.currentPage(),
      page_size:     this.pageSize(),
      search:        this.searchTerm.trim(),
      order_by:      this.sortColumn(),
      order_dir:     this.sortDirection(),
      filters:       this.buildColumnFilters(),
      // This component's pagination (currentPage/totalPages/rangeStart/
      // rangeEnd) is page-number-style, not cursor/keyset — it needs the
      // server's exact count (D-126 defaults to cursor mode, `total: null`,
      // when this isn't set).
      include_total: true,
    }).subscribe({
      next: res => {
        this.viewId.set(res.metadata.view_id);
        this.canEditView.set(res.metadata.can_edit_query && res.metadata.view_id !== null);
        this.currentQueryId.set(res.metadata.query_id);
        this.rawColumns = res.data.columns;
        this.queryColumnNames.set(res.data.columns.map(c => c.name));
        const linkedEntityPath = res.metadata.entity_logical_name
          ? logicalToUrlPath(res.metadata.entity_logical_name)
          : null;
        this.columns_.set(
          res.data.columns
            .filter(c => c.is_visible)
            .map((c, index) => {
              const lookupPath = c.lookup_target_entity
                ? logicalToUrlPath(c.lookup_target_entity)
                : null;
              const isFirstColLink = index === 0 && linkedEntityPath !== null;
              return {
                name:         c.name,
                display_name: c.display_name,
                type:         c.data_type,
                sortable:     c.is_sortable,
                lookup_target_entity: c.lookup_target_entity,
                choice_styles: c.choice_styles,
                // An explicit query-column route wins. Otherwise a lookup
                // column defaults to opening its target record's form, and
                // failing that the first visible column defaults to opening
                // the row's own linked-entity form.
                is_clickable: c.is_clickable || lookupPath !== null || isFirstColLink,
                route_template: c.route_template
                  || (lookupPath ? `/${lookupPath}/form?id={{${c.name}}}` : '')
                  || (isFirstColLink ? `/${linkedEntityPath}/form?id={{id}}` : ''),
              };
            }),
        );
        this.records.set(
          res.data.records.map(r => {
            // `__lookups` is a synthetic sidecar the query engine merges
            // into each row (D-077-style, batched per page) — split it back
            // out so it doesn't leak into `data` alongside real columns.
            const { __lookups, ...rest } = r as Record<string, unknown> & {
              __lookups?: Record<string, LookupMeta>;
            };
            return {
              id:          String(r['id'] ?? ''),
              entity_id:   '',
              data:        rest,
              lookups:     __lookups,
              created_at:  String(r['created_at'] ?? ''),
              updated_at:  String(r['created_at'] ?? ''),
              row_version: 1,
            };
          }),
        );
        // include_total: true above means this is non-null on any
        // conforming server response; the fallback only guards a
        // contract-violating response, not real cursor-mode behavior.
        this.total.set(res.data.total ?? 0);
        this.totalEstimated.set(res.data.total_estimated === true);
        this.loading.set(false);
      },
      error: (err: ApiError) => {
        this.error.set(err.message);
        this.loading.set(false);
      },
    });
  }

  /** B5-T4: the view's filters, for a bulk edit of every matching record. */
  readonly bulkEditFilters = computed(() => this.buildColumnFilters());

  private buildColumnFilters(): QueryFilter[] {
    const filters: QueryFilter[] = [...this.fixedFilters()];
    for (const [colName, draft] of Object.entries(this.activeFilters())) {
      if (!this.isFilterDraftActive(draft)) continue;
      const col  = this.columns().find(c => c.name === colName);
      const kind = col ? fieldTypeToFilterKind(col.type as FieldType) : 'text';
      filters.push(...columnFilterToQueryFilters(colName, draft, kind));
    }
    filters.push(...this.advancedFilters());
    const tag = this.tagFilter();
    if (tag) filters.push({ field: 'id', op: 'tagged', value: tag });
    return filters;
  }

  /** AK4-T1: the empty state's "clear filters", which also drops a tag filter. */
  clearEmptyFilters(): void {
    this.tagFilter.set(null);
    this.clearAllFilters();
  }

  /** B4-T4: drops the tag filter the tag page set. */
  clearTagFilter(): void {
    this.tagFilter.set(null);
    this.currentPage.set(1);
    this.load();
  }

  /** B4-T4: after a bulk tag, the selection stays so it can be tagged again. */
  onBulkTagged(): void {
    this.load();
  }

  // ── Advanced find (U12 Phase A, D-607) ─────────────────────────────────────

  toggleAdvancedFind(): void {
    this.advancedFindRequested.set(true);
    this.advancedFindOpen.update(open => !open);
  }

  /** The builder's Apply (and its Clear, with `[]`). */
  applyAdvancedFilters(filters: QueryFilter[]): void {
    this.advancedFilters.set(filters);
    this.currentPage.set(1);
    this.load();
  }

  /** The builder's "Save as view": apply the conditions, then save them with
   * the current columns as a personal view (`saveAsMyView`). */
  saveAdvancedFindAsView(filters: QueryFilter[]): void {
    this.applyAdvancedFilters(filters);
    void this.saveAsMyView();
  }

  /** Opening a view puts its saved advanced-find conditions in force (none
   * for a view that saved none). A list-embedding caller that locks the view
   * gets them too — they are part of the view. */
  private applyViewFilters(viewId: string): void {
    const view = this.availableViews().find(v => v.id === viewId);
    this.advancedFilters.set(viewFilters(view?.view_metadata));
    this.advancedFindOpen.set(false);
  }

  // ── Sort ───────────────────────────────────────────────────────────────────

  sortByColumnClick(colName: string, event: Event): void {
    event.stopPropagation();
    if (this.sortColumn() === colName) {
      this.sortDirection.update(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      this.sortColumn.set(colName);
      this.sortDirection.set('asc');
    }
    this.currentPage.set(1);
    this.load();
  }

  isSortedBy(colName: string): boolean { return this.sortColumn() === colName; }

  getSortIcon(colName: string): string {
    if (this.sortColumn() !== colName) return 'las la-sort';
    return this.sortDirection() === 'asc' ? 'las la-sort-up' : 'las la-sort-down';
  }

  sortAriaLabel(col: Col): string {
    if (!this.isSortedBy(col.name)) {
      return this.lang.translate('entityList.sortByField', { field: col.display_name });
    }
    return this.sortDirection() === 'asc'
      ? this.lang.translate('entityList.sortedAscending')
      : this.lang.translate('entityList.sortedDescending');
  }

  // ── Pagination ─────────────────────────────────────────────────────────────

  previousPage(): void {
    if (this.currentPage() > 1) { this.currentPage.update(p => p - 1); this.load(); }
  }

  nextPage(): void {
    if (this.currentPage() < this.totalPages()) { this.currentPage.update(p => p + 1); this.load(); }
  }

  // ── Search ─────────────────────────────────────────────────────────────────

  onSearchChange(term: string): void {
    this.searchDraft.set(term);
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => {
      this.searchTerm = term;
      this.currentPage.set(1);
      this.load();
    }, 300);
  }

  // ── Column filters ─────────────────────────────────────────────────────────

  toggleColumnFilter(colName: string, event: Event): void {
    event.stopPropagation();
    if (this.openColumnFilter() === colName) { this.closeColumnFilter(); return; }
    this.openColumnFilter.set(colName);
    const active = this.activeFilters()[colName];
    this.filterDrafts.update(c => ({
      ...c,
      [colName]: active ? { ...active } : {},
    }));
  }

  closeColumnFilter(event?: Event): void {
    event?.stopPropagation();
    const col = this.openColumnFilter();
    if (col) {
      const active = this.activeFilters()[col];
      this.filterDrafts.update(c => {
        const next = { ...c };
        if (active) { next[col] = { ...active }; } else { delete next[col]; }
        return next;
      });
    }
    this.openColumnFilter.set(null);
  }

  applyColumnFilter(colName: string, event?: Event): void {
    event?.stopPropagation();
    const draft = this.filterDrafts()[colName] ?? {};
    this.activeFilters.update(c => {
      const next = { ...c };
      if (this.isFilterDraftActive(draft)) { next[colName] = { ...draft }; } else { delete next[colName]; }
      return next;
    });
    this.currentPage.set(1);
    this.openColumnFilter.set(null);
    this.writeFiltersToUrl();
    this.load();
  }

  clearColumnFilter(colName: string, event?: Event): void {
    event?.stopPropagation();
    this.filterDrafts.update(c => { const n = { ...c }; delete n[colName]; return n; });
    this.activeFilters.update(c => { const n = { ...c }; delete n[colName]; return n; });
    if (this.openColumnFilter() === colName) this.openColumnFilter.set(null);
    this.currentPage.set(1);
    this.writeFiltersToUrl();
    this.load();
  }

  clearAllFilters(): void {
    this.filterDrafts.set({});
    this.activeFilters.set({});
    this.advancedFilters.set([]);
    this.searchDraft.set('');
    this.searchTerm = '';
    this.currentPage.set(1);
    this.writeFiltersToUrl();
    this.load();
  }

  isColumnFilterApplied(colName: string): boolean {
    return this.isFilterDraftActive(this.activeFilters()[colName]);
  }

  getFilterKind(col: Col): FilterKind {
    return fieldTypeToFilterKind(col.type as FieldType);
  }

  getColumnOptions(col: Col): { label: string; value: string }[] {
    return col.options ?? [];
  }

  // filter draft getters / setters

  getTextOperator(colName: string): TextOperator {
    return draftOperator(this.filterDrafts()[colName], TEXT_OPERATORS, 'contains');
  }
  setTextOperator(colName: string, op: TextOperator): void { this.patchDraft(colName, { operator: op }); }

  getTextValue(colName: string): string { return draftValue(this.filterDrafts()[colName]); }
  setTextValue(colName: string, v: string): void { this.patchDraft(colName, { value: v }); }

  requiresTextValue(colName: string): boolean {
    return !isValuelessOperator(this.getTextOperator(colName));
  }

  getNumberOperator(colName: string): NumberOperator {
    return draftOperator(this.filterDrafts()[colName], NUMBER_OPERATORS, 'eq');
  }
  setNumberOperator(colName: string, op: NumberOperator): void { this.patchDraft(colName, { operator: op }); }

  getNumberValue(colName: string): string { return draftValue(this.filterDrafts()[colName]); }
  setNumberValue(colName: string, v: string): void { this.patchDraft(colName, { value: v }); }

  requiresNumberValue(colName: string): boolean {
    return !isValuelessOperator(this.getNumberOperator(colName));
  }

  getDateOperator(colName: string): DateOperator {
    return draftOperator(this.filterDrafts()[colName], DATE_OPERATORS, '');
  }
  setDateOperator(colName: string, op: DateOperator): void { this.patchDraft(colName, { operator: op }); }

  getDateValue(colName: string): string { return draftValue(this.filterDrafts()[colName]); }
  setDateValue(colName: string, v: string): void { this.patchDraft(colName, { value: v }); }

  requiresDateValue(colName: string): boolean {
    const op = this.getDateOperator(colName);
    return op === 'on' || op === 'after' || op === 'before';
  }

  /** `between` on a number or date column: the popover shows a from/to pair. */
  isRangeOperator(colName: string): boolean {
    return this.filterDrafts()[colName]?.operator === 'between';
  }

  getValueTo(colName: string): string { return draftValueTo(this.filterDrafts()[colName]); }
  setValueTo(colName: string, v: string): void { this.patchDraft(colName, { valueTo: v }); }

  /** A lookup column's popover offers emptiness only — a record id is not
   * something to type into a column header (the advanced-find builder picks
   * one through the lookup picker instead). */
  getLookupOperator(colName: string): string {
    const op = this.filterDrafts()[colName]?.operator;
    return op === 'is_null' || op === 'is_not_null' ? op : '';
  }
  setLookupOperator(colName: string, op: string): void { this.patchDraft(colName, { operator: op }); }

  getBooleanValue(colName: string): string {
    const v = this.filterDrafts()[colName]?.value;
    if (v === true)  return 'true';
    if (v === false) return 'false';
    return '';
  }
  setBooleanValue(colName: string, v: string): void {
    this.patchDraft(colName, { operator: 'eq', value: v === '' ? null : v === 'true' });
  }

  getOptionsetValue(colName: string): string {
    const v = this.filterDrafts()[colName]?.value;
    return v == null ? '' : String(v);
  }
  setOptionsetValue(colName: string, v: string): void {
    this.patchDraft(colName, { operator: 'eq', value: v || null });
  }

  // ── Selection ──────────────────────────────────────────────────────────────

  isAllOnPageSelected(): boolean {
    const recs = this.records();
    return recs.length > 0 && recs.every(r => this.selectedRecordIds().has(r.id));
  }

  selectAllOnPage(): void {
    const ids = this.records().map(r => r.id);
    this.selectedRecordIds.update(s => new Set([...s, ...ids]));
  }

  deselectAllOnPage(): void {
    const ids = new Set(this.records().map(r => r.id));
    this.selectedRecordIds.update(s => new Set([...s].filter(id => !ids.has(id))));
  }

  toggleRecordSelection(row: EntityRecord): void {
    this.selectedRecordIds.update(s => {
      const next = new Set(s);
      if (next.has(row.id)) { next.delete(row.id); } else { next.add(row.id); }
      return next;
    });
  }

  clearSelection(): void { this.selectedRecordIds.set(new Set()); }

  private selectionHasState(active: boolean): boolean {
    if (this.bulkActionRunning()) return false;
    const rows = this.selectedRows();
    if (!rows?.length) return false;
    return rows.every(row => {
      const value = row['is_active'];
      if (value === null || value === undefined) return active;
      if (typeof value === 'boolean') return value === active;
      const text = String(value).trim().toLowerCase();
      if (['true', '1', 't', 'yes'].includes(text)) return active;
      if (['false', '0', 'f', 'no'].includes(text)) return !active;
      return false;
    });
  }

  canDeactivateSelection(): boolean { return this.selectionHasState(true); }
  canActivateSelection(): boolean { return this.selectionHasState(false); }

  /**
   * A18-T9: shows what the delete would take with it (or what blocks it),
   * asks for a reason when the entity requires one, then deletes the
   * selection as one operation so Undo restores it.
   */
  async deactivateSelected(): Promise<void> {
    const ids = [...this.selectedRecordIds()];
    if (!ids.length || this.bulkActionRunning()) return;
    const entity = this.entityName();
    // The preview is a courtesy; the delete itself still checks everything.
    const impact: DeleteImpact | null = await firstValueFrom(this.entitySvc.deleteImpact(entity, ids))
      .catch(() => null);
    if (impact?.blocked_by.length) {
      this.dialogSvc.error({
        title: this.lang.translate('entityList.actionFailedTitle'),
        message: this.lang.translate('entityList.deleteBlocked', {
          details: impact.blocked_by.map(b => `${b.entity} (${b.count})`).join(', '),
        }),
      });
      return;
    }
    const question = this.lang.translate('entityList.deactivateRecordConfirm', { count: ids.length });
    const cascades = impact?.cascades.length
      ? ' ' + this.lang.translate('entityList.deleteCascades', {
        details: impact.cascades.map(c => `${c.entity} (${c.count})`).join(', '),
      })
      : '';
    let reason: string | undefined;
    if (impact?.reason_required) {
      const given = await this.dialogSvc.prompt({
        title: this.lang.translate('entityList.deactivateSelected'),
        message: question + cascades,
        label: this.lang.translate('entityList.deleteReason'),
        confirmText: this.lang.translate('entityList.confirmButtonDelete'),
        validator: value => value.trim() ? null : this.lang.translate('entityList.deleteReasonRequired'),
      });
      if (given === null || !given.trim()) return;
      reason = given.trim();
    } else {
      const confirmed = await this.dialogSvc.confirm({
        message: question + cascades,
        variant: 'danger',
        confirmText: this.lang.translate('entityList.confirmButtonDelete'),
      });
      if (!confirmed) return;
    }
    // One operation id for the whole selection, so Undo restores it.
    const operationId = newOperationId();
    await this.runBulk(
      undefined,
      id => this.entitySvc.delete(entity, id, { operationId, reason }),
      succeeded => { if (succeeded > 0) this.offerUndo(operationId, succeeded); },
    );
  }

  private offerUndo(operationId: string, count: number): void {
    if (this.undoTimer) clearTimeout(this.undoTimer);
    this.undoOffer.set({ operationId, count });
    this.undoTimer = setTimeout(() => { this.undoOffer.set(null); this.undoTimer = null; }, UNDO_SECONDS * 1000);
  }

  /** A18-T9: this entity's recycle bin. */
  openBin(): void {
    void this.router.navigate(['/xrm/bin', this.entityName()]);
  }

  /** A18-T9: puts the last delete's records back. */
  undoDelete(): void {
    const offer = this.undoOffer();
    if (!offer) return;
    if (this.undoTimer) { clearTimeout(this.undoTimer); this.undoTimer = null; }
    this.undoOffer.set(null);
    this.entitySvc.restoreOperation(offer.operationId).subscribe({
      next: result => {
        this.load();
        if (result.failed.length) {
          this.dialogSvc.error({
            title: this.lang.translate('entityList.actionFailedTitle'),
            message: this.lang.translate('entityList.undoPartial', { count: result.failed.length }),
          });
        }
      },
      error: (err: ApiError) => this.dialogSvc.error({
        title: this.lang.translate('entityList.actionFailedTitle'), message: err.message,
      }),
    });
  }

  dismissUndo(): void {
    if (this.undoTimer) { clearTimeout(this.undoTimer); this.undoTimer = null; }
    this.undoOffer.set(null);
  }

  activateSelected(): void {
    this.runBulk(
      'entityList.activateRecordConfirm',
      id => this.entitySvc.restore(this.entityName(), id),
    );
  }

  deleteSelected(): void {
    this.runBulk(
      'entityList.hardDeleteConfirm',
      id => this.entitySvc.hardDelete(this.entityName(), id),
    );
  }

  runSelectionAction(action: SelectionAction): void {
    if (!this.isSelectionActionEnabled(action)) return;
    this.runBulk(action.confirmKey, id => action.run(id));
  }

  /**
   * Fans out `op` over the selection, then refreshes once.
   *
   * Counts failures rather than only successes: the previous
   * count-down-on-success loop left `remaining` above zero whenever any item
   * errored, so a partial failure skipped `clearSelection()`/`load()`
   * entirely and the grid kept rendering pre-mutation rows with no
   * indication anything had changed. Failures are collected and reported
   * once at the end instead of firing one `alert()` per failed record.
   */
  private async runBulk(
    confirmKey: string | undefined,
    op: (id: string) => Observable<unknown>,
    done?: (succeeded: number) => void,
  ): Promise<void> {
    const ids = [...this.selectedRecordIds()];
    if (!ids.length || this.bulkActionRunning()) return;
    if (confirmKey) {
      const isDanger = confirmKey.toLowerCase().includes('delete') || confirmKey.toLowerCase().includes('deactivate');
      const confirmed = await this.dialogSvc.confirm({
        message: this.lang.translate(confirmKey, { count: ids.length }),
        variant: isDanger ? 'danger' : 'primary',
        confirmText: this.lang.translate(
          confirmKey.toLowerCase().includes('delete') ? 'entityList.confirmButtonDelete' : 'entityList.confirmButtonDefault',
        ),
      });
      if (!confirmed) return;
    }

    this.bulkActionRunning.set(true);
    let remaining = ids.length;
    const failures: string[] = [];

    const settle = (): void => {
      if (--remaining > 0) return;
      this.bulkActionRunning.set(false);
      this.clearSelection();
      this.load();
      done?.(ids.length - failures.length);
      if (failures.length) {
        this.dialogSvc.error({
          title: this.lang.translate('entityList.actionFailedTitle'),
          message: this.lang.translate('entityList.bulkActionPartialFailure', {
            count:  failures.length,
            reason: failures[0],
          }),
        });
      }
    };

    for (const id of ids) {
      // `complete`, not `next` — settle exactly once per record no matter how
      // many values the operation emits. `error` short-circuits `complete`,
      // so the two branches stay mutually exclusive.
      op(id).subscribe({
        complete: () => settle(),
        error:    (err: ApiError) => { failures.push(err.message); settle(); },
      });
    }
  }

  duplicateSelected(): void {
    this.dialogSvc.error({
      title: this.lang.translate('entityList.notImplementedTitle'),
      message: this.lang.translate('entityList.duplicateNotImplemented'),
    });
  }

  /** `<xrm-bulk-edit-dialog>`'s `(applied)` handler — a completed bulk edit
   * (terminal or not; the dialog itself already reported the outcome)
   * clears the selection and reloads, same as `applyBulkEdit` always did
   * inline before the dialog became its own component (C-28). */
  /** "Bulk edit": opens the dialog, loading it first on the first click. */
  openBulkEdit(): void {
    const dialog = this.bulkEditDialog();
    if (dialog) { dialog.openDialog(); return; }
    this.bulkEditOpenPending = true;
    this.bulkEditRequested.set(true);
  }

  onBulkEditApplied(): void {
    this.clearSelection();
    this.load();
  }

  /** U7 Phase A — a bulk Assign finished (its dialog reported the outcome). */
  onRecordAccessChanged(): void {
    this.clearSelection();
    this.load();
  }

  /**
   * M12 (data management) — enqueues a durable, permission-filtered CSV or
   * Excel export of this entity (`POST /api/v1/{entity}/export`) and polls it
   * the same way `applyBulkEdit` polls a bulk job, then opens the presigned
   * download URL in a new tab once it's ready — same pattern
   * `AttachmentComponent`/`DocumentFolderBrowserComponent` already use for a
   * field's own file download, never a blob fetched through `ApiService`.
   *
   * Forwards the grid's filters (its fixed filters plus every active column
   * filter, already translated by `buildColumnFilters`). The export grammar is
   * narrower than `query/execute`'s (`splitExportFilters`); a filter it cannot
   * express is never approximated — the user is asked whether to export
   * without it instead (D-408). The view's own stored-query SQL is not
   * forwarded: the export endpoint takes structured filters only.
   */
  async exportList(format: 'csv' | 'xlsx' = 'csv'): Promise<void> {
    if (this.bulkActionRunning()) return;
    const entityName = this.entityName();

    const { exportable, unsupported } = splitExportFilters(this.buildColumnFilters());
    if (unsupported.length > 0) {
      const fields = [...new Set(unsupported.map(f => f.field))].join(', ');
      const proceed = await this.dialogSvc.confirm({
        title: this.lang.translate('entityList.export'),
        message: this.lang.translate('entityList.exportFiltersDropped', { fields }),
        confirmText: this.lang.translate('entityList.export'),
      });
      if (!proceed) return;
    }

    this.bulkActionRunning.set(true);
    try {
      const enqueued = await firstValueFrom(this.entitySvc.exportRecords(entityName, format, [], exportable));
      const status = await firstValueFrom(this.bulkJobs.poll(
        () => this.entitySvc.exportStatus(entityName, enqueued.id),
        s => isBulkTerminal(s.status),
      ));

      if (!isBulkTerminal(status.status)) {
        await this.dialogSvc.error({
          title: this.lang.translate('entityList.export'),
          message: this.lang.translate('entityList.exportStillRunning'),
        });
      } else if (status.status === 'completed' && status.download_url) {
        window.open(status.download_url, '_blank', 'noopener');
      } else {
        await this.dialogSvc.error({
          title: this.lang.translate('entityList.export'),
          message: this.lang.translate('entityList.exportFailed', { reason: status.error ?? status.status }),
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.dialogSvc.error({
        title: this.lang.translate('entityList.export'),
        message: this.lang.translate('entityList.exportFailed', { reason: message }),
      });
    } finally {
      this.bulkActionRunning.set(false);
    }
  }

  // ── Cell / navigation ──────────────────────────────────────────────────────

  isCellLinked(col: Col, colIndex: number, row: EntityRecord): boolean {
    if (col.is_clickable) return resolveRouteTemplate(col.route_template, row.data) !== null;
    return colIndex === 0;
  }

  handleCellNavigation(row: EntityRecord, col: Col, colIndex: number): void {
    if (col.is_clickable) {
      const route = resolveRouteTemplate(col.route_template, row.data);
      if (route) void this.router.navigateByUrl(route);
      return;
    }
    if (colIndex !== 0) return;
    this.editClick.emit(row);
  }

  handleAdd(recordType: string | null = null): void { this.newClick.emit(recordType); }

  handleAddRelationship(): void { this.addRelationshipClick.emit(); }

  handleRemoveRelationship(): void {
    const ids = [...this.selectedRecordIds()];
    if (ids.length) this.removeRelationshipClick.emit(ids);
  }

  /** What a cell actually shows: for a lookup column, the resolved target
   * display name when the server was able to resolve one, otherwise falls
   * back to `formatCellValue`'s normal formatting of the raw stored value
   * (the UUID) — same fallback stance as `resolve_lookup_meta`'s
   * best-effort resolution on the backend. */
  cellDisplayValue(row: EntityRecord, col: Col): string {
    if (col.type === 'lookup') {
      const meta = row.lookups?.[col.name] ?? (row.data?.['__lookups'] as Record<string, LookupMeta> | undefined)?.[col.name];
      if (meta?.name != null && meta.name !== '') return meta.name;
    }
    return this.formatCellValue(row.data[col.name], col);
  }

  /** Raw string value(s) of a `type: 'choice'` cell, one entry per selected
   * value (multi-select) — used to render one `xrm-choice-pill` per value
   * instead of `formatCellValue`'s comma-joined plain string. */
  choiceCellValues(row: EntityRecord, col: Col): string[] {
    const value = row.data[col.name];
    if (value == null) return [];
    return (Array.isArray(value) ? value : [value]).map(String);
  }

  /** D-490 — `col.type === 'currency'` cell: the stored USD amount,
   *  converted to the viewer's preferred currency and formatted with its
   *  icon. */
  currencyCellDisplay(row: EntityRecord, col: Col): string {
    const raw = row.data[col.name];
    if (raw == null || raw === '') return '';
    const usd = Number(raw);
    if (!Number.isFinite(usd)) return String(raw);
    const code = this.preferredCurrency();
    const rate = this.currency.getRate(code);
    return `${rate.icon}${this.currency.fromBase(usd, code).toFixed(2)}`;
  }

  formatCellValue(value: unknown, col: Col): string {
    if (value == null) return '';
    // U9 (D-605): a rich-text cell shows its visible text, never markup.
    if (col.type === 'rich_text') {
      const text = richTextToPlainText(String(value));
      return text.length > 80 ? text.slice(0, 77) + '…' : text;
    }
    if (col.type === 'bool') {
      const yes = this.lang.translate('entityList.yes');
      const no  = this.lang.translate('entityList.no');
      if (typeof value === 'boolean') return value ? yes : no;
      const s = String(value).toLowerCase().trim();
      if (s === 'true'  || s === '1' || s === 't') return yes;
      if (s === 'false' || s === '0' || s === 'f') return no;
    }
    if (Array.isArray(value)) return value.join(', ');
    const asDate = formatDateCell(String(value).trim());
    if (asDate !== null) return asDate;
    const s = String(value);
    return s.length > 80 ? s.slice(0, 77) + '…' : s;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private isFilterDraftActive(draft: ColumnFilterDraft | undefined): boolean {
    return isColumnFilterDraftActive(draft);
  }

  private patchDraft(colName: string, patch: Partial<ColumnFilterDraft>): void {
    this.filterDrafts.update(c => ({
      ...c,
      [colName]: { ...(c[colName] ?? {}), ...patch },
    }));
  }

  private writeFiltersToUrl(): void {
    if (!this.syncUrl()) return;
    const urlTree = this.router.parseUrl(this.router.url);
    const filters = serializeColumnFilters(this.activeFilters());
    if (filters === null) {
      delete urlTree.queryParams['filters'];
    } else {
      urlTree.queryParams['filters'] = filters;
    }
    void this.router.navigateByUrl(urlTree);
  }

  private writeViewToUrl(viewId: string): void {
    const urlTree = this.router.parseUrl(this.router.url);
    urlTree.queryParams['view'] = viewId;
    void this.router.navigateByUrl(urlTree);
  }

  /** B17-T6: what a card's tap or swipe does. */
  runCardAction(event: { action: SwipeAction; record: EntityRecord }): void {
    const row = event.record;
    switch (event.action) {
      case 'open':
      case 'assign':
        // Assigning happens on the record, where the owner can be changed.
        this.editClick.emit(row);
        break;
      case 'call': {
        const phone = ['phone', 'mobile', 'mobile_phone', 'telephone']
          .map(f => row.data[f])
          .find(v => typeof v === 'string' && v.trim());
        if (typeof phone === 'string') globalThis.location.href = `tel:${phone.replace(/[^\d+]/g, '')}`;
        break;
      }
      case 'complete':
        if (!('status' in row.data)) {
          this.editClick.emit(row);
          break;
        }
        this.entitySvc.update(this.entityName(), row.id, { status: 'completed' }, row.row_version).subscribe({
          next: () => this.refresh(),
          error: () => this.editClick.emit(row),
        });
        break;
    }
  }

  ngOnDestroy(): void {
    phoneQuery()?.removeEventListener('change', this.phoneListener);
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.loadSub?.unsubscribe();
  }
}
