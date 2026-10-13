import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  OnDestroy,
  OnInit,
  computed,
  inject,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { takeUntilDestroyed, toObservable } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import {
  Observable, catchError, concatMap, defer, forkJoin, from, map, of, switchMap, tap, throwError, toArray,
} from 'rxjs';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { EntityRecord } from '@attome/xrm';
import {
  EntityRecordResponse, EntityService, HasUnsavedChanges, entityFormRoute, entityListRoute,
} from '@attome/xrm/core/entity';
// D-543 — the editor never writes `view`; `ViewAdminService` stays for
// the table widgets' view picker.
import { ViewAdminService } from '@attome/xrm/core/query/data';
// Package import, not relative — `DashboardWidgetViewComponent` lives under
// this package's own `@attome/xrm/dashboard` entry point, outside this
// `registration` entry point's rootDir.
import { DashboardWidgetViewComponent } from '@attome/xrm/dashboard';
import { DashboardService, DashboardVariableBusService } from '@attome/xrm/dashboard/data';
import {
  GridMetrics, WidgetRect,
  applyResize, canvasHeightStyle, computeGridMetrics, diffLayout, diffPatch,
  dragTarget, resolveCollisions, snapToGridClamped, tileBoxStyle, widgetRects,
} from './layout-engine';
import { DraftHistory } from './draft-history';
import { WidgetPositionCommit, WidgetTypeDescriptor } from './page-editor.types';
import { WidgetPaletteComponent } from './widget-palette/widget-palette.component';
import {
  ChartFieldOption, ViewGroup, ViewSummary, WidgetInspectorComponent,
} from './widget-inspector/widget-inspector.component';
import { PageSettingsPanelComponent } from './page-settings-panel/page-settings-panel.component';

interface GridGhost {
  widgetId: string;
  col: number;
  row: number;
  colSpan: number;
  rowSpan: number;
}

/** A single undo/redo step — a full snapshot of the document state a draft
 * edit can touch: the page record, the widget list (so a draft delete undoes
 * locally), and each bound view's chart settings. */
interface DocSnapshot {
  widgets: EntityRecord[];
  page: EntityRecordResponse | null;
  viewMetadata: Record<string, unknown>;
}

/** The draft diff mirrored to `sessionStorage` so a refresh or crash can
 * offer recovery (Dashboard 10/10 Phase 1.4). Only diffs against the saved
 * server state are stored, never whole records. */
export interface StoredPageDraft {
  version: 1;
  page: Record<string, unknown>;
  widgets: Record<string, Record<string, unknown>>;
  deleted: string[];
  /** Pre-D-543 drafts carried pending view edits; the editor no longer writes
   * views, so this is only ever read back from an older stored draft. */
  views?: Record<string, unknown>;
}

/** Grid footprint given to every newly-created widget, whether added via a
 * palette click or a palette-to-canvas drop. */
const NEW_WIDGET_COL_SPAN = 4;
const NEW_WIDGET_ROW_SPAN = 2;

const isConflict = (e: ApiError | null | undefined): boolean => e?.status === 409 || e?.status === 412;

const toWidgetRecord = (rec: EntityRecordResponse): EntityRecord => ({
  id: rec.id,
  entity_id: rec.entity_id,
  data: rec.data,
  row_version: rec.row_version,
  created_at: rec.created_at ?? '',
  updated_at: rec.updated_at ?? '',
});

export const pageDraftStorageKey = (pageId: string): string => `attome-dashboard:page-draft:${pageId}`;

/**
 * The visual drag-and-drop Page Editor: tree loading via `DashboardService`,
 * selection, pointer drag/resize and save/cancel, plus three presentational
 * children (`widget-palette`, `widget-inspector`, `page-settings-panel`) and
 * two Angular-free modules (`layout-engine.ts`'s grid math,
 * `draft-history.ts`'s undo/redo stack).
 *
 * A page belongs to exactly one dashboard (D-520) and is loaded through that
 * dashboard's draft tree. A new page is created only in a dashboard's
 * context, with its root grid section (D-527); a page with no section is
 * reported and repaired explicitly — no read writes.
 *
 * **Draft/save model (Phase 1.4 — the editor never loses work).** The saved
 * snapshots (`savedWidgetsSnapshot`, `savedPageSnapshot`, `savedViewMetadata`)
 * are the server state. Every edit — moves, resizes, field and page-settings
 * edits, chart settings, and deletes — applies to the in-memory draft and
 * pushes an undo step. Add and duplicate create the widget on the server and
 * merge that one record into both the draft and the saved snapshot, so they
 * never reload the page or clear history; undoing one leaves the server
 * widget in the saved snapshot, and Save then deletes it. `saveChanges()`
 * runs sequentially with `If-Match`: page, widget PATCHes, view settings,
 * then DELETEs; each success updates only its own saved entry, so a failure
 * leaves everything unsaved still dirty. A 409/412 stops the queue and marks
 * the widget for "Keep mine"/"Take theirs". The draft diff is mirrored to
 * `sessionStorage` for recovery, and leaving with unsaved work is guarded
 * (route `canDeactivate` plus `beforeunload`).
 *
 * Parameters CRUD still commits immediately (not part of the draft).
 */
@Component({
  selector:   'xrm-page-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    DashboardWidgetViewComponent, TranslatePipe,
    WidgetPaletteComponent, WidgetInspectorComponent, PageSettingsPanelComponent,
  ],
  // One cross-filter bus per editor, like the viewer (Phase 2.4).
  providers: [DashboardVariableBusService],
  styleUrls:  ['../../../styles/xrm-form.css', './page-editor.component.css'],
  templateUrl: './page-editor.component.html',
  host: { '(window:beforeunload)': 'onBeforeUnload($event)' },
})
export class PageEditorComponent implements OnInit, AfterViewInit, OnDestroy, HasUnsavedChanges {
  private readonly svc           = inject(EntityService);
  private readonly dashboardApi  = inject(DashboardService);
  private readonly viewAdmin     = inject(ViewAdminService);
  private readonly router        = inject(Router);
  private readonly dialogService = inject(DialogService);
  private readonly lang          = inject(LangService);
  private readonly destroyRef    = inject(DestroyRef);

  // `EntityRouterComponent` mounts every registered `formComponent` override
  // through `NgComponentOutlet` and unconditionally passes `{ name, id }` —
  // `name` has to be declared even though this component never reads it, or
  // `NgComponentOutlet` throws NG0303 setting it.
  readonly name        = input('');
  readonly pageId      = input<string | null>(null);
  readonly dashboardId = input<string | null>(null);
  readonly id          = input<string | null>(null);

  /** Set once this component creates a brand-new page itself (see
   * `createPage` below). */
  private readonly createdPageId = signal<string | null>(null);
  private readonly effectivePageId = computed(() => this.pageId() ?? this.id() ?? this.createdPageId());
  /** The owning dashboard as loaded from the page record, for callers that
   * opened the editor with a page id only. */
  private readonly loadedDashboardId = signal<string | null>(null);
  readonly effectiveDashboardId = computed(() => this.dashboardId() ?? this.loadedDashboardId());

  /** True only while this screen has no page to edit yet. A page can only be
   * created inside a dashboard (D-520), so the prompt needs `dashboardId`. */
  readonly needsPageCreation = computed(() => !this.effectivePageId());
  readonly newPageName = signal('');
  readonly creatingPage = signal(false);

  onNewPageNameChange(value: string): void {
    this.newPageName.set(value);
  }

  createPage(): void {
    const name = this.newPageName().trim();
    const dashboardId = this.dashboardId();
    if (!name || !dashboardId || this.creatingPage()) return;
    this.creatingPage.set(true);
    this.dashboardApi.createPage(dashboardId, { name, sequence: 0, is_visible: true }).subscribe({
      next: created => {
        this.creatingPage.set(false);
        this.createdPageId.set(created.id);
        // Best-effort URL update so a refresh/bookmark keeps working.
        void this.router.navigate([], {
          queryParams: { id: created.id }, queryParamsHandling: 'merge', replaceUrl: true,
        });
        this.load();
      },
      error: (e: ApiError) => {
        this.creatingPage.set(false);
        this.error.set(e.message);
      },
    });
  }

  readonly loading   = signal(true);
  /** A load failure — there is no canvas to keep, so this replaces it. */
  readonly loadError = signal<string | null>(null);
  /** Any other failure — an inline, dismissible banner above the canvas. */
  readonly error     = signal<string | null>(null);
  readonly saving    = signal(false);
  readonly page      = signal<EntityRecordResponse | null>(null);

  readonly widgets     = signal<EntityRecord[]>([]);
  readonly widgetTypes = signal<WidgetTypeDescriptor[]>([]);

  // A widget's data source — a named, admin-defined `view`, picked
  // from a list rather than a raw stored-query id typed in blind.
  readonly views = signal<ViewSummary[]>([]);
  readonly viewGroups = computed<ViewGroup[]>(() => {
    const byEntity = new Map<string, ViewSummary[]>();
    for (const v of this.views()) {
      const list = byEntity.get(v.entity_name) ?? [];
      list.push(v);
      byEntity.set(v.entity_name, list);
    }
    return [...byEntity.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([entity_name, views]) => ({
        entity_name,
        views: views.sort((a, b) => a.name.localeCompare(b.name)),
      }));
  });

  /** `ViewAdminService.list()` walks every page (`getAllPages`). */
  private loadViews(): void {
    this.viewAdmin.list().subscribe({
      next: views => {
        this.views.set(views);
        this.savedViewMetadata = Object.fromEntries(views.map(v => [v.id, v.view_metadata]));
      },
      error: () => this.views.set([]),
    });
  }

  readonly rootSectionId    = signal<string | null>(null);
  /** The page has no section at all (D-527) — widgets cannot be added until
   * `repairRootSection()` provisions one. */
  readonly needsRootSection = signal(false);
  readonly repairingRootSection = signal(false);
  /** Dashboard 10/10 Phase 5.C — a `Set`, insertion-ordered (JS guarantee),
   * so the inspector can show the most-recently-selected widget's fields
   * (`selectedWidget` below) even when several are selected. */
  readonly selectedWidgetIds = signal<Set<string>>(new Set());
  readonly paletteOpen      = signal(false);
  readonly previewMode      = signal(false);
  /** Set by a plain (non-modifier) `selectWidget` click — the anchor a
   * following Shift+Click range-selects from. */
  private lastSelectedWidgetId: string | null = null;

  /** The most-recently-selected widget, for the single-widget inspector
   * panel — multi-select edits the whole set via keyboard/copy-paste, but
   * only one widget's fields are ever shown at a time. */
  readonly selectedWidget = computed<EntityRecord | null>(() => {
    const id = Array.from(this.selectedWidgetIds()).at(-1);
    if (!id) return null;
    return this.widgets().find(w => w.id === id) ?? null;
  });

  /** Last `validateWidgetConfig` result for the selected widget. */
  readonly configErrors = signal<string[]>([]);

  // ── Draft / save / undo-redo ─────────────────────────────────────────────

  private readonly savedWidgetsSnapshot = signal<EntityRecord[]>([]);
  private readonly savedPageSnapshot = signal<EntityRecordResponse | null>(null);
  private savedViewMetadata: Record<string, unknown> = {};

  /** Widgets whose save hit a 409/412 — each offers "Keep mine"/"Take theirs". */
  readonly conflictedWidgetIds = signal<ReadonlySet<string>>(new Set());
  /** A draft found in `sessionStorage` on load, awaiting Restore/Discard. */
  readonly recoverableDraft = signal<StoredPageDraft | null>(null);

  private readonly history = new DraftHistory<DocSnapshot>();
  // Bumped on every history mutation so `dirty`/`canUndo`/`canRedo` stay
  // reactive (`DraftHistory` has no Angular dependency).
  private readonly historyTick = signal(0);
  readonly dirty   = computed(() => { this.historyTick(); return this.history.canUndo; });
  readonly canUndo = this.dirty;
  readonly canRedo = computed(() => { this.historyTick(); return this.history.canRedo; });

  hasUnsavedChanges(): boolean {
    return this.dirty();
  }

  /** Covers a refresh or tab close; in-app navigation goes through the
   * route's `unsavedChangesGuard`. */
  onBeforeUnload(event: BeforeUnloadEvent): void {
    if (this.dirty()) event.preventDefault();
  }

  private snapshot(): DocSnapshot {
    return { widgets: this.widgets(), page: this.page(), viewMetadata: this.viewMetadataMap() };
  }

  private restore(snapshot: DocSnapshot): void {
    this.widgets.set(snapshot.widgets);
    this.page.set(snapshot.page);
    this.applyViewMetadata(snapshot.viewMetadata);
  }

  private pushHistory(): void {
    this.history.push(this.snapshot());
    this.historyTick.update(v => v + 1);
  }

  undo(): void {
    const prev = this.history.undo(this.snapshot());
    this.historyTick.update(v => v + 1);
    if (!prev) return;
    this.restore(prev);
    this.persistDraft();
  }

  redo(): void {
    const next = this.history.redo(this.snapshot());
    this.historyTick.update(v => v + 1);
    if (!next) return;
    this.restore(next);
    this.persistDraft();
  }

  private clearDraftHistory(): void {
    this.history.clear();
    this.historyTick.update(v => v + 1);
  }

  private viewMetadataMap(): Record<string, unknown> {
    return Object.fromEntries(this.views().map(v => [v.id, v.view_metadata]));
  }

  private applyViewMetadata(metadata: Record<string, unknown>): void {
    this.views.update(list => list.map(v =>
      Object.prototype.hasOwnProperty.call(metadata, v.id)
        ? { ...v, view_metadata: metadata[v.id] as ViewSummary['view_metadata'] }
        : v));
  }

  private static readonly PAGE_DRAFT_KEYS = [
    'name', 'name_ar', 'slug', 'icon', 'background_kind', 'background_value', 'padding',
    'is_visible', 'settings',
  ] as const;
  private static readonly WIDGET_DRAFT_KEYS = [
    'grid_col', 'grid_row', 'grid_col_span', 'grid_row_span', 'name', 'query_id', 'view_id',
    'config',
  ] as const;

  /** The draft as a diff against the saved server state, or `null` when
   * nothing differs. */
  private draftDiff(): StoredPageDraft | null {
    const page = this.page();
    const pagePatch = page
      ? diffPatch(this.savedPageSnapshot()?.data, page.data, PageEditorComponent.PAGE_DRAFT_KEYS)
      : {};
    const saved = this.savedWidgetsSnapshot();
    const widgets: Record<string, Record<string, unknown>> = {};
    for (const w of this.widgets()) {
      const before = saved.find(sw => sw.id === w.id);
      if (!before) continue;
      const patch = diffPatch(before.data, w.data, PageEditorComponent.WIDGET_DRAFT_KEYS);
      if (Object.keys(patch).length > 0) widgets[w.id] = patch;
    }
    const currentIds = new Set(this.widgets().map(w => w.id));
    const deleted = saved.filter(sw => !currentIds.has(sw.id)).map(sw => sw.id);
    // D-543: no `views` entry — the editor no longer writes
    // `view.view_metadata`, so there is nothing about a view to
    // recover. Chart settings ride along in each widget's own `config` patch.
    const empty = Object.keys(pagePatch).length === 0 && Object.keys(widgets).length === 0
      && deleted.length === 0;
    return empty ? null : { version: 1, page: pagePatch, widgets, deleted };
  }

  /** Mirrors the draft diff to `sessionStorage` (or clears it when nothing
   * is unsaved). Storage can be unavailable — recovery is a convenience, the
   * editor works without it. */
  private persistDraft(): void {
    const pageId = this.effectivePageId();
    if (!pageId) return;
    const draft = this.draftDiff();
    try {
      if (draft) sessionStorage.setItem(pageDraftStorageKey(pageId), JSON.stringify(draft));
      else sessionStorage.removeItem(pageDraftStorageKey(pageId));
    } catch { /* storage unavailable — recovery simply isn't offered */ }
  }

  private clearStoredDraft(): void {
    const pageId = this.effectivePageId();
    if (!pageId) return;
    try { sessionStorage.removeItem(pageDraftStorageKey(pageId)); } catch { /* see persistDraft */ }
  }

  private readStoredDraft(pageId: string): StoredPageDraft | null {
    try {
      const raw = sessionStorage.getItem(pageDraftStorageKey(pageId));
      if (!raw) return null;
      const parsed = JSON.parse(raw) as StoredPageDraft;
      return parsed?.version === 1 ? parsed : null;
    } catch {
      return null;
    }
  }

  /** Re-applies a recovered draft on top of the freshly loaded page, as one
   * undoable step. Widgets no longer on the page are skipped. */
  restoreRecoveredDraft(): void {
    const draft = this.recoverableDraft();
    if (!draft) return;
    this.pushHistory();
    this.page.update(p => (p ? { ...p, data: { ...p.data, ...draft.page } } : p));
    const deleted = new Set(draft.deleted);
    this.widgets.update(list => list
      .filter(w => !deleted.has(w.id))
      .map(w => (draft.widgets[w.id] ? { ...w, data: { ...w.data, ...draft.widgets[w.id] } } : w)));
    this.applyViewMetadata(draft.views ?? {});
    this.recoverableDraft.set(null);
    this.persistDraft();
  }

  discardRecoveredDraft(): void {
    this.recoverableDraft.set(null);
    this.clearStoredDraft();
  }

  /** Commits every pending draft edit, sequentially (concurrent writes for
   * this organization race a per-org audit-chain-append advisory lock):
   * page settings, widget PATCHes, chart settings, then DELETEs. */
  saveChanges(): void {
    if (!this.dirty() || this.saving()) return;
    this.saving.set(true);
    this.error.set(null);
    this.conflictedWidgetIds.set(new Set());

    const savedIds = new Set(this.savedWidgetsSnapshot().map(w => w.id));
    const currentIds = new Set(this.widgets().map(w => w.id));
    const steps: Observable<unknown>[] = [
      defer(() => this.savePage$()),
      ...this.widgets().filter(w => savedIds.has(w.id)).map(w => defer(() => this.saveWidget$(w.id))),
      ...[...savedIds].filter(id => !currentIds.has(id)).map(id => defer(() => this.deleteWidget$(id))),
    ];

    from(steps).pipe(concatMap(step => step), toArray()).subscribe({
      next: () => {
        this.saving.set(false);
        this.clearDraftHistory();
        this.clearStoredDraft();
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.error.set(this.conflictedWidgetIds().size > 0
          ? this.lang.translate('pageEditor.conflict')
          : e.message);
        this.persistDraft();
      },
    });
  }

  private savePage$(): Observable<unknown> {
    const current = this.page();
    const saved = this.savedPageSnapshot();
    if (!current) return of(null);
    const patch = diffPatch(saved?.data, current.data, PageEditorComponent.PAGE_DRAFT_KEYS);
    if (Object.keys(patch).length === 0) return of(null);
    return this.svc.update('dashboard_page', current.id, patch, current.row_version).pipe(
      tap(updated => {
        this.page.update(p => (p ? { ...p, row_version: updated.row_version } : p));
        this.savedPageSnapshot.set({
          ...(saved ?? current),
          data: { ...(saved ?? current).data, ...patch },
          row_version: updated.row_version,
        });
      }),
    );
  }

  private saveWidget$(widgetId: string): Observable<unknown> {
    const current = this.widgets().find(w => w.id === widgetId);
    const before = this.savedWidgetsSnapshot().find(w => w.id === widgetId);
    if (!current || !before) return of(null);
    const patch = diffPatch(before.data, current.data, PageEditorComponent.WIDGET_DRAFT_KEYS);
    if (Object.keys(patch).length === 0) return of(null);
    return this.svc.update('dashboard_widget', widgetId, patch, current.row_version).pipe(
      tap(rec => {
        this.patchLocalWidget(widgetId, {}, rec.row_version);
        this.savedWidgetsSnapshot.update(list => list.map(sw =>
          sw.id === widgetId ? { ...sw, data: { ...sw.data, ...patch }, row_version: rec.row_version } : sw));
      }),
      catchError((e: ApiError) => {
        if (isConflict(e)) this.conflictedWidgetIds.update(ids => new Set([...ids, widgetId]));
        return throwError(() => e);
      }),
    );
  }

  private deleteWidget$(widgetId: string): Observable<unknown> {
    return this.svc.delete('dashboard_widget', widgetId).pipe(
      tap(() => this.savedWidgetsSnapshot.update(list => list.filter(w => w.id !== widgetId))),
    );
  }

  /** Resolves a save conflict in favour of the local edit: re-reads the
   * widget for its current `row_version`, re-applies this editor's diff on
   * top of the server's version, and saves again. */
  keepMine(widgetId: string): void {
    const before = this.savedWidgetsSnapshot().find(w => w.id === widgetId);
    const current = this.widgets().find(w => w.id === widgetId);
    if (!before || !current) return;
    const localPatch = diffPatch(before.data, current.data, PageEditorComponent.WIDGET_DRAFT_KEYS);
    this.svc.get('dashboard_widget', widgetId).subscribe({
      next: rec => {
        const server = toWidgetRecord(rec);
        this.savedWidgetsSnapshot.update(list => list.map(w => (w.id === widgetId ? server : w)));
        this.widgets.update(list => list.map(w =>
          w.id === widgetId ? { ...server, data: { ...server.data, ...localPatch } } : w));
        this.resolveConflict(widgetId);
        this.saveChanges();
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Resolves a save conflict in favour of the other session: the widget
   * takes the server's version, locally and in the saved snapshot. */
  takeTheirs(widgetId: string): void {
    this.svc.get('dashboard_widget', widgetId).subscribe({
      next: rec => {
        const server = toWidgetRecord(rec);
        this.savedWidgetsSnapshot.update(list => list.map(w => (w.id === widgetId ? server : w)));
        this.widgets.update(list => list.map(w => (w.id === widgetId ? server : w)));
        this.resolveConflict(widgetId);
        this.persistDraft();
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  private resolveConflict(widgetId: string): void {
    this.conflictedWidgetIds.update(ids => new Set([...ids].filter(id => id !== widgetId)));
    if (this.conflictedWidgetIds().size === 0) this.error.set(null);
  }

  /** Discards every pending draft edit, restoring the last-saved state. */
  cancelChanges(): void {
    if (!this.dirty()) return;
    this.clearDraftHistory();
    const saved = this.savedPageSnapshot();
    if (saved) this.page.set(saved);
    this.widgets.set(this.savedWidgetsSnapshot());
    this.applyViewMetadata(this.savedViewMetadata);
    this.selectedWidgetIds.set(new Set());
    this.lastSelectedWidgetId = null;
    this.conflictedWidgetIds.set(new Set());
    this.clearStoredDraft();
  }

  togglePreview(): void {
    this.previewMode.update(v => !v);
  }

  // ── Header title inline edit ─────────────────────────────────────────────

  readonly editingTitle = signal(false);
  titleDraft = '';

  startEditTitle(): void {
    this.titleDraft = String(this.page()?.data['name'] ?? '');
    this.editingTitle.set(true);
  }

  commitTitle(value: string): void {
    this.editingTitle.set(false);
    const trimmed = value.trim();
    if (trimmed && trimmed !== this.page()?.data['name']) {
      this.updatePageLocal({ name: trimmed });
    }
  }

  // ── Palette / inspector / page-settings field edits ─────────────────────

  openPageSettings(): void {
    this.paletteOpen.set(false);
    this.clearWidgetSelection();
  }

  onWidgetField(field: string, value: unknown): void {
    const widget = this.selectedWidget();
    if (!widget) return;
    this.updateWidgetLocal(widget.id, { [field]: value });
    if (field === 'config') {
      const widgetType = String(widget.data['widget_type'] ?? '');
      this.validateWidgetConfig(String(value ?? ''), widgetType === 'declarative_widget' ? undefined : widgetType);
    }
  }

  /** `POST /api/v1/attome-dashboard/widget/validate-config` — advisory only: a
   * result here updates `configErrors` for inline display and never blocks
   * `saveChanges()`. */
  private validateWidgetConfig(raw: string, widgetType?: string): void {
    let parsed: unknown;
    try {
      parsed = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      this.configErrors.set([this.lang.translate('pageEditor.configNotValidJson')]);
      return;
    }
    this.dashboardApi.validateWidgetConfig(parsed, widgetType).subscribe({
      next: res => this.configErrors.set(res.valid ? [] : (res.errors ?? [])),
      error: () => this.configErrors.set([]),
    });
  }

  onSavePageSettings(patch: Record<string, unknown>): void {
    this.updatePageLocal(patch);
  }

  private updatePageLocal(patch: Record<string, unknown>): void {
    const current = this.page();
    if (!current) return;
    this.pushHistory();
    this.page.set({ ...current, data: { ...current.data, ...patch } });
    this.persistDraft();
  }

  private updateWidgetLocal(widgetId: string, patch: Record<string, unknown>): void {
    this.pushHistory();
    this.widgets.update(list =>
      list.map(w => (w.id === widgetId ? { ...w, data: { ...w.data, ...patch } } : w)),
    );
    this.persistDraft();
  }

  // ── Parameters (dashboard_parameter) — this page's "Global Filters".
  // CRUD here commits immediately (not draft-batched).

  readonly parameters = signal<EntityRecord[]>([]);
  /** Names only, for the widget inspector's binding-source picker
   * (Dashboard 10/10 Phase 5.A) — a `source: 'parameter'` binding's `name`
   * must be one of these. */
  readonly declaredParameterNames = computed(() =>
    this.parameters().map(p => String(p.data['name'] ?? '')).filter(n => n.length > 0));

  private loadParameters(): void {
    const pageId = this.effectivePageId();
    if (!pageId) return;
    this.svc.list('dashboard_parameter', {
      filters: [{ field: 'page_id', op: 'eq', value: pageId }],
      sorts:   [{ field: 'name', dir: 'asc' }],
      limit:   100,
    }).subscribe({
      next: res => this.parameters.set(res.data),
      error: () => this.parameters.set([]),
    });
  }

  addParameter(): void {
    const pageId = this.effectivePageId();
    const dashboardId = this.effectiveDashboardId();
    if (!pageId || !dashboardId) return;
    this.svc.create('dashboard_parameter', {
      page_id: pageId,
      dashboard_id: dashboardId,
      name: this.lang.translate('pageEditor.newFilterName'),
      parameter_type: 'text',
    }).subscribe({
      next: () => this.loadParameters(),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  updateParameterField(paramId: string, field: string, value: unknown): void {
    const p = this.parameters().find(x => x.id === paramId);
    if (!p) return;
    this.svc.update('dashboard_parameter', paramId, { [field]: value }, p.row_version).subscribe({
      next: () => this.loadParameters(),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  deleteParameter(paramId: string): void {
    this.svc.delete('dashboard_parameter', paramId).subscribe({
      next: () => this.parameters.update(list => list.filter(p => p.id !== paramId)),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  // ── Grid canvas ──────────────────────────────────────────────────────────

  private readonly gridEl = viewChild<ElementRef<HTMLElement>>('gridEl');
  private resizeObserver: ResizeObserver | null = null;

  // The single source of grid geometry, written once per real resize.
  readonly gridMetrics = signal<GridMetrics>(computeGridMetrics(1200));

  readonly activeDragWidgetId   = signal<string | null>(null);
  readonly activeResizeWidgetId = signal<string | null>(null);
  readonly previewLayout        = signal<Map<string, WidgetRect> | null>(null);
  readonly gridGhost            = signal<GridGhost | null>(null);

  // Raw pixel deltas from the widget currently under the pointer.
  readonly liveDragDelta   = signal<{ dx: number; dy: number } | null>(null);
  readonly liveResizeDelta = signal<{ dx: number; dy: number } | null>(null);

  private moveOrigin: { col: number; row: number; colSpan: number; rowSpan: number } | null = null;
  private resizeOrigin: { col: number; row: number; colSpan: number; rowSpan: number } | null = null;

  private activeDragCleanup: (() => void) | null = null;
  private activeResizeCleanup: (() => void) | null = null;

  readonly gridStyle = computed<Record<string, string>>(() => {
    const preview = this.previewLayout();
    const ghost = this.gridGhost();
    const live: WidgetRect[] = [
      ...(preview ? [...preview.values()] : []),
      ...(ghost ? [{ id: ghost.widgetId, col: ghost.col, row: ghost.row, colSpan: ghost.colSpan, rowSpan: ghost.rowSpan }] : []),
    ];
    return canvasHeightStyle(widgetRects(this.widgets()), live, this.gridMetrics());
  });

  /** Per-widget inline CSS text, keyed by widget id. */
  readonly widgetStyleMap = computed<Map<string, string>>(() => {
    const metrics = this.gridMetrics();
    const preview = this.previewLayout();
    const dragId = this.activeDragWidgetId();
    const resizeId = this.activeResizeWidgetId();
    const dragDelta = this.liveDragDelta();
    const resizeDelta = this.liveResizeDelta();
    const map = new Map<string, string>();
    for (const rect of widgetRects(this.widgets())) {
      const isDrag = dragId === rect.id;
      const isResize = resizeId === rect.id;
      const base: WidgetRect =
        isDrag && this.moveOrigin ? { ...rect, col: this.moveOrigin.col, row: this.moveOrigin.row } :
        isResize && this.resizeOrigin ? { ...rect, col: this.resizeOrigin.col, row: this.resizeOrigin.row,
          colSpan: this.resizeOrigin.colSpan, rowSpan: this.resizeOrigin.rowSpan } :
        preview?.get(rect.id) ?? rect;
      map.set(rect.id, tileBoxStyle(base, metrics, {
        delta: isDrag ? dragDelta : isResize ? resizeDelta : null,
        resizing: isResize,
        active: isDrag || isResize,
      }));
    }
    return map;
  });

  ngAfterViewInit(): void {
    const el = this.gridEl()?.nativeElement;
    if (el && typeof ResizeObserver !== 'undefined') {
      this.resizeObserver = new ResizeObserver(entries => {
        for (const entry of entries) {
          if (entry.contentRect.width > 0) {
            this.gridMetrics.set(computeGridMetrics(entry.contentRect.width));
          }
        }
      });
      this.resizeObserver.observe(el);
      if (el.clientWidth > 0) {
        this.gridMetrics.set(computeGridMetrics(el.clientWidth));
      }
    }
  }

  ngOnDestroy(): void {
    this.resizeObserver?.disconnect();
    this.resizeObserver = null;
    this.activeDragCleanup?.();
    this.activeDragCleanup = null;
    this.activeResizeCleanup?.();
    this.activeResizeCleanup = null;
  }

  /** Wires a pointer gesture: `onMove(dx, dy)` fires on every move with the
   * raw delta from `ev`'s own start position, `onEnd()` fires once on
   * pointerup/pointercancel. Returns the teardown. */
  private trackPointer(ev: PointerEvent, onMove: (dx: number, dy: number) => void, onEnd: () => void): () => void {
    const startX = ev.clientX;
    const startY = ev.clientY;
    const move = (e: PointerEvent) => onMove(e.clientX - startX, e.clientY - startY);
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      window.removeEventListener('pointercancel', up);
      onEnd();
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up, { once: true });
    window.addEventListener('pointercancel', up, { once: true });
    return up;
  }

  // ── Drag & Move ──────────────────────────────────────────────────────────

  /** `(pointerdown)` handler on a tile's own header. */
  startDrag(ev: PointerEvent, widget: EntityRecord): void {
    if (ev.button !== 0) return;
    const target = ev.target as HTMLElement;
    if (target.closest('button') || target.closest('.xpe-tile-actions') || target.closest('.xpe-handle-se')) return;
    ev.preventDefault();
    ev.stopPropagation();
    this.selectWidget(widget.id);

    let dragInitiated = false;
    this.activeDragCleanup = this.trackPointer(ev,
      (dx, dy) => {
        // Require at least 4px movement before drag activates.
        if (!dragInitiated) {
          if (Math.hypot(dx, dy) < 4) return;
          dragInitiated = true;
          this.onWidgetDragStart(widget);
        }
        this.onWidgetDragMove(widget, dx, dy);
      },
      () => {
        this.activeDragCleanup = null;
        if (dragInitiated) this.onWidgetDragEnd(widget.id);
      },
    );
  }

  private onWidgetDragStart(widget: EntityRecord): void {
    this.activeDragWidgetId.set(widget.id);
    const [rect] = widgetRects([widget]);
    this.moveOrigin = rect;
    this.gridGhost.set({ widgetId: widget.id, col: rect.col, row: rect.row, colSpan: rect.colSpan, rowSpan: rect.rowSpan });
    this.liveDragDelta.set({ dx: 0, dy: 0 });
  }

  private onWidgetDragMove(widget: EntityRecord, dx: number, dy: number): void {
    if (!this.moveOrigin) return;
    this.liveDragDelta.set({ dx, dy });
    const metrics = this.gridMetrics();
    const { col, row } = dragTarget(this.moveOrigin, { dx, dy }, metrics);

    const rects = widgetRects(this.widgets()).map(r =>
      r.id === widget.id ? { ...r, col, row, colSpan: this.moveOrigin!.colSpan, rowSpan: this.moveOrigin!.rowSpan } : r);
    const layoutMap = new Map(resolveCollisions(rects, widget.id, metrics.columns).map(item => [item.id, item]));

    this.previewLayout.set(layoutMap);
    this.gridGhost.set({ widgetId: widget.id, col, row, colSpan: this.moveOrigin.colSpan, rowSpan: this.moveOrigin.rowSpan });
  }

  private onWidgetDragEnd(widgetId: string): void {
    this.activeDragWidgetId.set(null);
    const layout = this.previewLayout();
    const ghost = this.gridGhost();
    this.gridGhost.set(null);
    this.previewLayout.set(null);
    this.liveDragDelta.set(null);

    if (layout) {
      this.applyLocalPositionCommits(diffLayout(widgetRects(this.widgets()), layout, ['col', 'row']));
    } else if (ghost && ghost.widgetId === widgetId) {
      this.applyLocalPositionCommits([{ widgetId, patch: { grid_col: ghost.col, grid_row: ghost.row } }]);
    }
    this.moveOrigin = null;
  }

  // ── Resize ───────────────────────────────────────────────────────────────

  /** `(pointerdown)` handler on a tile's own resize handle. */
  startResize(ev: PointerEvent, widget: EntityRecord): void {
    if (ev.button !== 0) return;
    ev.preventDefault();
    ev.stopPropagation();
    this.selectWidget(widget.id);
    this.onWidgetResizeStart(widget);
    this.activeResizeCleanup = this.trackPointer(ev,
      (dx, dy) => this.onWidgetResizeMove(widget, dx, dy),
      () => { this.activeResizeCleanup = null; this.onWidgetResizeEnd(widget.id); },
    );
  }

  private onWidgetResizeStart(widget: EntityRecord): void {
    this.activeResizeWidgetId.set(widget.id);
    const [rect] = widgetRects([widget]);
    this.resizeOrigin = rect;
    this.gridGhost.set({ widgetId: widget.id, col: rect.col, row: rect.row, colSpan: rect.colSpan, rowSpan: rect.rowSpan });
    this.liveResizeDelta.set({ dx: 0, dy: 0 });
  }

  private onWidgetResizeMove(widget: EntityRecord, dx: number, dy: number): void {
    if (!this.resizeOrigin) return;
    this.liveResizeDelta.set({ dx, dy });
    const metrics = this.gridMetrics();
    const resized = applyResize(
      { id: widget.id, col: this.resizeOrigin.col, row: this.resizeOrigin.row,
        colSpan: this.resizeOrigin.colSpan, rowSpan: this.resizeOrigin.rowSpan },
      dx, dy, metrics,
    );

    const rects = widgetRects(this.widgets()).map(r =>
      r.id === widget.id ? { ...r, colSpan: resized.colSpan, rowSpan: resized.rowSpan } : r);
    const layoutMap = new Map(resolveCollisions(rects, widget.id, metrics.columns).map(item => [item.id, item]));

    this.previewLayout.set(layoutMap);
    this.gridGhost.set({
      widgetId: widget.id, col: this.resizeOrigin.col, row: this.resizeOrigin.row,
      colSpan: resized.colSpan, rowSpan: resized.rowSpan,
    });
  }

  private onWidgetResizeEnd(widgetId: string): void {
    this.activeResizeWidgetId.set(null);
    const layout = this.previewLayout();
    const ghost = this.gridGhost();
    this.gridGhost.set(null);
    this.previewLayout.set(null);
    this.liveResizeDelta.set(null);

    if (layout) {
      this.applyLocalPositionCommits(diffLayout(widgetRects(this.widgets()), layout, ['col', 'row', 'colSpan', 'rowSpan']));
    } else if (ghost && ghost.widgetId === widgetId) {
      this.applyLocalPositionCommits([{
        widgetId, patch: { grid_col_span: ghost.colSpan, grid_row_span: ghost.rowSpan },
      }]);
    }
    this.resizeOrigin = null;
  }

  // ── Keyboard move/resize + copy/paste (Dashboard 10/10 Phases 5.B/5.D) ──
  // Bound to the tile's own `(keydown)`, not `window:keydown` — scoped to
  // when a tile has focus, so typing in the inspector's fields (a sibling
  // subtree) never triggers it. One grid unit per press; Shift resizes
  // instead of moving. Reuses the same resolveCollisions/diffLayout/
  // applyLocalPositionCommits pipeline the pointer drag/resize handlers use
  // above, so a keyboard move gets the same collision and undo behavior.
  // Ctrl/Cmd+C/V copy and paste the whole current selection, not just the
  // focused tile.

  onTileKeydown(ev: KeyboardEvent, widget: EntityRecord): void {
    if (this.previewMode()) return;
    if ((ev.ctrlKey || ev.metaKey) && (ev.key === 'c' || ev.key === 'C')) {
      ev.preventDefault();
      this.onCopySelectedWidgets();
      return;
    }
    if ((ev.ctrlKey || ev.metaKey) && (ev.key === 'v' || ev.key === 'V')) {
      ev.preventDefault();
      this.onPasteClipboardWidgets();
      return;
    }
    const resizing = ev.shiftKey;
    let dCol = 0, dRow = 0, dColSpan = 0, dRowSpan = 0;
    switch (ev.key) {
      case 'ArrowLeft':  if (resizing) dColSpan = -1; else dCol = -1; break;
      case 'ArrowRight': if (resizing) dColSpan = 1;  else dCol = 1;  break;
      case 'ArrowUp':    if (resizing) dRowSpan = -1; else dRow = -1; break;
      case 'ArrowDown':  if (resizing) dRowSpan = 1;  else dRow = 1;  break;
      default: return;
    }
    ev.preventDefault();
    ev.stopPropagation();

    const metrics = this.gridMetrics();
    const [rect] = widgetRects([widget]);
    const colSpan = Math.max(1, rect.colSpan + dColSpan);
    const rowSpan = Math.max(1, rect.rowSpan + dRowSpan);
    const col = Math.max(0, Math.min(rect.col + dCol, metrics.columns - colSpan));
    const row = Math.max(0, rect.row + dRow);

    const rects = widgetRects(this.widgets()).map(r =>
      r.id === widget.id ? { ...r, col, row, colSpan, rowSpan } : r);
    const layout = new Map(resolveCollisions(rects, widget.id, metrics.columns).map(item => [item.id, item]));
    const fields: (keyof Omit<WidgetRect, 'id'>)[] = resizing ? ['col', 'row', 'colSpan', 'rowSpan'] : ['col', 'row'];
    this.applyLocalPositionCommits(diffLayout(widgetRects(this.widgets()), layout, fields));
  }

  gridGhostStyle(ghost: GridGhost): Record<string, string> {
    const { cellW, cellH, gap } = this.gridMetrics();
    return {
      position: 'absolute',
      left:   `${ghost.col * (cellW + gap)}px`,
      top:    `${ghost.row * (cellH + gap)}px`,
      width:  `${ghost.colSpan * cellW + (ghost.colSpan - 1) * gap}px`,
      height: `${ghost.rowSpan * cellH + (ghost.rowSpan - 1) * gap}px`,
      zIndex: '10',
    };
  }

  // ── Drag a widget type from the palette onto the canvas ─────────────────
  // Native HTML5 drag-and-drop (not the pointer-event move/resize system
  // above) — a palette card has no existing grid position to glue a
  // transform to. Reuses `gridGhost`, sentinel-keyed '__new__'.

  private static readonly NEW_WIDGET_GHOST_ID = '__new__';
  private draggedPaletteTypeId: string | null = null;

  onPaletteDragStart(typeId: string): void {
    this.draggedPaletteTypeId = typeId;
  }

  onPaletteDragEnd(): void {
    this.draggedPaletteTypeId = null;
    this.gridGhost.set(null);
  }

  onCanvasDragOver(ev: DragEvent): void {
    if (!this.draggedPaletteTypeId) return;
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = 'copy';
    const { col, row } = this.dropPositionFromEvent(ev);
    this.gridGhost.set({
      widgetId: PageEditorComponent.NEW_WIDGET_GHOST_ID, col, row,
      colSpan: NEW_WIDGET_COL_SPAN, rowSpan: NEW_WIDGET_ROW_SPAN,
    });
  }

  onCanvasDragLeave(ev: DragEvent): void {
    // Fires when moving between the grid's own children too — only clear
    // the ghost once the pointer has genuinely left the grid container.
    const grid = this.gridEl()?.nativeElement;
    const related = ev.relatedTarget as Node | null;
    if (grid && related && grid.contains(related)) return;
    if (this.gridGhost()?.widgetId === PageEditorComponent.NEW_WIDGET_GHOST_ID) {
      this.gridGhost.set(null);
    }
  }

  onCanvasDrop(ev: DragEvent): void {
    ev.preventDefault();
    const typeId = ev.dataTransfer?.getData('text/plain') || this.draggedPaletteTypeId;
    this.draggedPaletteTypeId = null;
    this.gridGhost.set(null);
    if (!typeId) return;
    const { col, row } = this.dropPositionFromEvent(ev);
    this.onAddWidget(typeId, col, row);
    this.paletteOpen.set(false);
  }

  /** Cursor position -> the grid cell for the dropped widget's top-left
   * corner (`widget-palette` pins the drag image's corner to the cursor). */
  private dropPositionFromEvent(ev: DragEvent): { col: number; row: number } {
    const grid = this.gridEl()?.nativeElement;
    if (!grid) return { col: 0, row: 0 };
    const rect = grid.getBoundingClientRect();
    return snapToGridClamped(
      { x: ev.clientX - rect.left, y: ev.clientY - rect.top },
      this.gridMetrics(), NEW_WIDGET_COL_SPAN,
    );
  }

  // ── Page/widget data ─────────────────────────────────────────────────────

  /** Fields of the selected widget's structured-definition source entity
   * (`config.data.source`), for the inspector's data panel. */
  readonly fieldOptions = signal<ChartFieldOption[]>([]);

  /** The selected widget's source entity, compared by value so an unrelated
   * config edit never re-fetches the schema. */
  private readonly selectionSource = computed(() => {
    const raw = this.selectedWidget()?.data['config'];
    if (typeof raw !== 'string' || !raw.trim()) return null;
    try {
      const source = (JSON.parse(raw) as { data?: { source?: unknown } })?.data?.source;
      return typeof source === 'string' && source ? source : null;
    } catch {
      return null;
    }
  });

  constructor() {
    this.dashboardApi.widgetTypes().subscribe({
      next: types => this.widgetTypes.set(types),
      error: () => this.widgetTypes.set([]),
    });
    this.loadViews();

    // `switchMap` cancels the previous selection's lookup, so a slow schema
    // response for a widget no longer selected never overwrites the current
    // one's fields; `takeUntilDestroyed` tears it down with the editor.
    toObservable(this.selectionSource).pipe(
      switchMap(entity => entity
        ? this.svc.getSchema(entity).pipe(
            map(schema => {
              const options = schema.fields.map((f): ChartFieldOption => ({
                name: f.name,
                label: f.display_name,
                is_date: f.field_type === 'date',
                is_numeric: f.field_type === 'number' || f.field_type === 'currency',
              }));
              // The system timestamps every table carries: the usual time axis.
              for (const [name, key] of [['created_at', 'pageEditor.fieldCreatedOn'], ['modified_at', 'pageEditor.fieldModifiedOn']]) {
                if (!options.some(o => o.name === name)) {
                  options.push({ name, label: this.lang.translate(key), is_date: true, is_numeric: false });
                }
              }
              return options;
            }),
            catchError(() => of([] as ChartFieldOption[])),
          )
        : of([] as ChartFieldOption[])),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(options => this.fieldOptions.set(options));
  }

  ngOnInit(): void {
    this.load();
  }

  private load(): void {
    const pageId = this.effectivePageId();
    if (!pageId) {
      // Not an error — `needsPageCreation` drives the inline prompt instead.
      this.loading.set(false);
      return;
    }
    this.dashboardApi.loadPageWidgets(pageId).subscribe({
      next: tree => {
        if (!tree.dashboardId) {
          this.loadError.set(this.lang.translate('pageEditor.noDashboard'));
          this.loading.set(false);
          return;
        }
        this.loadedDashboardId.set(tree.dashboardId);
        this.page.set(tree.page);
        this.savedPageSnapshot.set(tree.page);
        this.rootSectionId.set(tree.rootSectionId);
        this.needsRootSection.set(tree.needsRootSection);
        this.widgets.set(tree.widgets);
        this.savedWidgetsSnapshot.set(tree.widgets);
        this.clearDraftHistory();
        this.loading.set(false);
        this.recoverableDraft.set(this.readStoredDraft(pageId));
        this.loadParameters();
      },
      error: (e: ApiError) => { this.loadError.set(e.message); this.loading.set(false); },
    });
  }

  /** Provisions the missing root section (D-527) — an explicit action, never
   * a side effect of loading. */
  repairRootSection(): void {
    const dashboardId = this.effectiveDashboardId();
    const pageId = this.effectivePageId();
    if (!dashboardId || !pageId || this.repairingRootSection()) return;
    this.repairingRootSection.set(true);
    this.dashboardApi.repairRootSection(dashboardId, pageId).subscribe({
      next: res => {
        this.repairingRootSection.set(false);
        this.rootSectionId.set(res.id);
        this.needsRootSection.set(false);
      },
      error: (e: ApiError) => {
        this.repairingRootSection.set(false);
        this.error.set(e.message);
      },
    });
  }

  /** Dashboard 10/10 Phase 5.C. No `event` (plain Enter activation, or a
   * programmatic call) selects just `id`. Ctrl/Cmd+Click toggles `id` in the
   * set. Shift+Click selects the contiguous range, in canvas order, between
   * the last plain-selected widget and `id`. */
  selectWidget(id: string, event?: MouseEvent): void {
    this.paletteOpen.set(false);
    this.configErrors.set([]);

    if (event?.shiftKey && this.lastSelectedWidgetId) {
      const ids = this.widgets().map(w => w.id);
      const from = ids.indexOf(this.lastSelectedWidgetId);
      const to = ids.indexOf(id);
      if (from !== -1 && to !== -1) {
        const [start, end] = from <= to ? [from, to] : [to, from];
        this.selectedWidgetIds.set(new Set(ids.slice(start, end + 1)));
        return;
      }
    }

    if (event?.ctrlKey || event?.metaKey) {
      const next = new Set(this.selectedWidgetIds());
      if (next.has(id)) next.delete(id); else next.add(id);
      this.selectedWidgetIds.set(next);
      this.lastSelectedWidgetId = id;
      return;
    }

    this.selectedWidgetIds.set(new Set([id]));
    this.lastSelectedWidgetId = id;
  }

  /** Toggles `id` in the selection without affecting anything else — the
   * tile checkbox's handler, independent of click-modifier semantics. */
  toggleWidgetSelected(id: string, selected: boolean): void {
    const next = new Set(this.selectedWidgetIds());
    if (selected) next.add(id); else next.delete(id);
    this.selectedWidgetIds.set(next);
    this.lastSelectedWidgetId = id;
  }

  clearWidgetSelection(): void {
    this.selectedWidgetIds.set(new Set());
    this.lastSelectedWidgetId = null;
    this.configErrors.set([]);
  }

  onAddWidget(typeId: string, col?: number, row?: number): void {
    const sectionId = this.rootSectionId();
    if (!sectionId) return;
    const existing = this.widgets();
    const nextRow = existing.reduce(
      (max, w) => Math.max(max, Number(w.data['grid_row'] ?? 0) + Number(w.data['grid_row_span'] ?? 1)), 0);

    this.svc.create('dashboard_widget', {
      section_id: sectionId,
      widget_type: typeId,
      sequence: existing.length * 10,
      is_visible: true,
      grid_col: col ?? 0,
      grid_row: row ?? nextRow,
      grid_col_span: NEW_WIDGET_COL_SPAN,
      grid_row_span: NEW_WIDGET_ROW_SPAN,
    }).subscribe({
      next: rec => {
        this.mergeCreatedWidget(rec);
        this.paletteOpen.set(false);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Merges one server-created widget into the draft and the saved snapshot
   * as an undoable step — never a reload, never a history clear, so every
   * other pending edit stays saveable. */
  private mergeCreatedWidget(rec: EntityRecordResponse): void {
    const widget = toWidgetRecord(rec);
    this.pushHistory();
    this.widgets.update(list => [...list, widget]);
    this.savedWidgetsSnapshot.update(list => [...list, widget]);
    this.selectWidget(widget.id);
    this.persistDraft();
  }

  private patchLocalWidget(widgetId: string, dataPatch: Record<string, unknown>, rowVersion?: number): void {
    this.widgets.update(list =>
      list.map(w =>
        w.id === widgetId
          ? { ...w, data: { ...w.data, ...dataPatch }, ...(rowVersion !== undefined ? { row_version: rowVersion } : {}) }
          : w
      )
    );
  }

  /** Applies a drag/resize gesture's computed position(s) to the draft only —
   * one undo step for the whole gesture. */
  private applyLocalPositionCommits(commits: WidgetPositionCommit[]): void {
    if (commits.length === 0) return;
    this.pushHistory();
    this.widgets.update(list =>
      list.map(w => {
        const c = commits.find(x => x.widgetId === w.id);
        return c ? { ...w, data: { ...w.data, ...c.patch } } : w;
      }),
    );
    this.persistDraft();
  }

  onDuplicateWidgetId(widgetId: string): void {
    this.dashboardApi.duplicateWidget(widgetId).pipe(
      switchMap(res => this.svc.get('dashboard_widget', res.id)),
    ).subscribe({
      next: rec => this.mergeCreatedWidget(rec),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Duplicates every selected widget — each is its own server round trip
   * (`dashboardApi.duplicateWidget`), same as the single-widget action. */
  onDuplicateSelectedWidget(): void {
    for (const id of this.selectedWidgetIds()) this.onDuplicateWidgetId(id);
  }

  // ── Copy/paste (Dashboard 10/10 Phase 5.D) ───────────────────────────────
  // The clipboard holds ids, not a data snapshot — paste re-reads each
  // source widget's current state through the same `duplicateWidget` round
  // trip "Duplicate" already uses (server-side copy, choice/required-field
  // validation, its own `row_version`), rather than a second bulk-create
  // path. A source widget deleted between copy and paste is simply skipped
  // (the server 404s that one `duplicateWidget` call; the rest still land).

  private clipboardWidgetIds: readonly string[] = [];

  onCopySelectedWidgets(): void {
    this.clipboardWidgetIds = Array.from(this.selectedWidgetIds());
  }

  onPasteClipboardWidgets(): void {
    const ids = this.clipboardWidgetIds;
    if (ids.length === 0) return;
    forkJoin(
      ids.map(id => this.dashboardApi.duplicateWidget(id).pipe(
        switchMap(res => this.svc.get('dashboard_widget', res.id)),
        catchError(() => of(null)),
      )),
    ).subscribe(results => {
      const pasted = results.filter((r): r is EntityRecordResponse => r !== null).map(toWidgetRecord);
      if (pasted.length === 0) return;
      this.pushHistory();
      this.widgets.update(list => [...list, ...pasted]);
      this.savedWidgetsSnapshot.update(list => [...list, ...pasted]);
      this.selectedWidgetIds.set(new Set(pasted.map(w => w.id)));
      this.lastSelectedWidgetId = pasted.at(-1)!.id;
      this.persistDraft();
    });
  }

  /** Deleting is a draft edit: the widget leaves the canvas now, undo brings
   * it back, and Save removes it on the server. */
  async onDeleteWidgetId(widgetId: string): Promise<void> {
    const ok = await this.dialogService.confirm({
      title: this.lang.translate('pageEditor.deleteWidgetConfirmTitle'),
      message: this.lang.translate('pageEditor.deleteWidgetConfirmMessage'),
      variant: 'danger',
      confirmText: this.lang.translate('pageEditor.delete'),
    });
    if (!ok) return;

    this.pushHistory();
    this.widgets.update(list => list.filter(w => w.id !== widgetId));
    if (this.selectedWidgetIds().has(widgetId)) {
      const next = new Set(this.selectedWidgetIds());
      next.delete(widgetId);
      this.selectedWidgetIds.set(next);
    }
    this.persistDraft();
  }

  /** One confirm dialog for the whole selection, then one draft edit/undo
   * step removing all of them together. */
  async onDeleteSelectedWidget(): Promise<void> {
    const ids = Array.from(this.selectedWidgetIds());
    if (ids.length === 0) return;
    const ok = await this.dialogService.confirm({
      title: this.lang.translate('pageEditor.deleteWidgetConfirmTitle'),
      message: this.lang.translate('pageEditor.deleteWidgetConfirmMessage'),
      variant: 'danger',
      confirmText: this.lang.translate('pageEditor.delete'),
    });
    if (!ok) return;

    this.pushHistory();
    const idSet = new Set(ids);
    this.widgets.update(list => list.filter(w => !idSet.has(w.id)));
    this.selectedWidgetIds.set(new Set());
    this.persistDraft();
  }

  goBack(): void {
    const dashboardId = this.effectiveDashboardId();
    if (dashboardId) {
      void this.router.navigate(entityFormRoute('attome_dashboard'), { queryParams: { id: dashboardId } });
    } else {
      void this.router.navigate(entityListRoute('dashboard_page'));
    }
  }
}
