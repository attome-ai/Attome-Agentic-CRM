import { DOCUMENT } from '@angular/common';
import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, effect, inject, input, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router, RouterLink } from '@angular/router';
import { Subject, catchError, map, of, switchMap } from 'rxjs';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityRecordResponse, EntityService, entityFormRoute } from '@attome/xrm/core/entity';
import {
  DashboardParameter, DashboardService, DashboardTree, DashboardVariableBusService, PageWidgetResult,
  PublishedState, PublishedView, WidgetInputs,
} from '@attome/xrm/dashboard/data';
import { DashboardSectionViewComponent } from '../dashboard-section-view/dashboard-section-view.component';

/** A page's `settings.refresh_interval_minutes`, or 0 (no auto-refresh). */
export function refreshIntervalMinutes(page: EntityRecord | undefined): number {
  const raw = page?.data['settings'];
  if (typeof raw !== 'string' || !raw.trim()) return 0;
  try {
    const minutes = Number((JSON.parse(raw) as { refresh_interval_minutes?: unknown }).refresh_interval_minutes);
    return Number.isFinite(minutes) && minutes >= 1 ? Math.floor(minutes) : 0;
  } catch {
    return 0;
  }
}

/** How often the "updated" text and the staleness check re-evaluate. */
const CLOCK_TICK_MS = 30_000;

const PARAMETER_TYPES = new Set(['date_range', 'choice', 'text', 'number', 'entity_lookup']);

/** A draft `dashboard_parameter` row in the declaration shape. */
function rowToParameter(row: EntityRecord): DashboardParameter {
  const text = (value: unknown): string | null => typeof value === 'string' ? value : null;
  const type = String(row.data['parameter_type'] ?? 'text');
  return {
    id: row.id,
    name: String(row.data['name'] ?? ''),
    name_ar: text(row.data['name_ar']),
    page_id: text(row.data['page_id']),
    parameter_type: (PARAMETER_TYPES.has(type) ? type : 'text') as DashboardParameter['parameter_type'],
    default_value: text(row.data['default_value']),
  };
}

/**
 * Read-only rendering of an `attome_dashboard` — `/xrm/dashboard/view?id=…`.
 *
 * **What it renders (D-521, Dashboard 10/10 Phase 1.3).** By default the
 * dashboard's *published* snapshot (`GET .../published`): the immutable
 * version viewers see. A dashboard with nothing live shows a not-published
 * state. The working copy renders only in
 * the explicit draft preview (`?draft=1`), which reads the editor-only tree
 * route.
 *
 * **Where the numbers come from (Phase 2, D-522).** Nowhere in the browser:
 * each page loads its widgets' data in one `POST .../pages/{id}/data` request,
 * and the filter bar sends parameter *values* — typed by each parameter's
 * declared type — never filters. A newer page request cancels an older one.
 *
 * **Cross-filtering.** The variable bus is provided here, per viewer, so one
 * dashboard's selections never leak into the next. A widget re-queries itself
 * when a variable it listens to changes; a page reload carries the bus's
 * current values so a parameter change keeps active cross-filters.
 *
 * **Refresh (Phase 4.3).** A page whose settings set
 * `refresh_interval_minutes` reloads its data on that interval while the tab
 * is visible, and at once when a hidden tab becomes visible overdue. A
 * refresh keeps the current numbers on screen until the new ones arrive; a
 * failed refresh keeps them and says so. The header shows when the data was
 * loaded and marks it stale once two intervals pass without a successful
 * load. "Refresh" reloads on demand.
 *
 * This is **not** the anonymous public/embed surface — every request here is
 * an ordinary authenticated session.
 */
@Component({
  selector:   'attome-dashboard-viewer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [RouterLink, DashboardSectionViewComponent, TranslatePipe],
  providers:  [DashboardVariableBusService],
  styleUrls:  ['../../../styles/xrm-form.css', './dashboard-viewer.component.css'],
  templateUrl: './dashboard-viewer.component.html',
})
export class DashboardViewerComponent implements OnInit {
  private readonly svc          = inject(EntityService);
  private readonly dashboardApi = inject(DashboardService);
  private readonly router       = inject(Router);
  private readonly lang         = inject(LangService);
  private readonly bus          = inject(DashboardVariableBusService);
  private readonly destroyRef   = inject(DestroyRef);
  private readonly document     = inject(DOCUMENT);

  /** Bound from `?id=` via `withComponentInputBinding()`. */
  readonly id = input<string | null>(null);

  /** True when nested inside another record's form. */
  readonly embedded = input(false);

  /** `?draft=1` — the editor's "Preview draft". */
  readonly draft = input<string | boolean | null>(null);
  readonly draftPreview = computed(() => {
    const value = this.draft();
    return value === true || value === '1' || value === 'true';
  });

  readonly loading   = signal(true);
  readonly error     = signal<string | null>(null);
  readonly dashboard = signal<EntityRecordResponse | null>(null);

  /** `null` in draft preview; otherwise what `GET .../published` reported. */
  readonly publishedState = signal<PublishedState | null>(null);
  readonly versionNumber  = signal<number | null>(null);

  readonly pages          = signal<EntityRecord[]>([]);
  readonly selectedPageId = signal<string | null>(null);

  private readonly allSections         = signal<EntityRecord[]>([]);
  private readonly allWidgetsBySection = signal<ReadonlyMap<string, EntityRecord[]>>(new Map());

  readonly sections = computed(() =>
    this.allSections().filter(s => s.data['page_id'] === this.selectedPageId()));
  readonly widgetsBySection = this.allWidgetsBySection;

  // ── Filter bar ───────────────────────────────────────────────────────────
  /** The declarations of the executed definition: the published snapshot's,
   * or the draft's rows in preview. */
  readonly parameters = signal<DashboardParameter[]>([]);
  /** Keyed by parameter name; a `date_range` parameter uses two keys,
   * `{name}__from`/`{name}__to`. */
  readonly filterValues = signal<Record<string, string>>({});

  readonly visibleParameters = computed(() =>
    this.parameters().filter(p => p.page_id == null || p.page_id === this.selectedPageId()));

  /** What reaches the server: one value per set parameter, typed by its
   * declaration. An unset parameter is omitted, so its declared default
   * applies on the server. A half-filled date range is omitted too. */
  readonly parameterValues = computed<Record<string, unknown>>(() => {
    const values = this.filterValues();
    const out: Record<string, unknown> = {};
    for (const p of this.visibleParameters()) {
      if (p.parameter_type === 'date_range') {
        const start = values[`${p.name}__from`];
        const end   = values[`${p.name}__to`];
        if (start && end) out[p.name] = { start, end };
      } else {
        const value = values[p.name];
        if (value) out[p.name] = value;
      }
    }
    return out;
  });

  /** Page-batch results for the selected page, by widget id; `null` while
   * loading. */
  readonly results = signal<ReadonlyMap<string, PageWidgetResult> | null>(null);
  readonly dataError = signal<string | null>(null);
  private readonly pageRequests = new Subject<{ dashboardId: string; pageId: string; inputs: WidgetInputs; background: boolean }>();

  // ── Refresh ──────────────────────────────────────────────────────────────
  /** When the selected page's data last loaded successfully. */
  readonly loadedAt = signal<Date | null>(null);
  readonly refreshing = signal(false);
  /** A background refresh failed; the previous numbers are still shown. */
  readonly refreshFailed = signal(false);
  /** A coarse clock for the "updated" text and staleness. */
  readonly now = signal(Date.now());

  readonly selectedPage = computed(() => this.pages().find(p => p.id === this.selectedPageId()));
  readonly refreshMinutes = computed(() => refreshIntervalMinutes(this.selectedPage()));

  /** Two refresh intervals without a successful load. */
  readonly stale = computed(() => {
    const minutes = this.refreshMinutes();
    const loaded = this.loadedAt();
    return minutes > 0 && !!loaded && this.now() - loaded.getTime() > 2 * minutes * 60_000;
  });

  readonly loadedAtText = computed(() => {
    const loaded = this.loadedAt();
    return loaded ? loaded.toLocaleTimeString(this.lang.intlLocale(), { hour: '2-digit', minute: '2-digit' }) : '';
  });

  constructor() {
    this.pageRequests.pipe(
      switchMap(({ dashboardId, pageId, inputs, background }) =>
        this.dashboardApi.pageData(dashboardId, pageId, inputs).pipe(
          map(res => ({ ok: true as const, res, background })),
          catchError((e: ApiError) => of({ ok: false as const, message: e.message, background })),
        )),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(outcome => {
      this.refreshing.set(false);
      if (outcome.ok) {
        this.dataError.set(null);
        this.refreshFailed.set(false);
        this.results.set(new Map(outcome.res.widgets.map(w => [w.widget_id, w])));
        this.loadedAt.set(new Date());
        this.now.set(Date.now());
      } else if (outcome.background && this.results() !== null) {
        this.refreshFailed.set(true);
      } else {
        this.dataError.set(outcome.message);
        this.results.set(new Map());
      }
    });

    // The page's refresh interval, re-armed when the page or its interval changes.
    effect(onCleanup => {
      const minutes = this.refreshMinutes();
      if (minutes <= 0 || !this.selectedPageId()) return;
      const timer = setInterval(() => {
        if (this.document.visibilityState !== 'hidden') this.refresh();
      }, minutes * 60_000);
      const onVisible = (): void => {
        const loaded = this.loadedAt();
        if (this.document.visibilityState === 'visible' && loaded && Date.now() - loaded.getTime() >= minutes * 60_000) {
          this.refresh();
        }
      };
      this.document.addEventListener('visibilitychange', onVisible);
      onCleanup(() => {
        clearInterval(timer);
        this.document.removeEventListener('visibilitychange', onVisible);
      });
    });

    const clock = setInterval(() => this.now.set(Date.now()), CLOCK_TICK_MS);
    this.destroyRef.onDestroy(() => clearInterval(clock));
  }

  /** Reloads the selected page's data, keeping the current numbers on screen. */
  refresh(): void {
    this.loadPageData(true);
  }

  setFilterValue(key: string, value: string): void {
    this.filterValues.update(v => ({ ...v, [key]: value }));
    this.loadPageData();
  }

  parameterLabel(p: DashboardParameter): string {
    return (this.lang.current() === 'ar' && p.name_ar) ? p.name_ar : p.name;
  }

  ngOnInit(): void {
    const id = this.id();
    if (!id) {
      this.error.set(this.lang.translate('dashboard.viewer.noDashboardIdGiven'));
      this.loading.set(false);
      return;
    }
    if (this.draftPreview()) {
      this.dashboardApi.loadTree(id).subscribe({
        next: tree => {
          this.showTree(tree);
          this.loadDraftParameters(id);
        },
        error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
      });
      return;
    }
    this.dashboardApi.loadPublished(id).subscribe({
      next: (published: PublishedView) => {
        this.publishedState.set(published.state);
        this.versionNumber.set(published.versionNumber);
        this.parameters.set(published.parameters);
        if (!published.tree) {
          this.loading.set(false);
          return;
        }
        this.showTree(published.tree);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  private showTree(tree: DashboardTree): void {
    this.dashboard.set(tree.dashboard);
    this.pages.set(tree.pages);
    this.allSections.set(tree.sections);
    this.allWidgetsBySection.set(tree.widgetsBySection);
    this.loading.set(false);
    if (tree.pages.length > 0) this.selectPage(tree.pages[0].id);
  }

  /** Draft preview only: the working copy's parameter rows (the published
   * path reads the snapshot's declarations instead). */
  private loadDraftParameters(id: string): void {
    this.svc.list('dashboard_parameter', {
      filters: [{ field: 'dashboard_id', op: 'eq', value: id }],
      limit:   100,
    }).subscribe({
      next: res => this.parameters.set(res.data.map(rowToParameter)),
      error: () => { /* Non-fatal: the page still renders with declared defaults. */ },
    });
  }

  /** One request for every widget on the selected page. A background load
   * keeps the current results until the new ones arrive. */
  private loadPageData(background = false): void {
    const dashboardId = this.id();
    const pageId = this.selectedPageId();
    if (!dashboardId || !pageId) return;
    const keep = background && this.results() !== null;
    if (keep) {
      this.refreshing.set(true);
    } else {
      this.results.set(null);
      this.loadedAt.set(null);
      this.refreshFailed.set(false);
    }
    const crossFilters: Record<string, unknown> = {};
    for (const [name, value] of this.bus.values()) {
      if (value !== undefined && value !== null) crossFilters[name] = String(value);
    }
    this.pageRequests.next({
      dashboardId,
      pageId,
      inputs: { parameters: this.parameterValues(), cross_filters: crossFilters, preview: this.draftPreview() },
      background: keep,
    });
  }

  editLink(): string[] {
    return entityFormRoute('attome_dashboard');
  }

  /** Switches the tab client-side and loads that page's data. */
  selectPage(pageId: string): void {
    this.selectedPageId.set(pageId);
    this.loadPageData();
  }

  /** One responsive page grid; nested legacy sections are flattened into it. */
  readonly canvasSection = computed(() => {
    const pageSections = this.sections();
    const root = pageSections.find(s => s.data['parent_section_id'] == null) ?? pageSections[0];
    return root ? { ...root, data: { ...root.data, section_type: 'container', layout_mode: 'grid' } } : null;
  });

  cancel(): void {
    this.router.navigate(entityFormRoute('attome_dashboard'), { queryParams: { id: this.id() } });
  }
}
