import {
  ChangeDetectionStrategy, Component, DestroyRef, InjectionToken, Type, computed, effect, inject, input, signal,
  untracked,
} from '@angular/core';
import { NgComponentOutlet, NgTemplateOutlet } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router } from '@angular/router';
import { filter } from 'rxjs';
import { TranslatePipe } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';
import { EntityListComponent, entityFormRoute } from '@attome/xrm/core/entity';
import {
  CalendarViewComponent, KanbanBoardComponent, MapViewComponent, SplitViewComponent, TimelineViewComponent,
} from '@attome/xrm/core/entity/views';
import { AvailableView, ViewAdminService, ViewKind } from '@attome/xrm/core/query/data';

/** The view kinds this page can render. `chart` is drawn by
 * `@attome/xrm/dashboard/chart`'s `ChartViewComponent`, loaded on demand. */
export type RenderedViewKind = ViewKind;
export const RENDERED_VIEW_KINDS: readonly RenderedViewKind[] = ['list', 'kanban', 'calendar', 'timeline', 'chart', 'map'];

const KIND_ICONS: Record<RenderedViewKind, string> = {
  list:     'las la-list',
  kanban:   'las la-columns',
  calendar: 'las la-calendar-alt',
  timeline: 'las la-stream',
  chart:    'las la-chart-bar',
  map:      'las la-globe',
};

function renderedKind(kind: ViewKind | undefined): RenderedViewKind {
  return kind ?? 'list';
}

/** Loads the chart renderer's entry point — a separate lazy chunk, fetched
 * the first time a chart view is shown. */
export type ChartViewLoader = () => Promise<Type<unknown>>;
export const loadChartView: ChartViewLoader = () =>
  import('@attome/xrm/dashboard/chart').then(m => m.ChartViewComponent);
/** The chart renderer's loader; replaced in specs. */
export const CHART_VIEW_LOADER = new InjectionToken<ChartViewLoader>('CHART_VIEW_LOADER', {
  providedIn: 'root',
  factory: () => loadChartView,
});

/**
 * U13/M64 — the entity list route. The selected view (URL `?view=<id>`, the
 * same query parameter `EntityListComponent` already reads and writes) picks
 * the renderer: `kind = list` → `EntityListComponent`, `kanban` →
 * `KanbanBoardComponent`, `calendar`/`timeline` likewise. The view-kind
 * switcher offers only the kinds for which this entity actually has a view,
 * and switching writes that kind's (default, else first) view id to the URL,
 * so reload, back/forward and shared links all land on the same renderer.
 *
 * Resolution mirrors `EntityListComponent.loadAvailableViews` exactly
 * (requested id → `is_default` → first), so when the selected view is a list
 * the list is given no `initialViewId` and resolves the same view itself.
 */
@Component({
  selector:   'attome-metadata-list-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [
    EntityListComponent, KanbanBoardComponent, CalendarViewComponent, TimelineViewComponent, MapViewComponent,
    SplitViewComponent, NgComponentOutlet, NgTemplateOutlet, TranslatePipe,
  ],
  templateUrl: './entity-list-page.component.html',
  styleUrl:    './entity-list-page.component.css',
})
export class EntityListPageComponent {
  private readonly router     = inject(Router);
  private readonly viewSvc    = inject(ViewAdminService);
  private readonly destroyRef = inject(DestroyRef);

  readonly name = input('');
  /** A13-T3: a list view shown as a split view (records beside the selected one). */
  readonly split = signal(false);

  /** `null` while the entity's views are loading. */
  readonly views     = signal<AvailableView[] | null>(null);
  readonly urlViewId = signal<string | null>(null);
  /** The views spinner, held back 300 ms: a fast load goes straight to the
   * list instead of flashing "Loading…" first. */
  readonly showViewsLoading = signal(false);
  private readonly viewsLoadingDelay = effect(onCleanup => {
    if (this.views() !== null) { this.showViewsLoading.set(false); return; }
    const timer = setTimeout(() => this.showViewsLoading.set(true), 300);
    onCleanup(() => clearTimeout(timer));
  });

  readonly selectedView = computed<AvailableView | null>(() => {
    const views = this.views();
    if (!views) return null;
    const requested = this.urlViewId();
    return (requested ? views.find(v => v.id === requested) : undefined)
      ?? views.find(v => v.is_default)
      ?? views[0]
      ?? null;
  });

  readonly activeKind = computed<RenderedViewKind>(() => renderedKind(this.selectedView()?.kind));

  /** Kinds this entity has at least one view of, in a stable order. */
  readonly availableKinds = computed<RenderedViewKind[]>(() => {
    const present = new Set((this.views() ?? []).map(v => renderedKind(v.kind)));
    return RENDERED_VIEW_KINDS.filter(k => present.has(k));
  });

  /** Views of the active non-list kind, for that kind's own view picker (the
   * list keeps its existing picker). */
  readonly kindViews = computed<AvailableView[]>(() => {
    const kind = this.activeKind();
    return (this.views() ?? []).filter(v => renderedKind(v.kind) === kind);
  });

  /** The list's own picker offers only list views; the other kinds are
   * reached through the kind switcher. */
  readonly listPickerKinds: readonly ViewKind[] = ['list'];

  /** `ChartViewComponent`, once its chunk has loaded. */
  readonly chartViewComponent = signal<Type<unknown> | null>(null);
  readonly chartLoadFailed    = signal(false);
  private readonly chartViewLoader = inject(CHART_VIEW_LOADER);

  constructor() {
    this.urlViewId.set(this.readViewParam());
    this.router.events.pipe(
      filter((e): e is NavigationEnd => e instanceof NavigationEnd),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(() => this.urlViewId.set(this.readViewParam()));

    effect(() => {
      const entity = this.name();
      untracked(() => this.loadViews(entity));
    });

    effect(() => {
      if (this.activeKind() !== 'chart' || this.chartViewComponent()) return;
      untracked(() => {
        this.chartViewLoader().then(
          component => this.chartViewComponent.set(component),
          () => this.chartLoadFailed.set(true),
        );
      });
    });
  }

  kindIcon(kind: RenderedViewKind): string { return KIND_ICONS[kind]; }

  private loadViews(entity: string): void {
    this.views.set(null);
    if (!entity) return;
    this.viewSvc.listAvailable(entity).subscribe({
      next: views => { if (entity === this.name()) this.views.set(views); },
      // The list component reports the load failure itself; an empty view set
      // renders as `list`, which keeps that behaviour.
      error: () => { if (entity === this.name()) this.views.set([]); },
    });
  }

  private readViewParam(): string | null {
    return this.router.parseUrl(this.router.url).queryParamMap.get('view');
  }

  selectKind(kind: RenderedViewKind): void {
    if (kind === this.activeKind()) return;
    const candidates = (this.views() ?? []).filter(v => renderedKind(v.kind) === kind);
    const target = candidates.find(v => v.is_default) ?? candidates[0];
    if (target) this.selectView(target.id);
  }

  selectView(viewId: string): void {
    if (!viewId || viewId === this.selectedView()?.id) return;
    const urlTree = this.router.parseUrl(this.router.url);
    urlTree.queryParams['view'] = viewId;
    this.urlViewId.set(viewId);
    void this.router.navigateByUrl(urlTree);
  }

  /** A27-T4: a chosen record type opens the new form with it preset. */
  onCreate(recordType: string | null = null): void {
    const route = entityFormRoute(this.name());
    if (recordType) this.router.navigate(route, { queryParams: { record_type: recordType } });
    else this.router.navigate(route);
  }

  onEdit(record: EntityRecord): void {
    this.onEditId(record.id);
  }

  onEditId(id: string): void {
    this.router.navigate(entityFormRoute(this.name()), {
      queryParams: { id },
    });
  }
}
