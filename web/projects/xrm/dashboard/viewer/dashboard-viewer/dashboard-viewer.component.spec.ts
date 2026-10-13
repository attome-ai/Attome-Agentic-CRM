import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Subject, of, throwError } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityRecordResponse, EntityService } from '@attome/xrm/core/entity';
import {
  DashboardParameter, DashboardService, DashboardTree, PageDataResponse, PublishedState, PublishedView,
} from '@attome/xrm/dashboard/data';
import { DashboardViewerComponent, refreshIntervalMinutes } from './dashboard-viewer.component';

// Covers:
//   1. page tabs render from the loaded tree,
//   2. D-521 — viewers read the published snapshot, `none` is shown as such,
//      and only the explicit draft preview reads the tree,
//   3. Phase 2.4 — one page-data request per page, parameter VALUES typed by
//      their declaration (never filters), and a newer page request cancels an
//      older one.

function dashboardRecord(id: string, name: string): EntityRecordResponse {
  return {
    id,
    entity_id: 'attome_dashboard',
    data: { name, dashboard_type: 'team' },
    row_version: 0,
  };
}

function page(id: string, name: string, settings?: Record<string, unknown>): EntityRecord {
  return {
    id,
    entity_id: 'dashboard_page',
    data: settings ? { name, settings: JSON.stringify(settings) } : { name },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    row_version: 0,
  };
}

function parameter(
  name: string,
  parameterType: DashboardParameter['parameter_type'] = 'text',
  pageId: string | null = null,
): DashboardParameter {
  return { id: `param-${name}`, name, name_ar: null, page_id: pageId, parameter_type: parameterType, default_value: null };
}

function treeOf(pages: EntityRecord[]): DashboardTree {
  return { dashboard: dashboardRecord('d1', 'Sales Overview'), pages, sections: [], widgetsBySection: new Map() };
}

function publishedView(
  tree: DashboardTree | null,
  state: PublishedState = 'published',
  parameters: DashboardParameter[] = [],
): PublishedView {
  return {
    state,
    versionId: state === 'published' ? 'ver-1' : null,
    versionNumber: state === 'published' ? 1 : null,
    tree: state === 'none' ? null : tree,
    parameters,
  };
}

function pageResponse(pageId: string): PageDataResponse {
  return { page_id: pageId, definition_source: 'published', published_version_number: 1, widgets: [] };
}

function setup(options: {
  pages?: EntityRecord[];
  parameters?: DashboardParameter[];
  state?: PublishedState;
  draft?: string;
  pageData?: ReturnType<typeof vi.fn>;
} = {}): {
  fixture: ComponentFixture<DashboardViewerComponent>;
  loadTreeSpy: ReturnType<typeof vi.fn>;
  loadPublishedSpy: ReturnType<typeof vi.fn>;
  pageDataSpy: ReturnType<typeof vi.fn>;
} {
  const tree = treeOf(options.pages ?? []);
  const listSpy = vi.fn(() => of({ data: [], meta: { total: 0, limit: 100, offset: 0 } }));
  const loadTreeSpy = vi.fn(() => of(tree));
  const loadPublishedSpy = vi.fn(() => of(publishedView(tree, options.state, options.parameters)));
  const pageDataSpy = options.pageData ?? vi.fn((_: string, pageId: string) => of(pageResponse(pageId)));

  TestBed.configureTestingModule({
    imports: [DashboardViewerComponent],
    providers: [
      // A real (empty) router, not a mocked `Router` — `[routerLink]` on
      // the Edit link needs a live `ActivatedRoute` to resolve at all.
      provideRouter([]),
      { provide: LangService, useValue: { translate: (key: string) => key, current: () => 'en', intlLocale: () => 'en-US' } },
      { provide: EntityService, useValue: { list: listSpy } },
      {
        provide: DashboardService,
        useValue: { loadTree: loadTreeSpy, loadPublished: loadPublishedSpy, pageData: pageDataSpy },
      },
    ],
  });

  const fixture = TestBed.createComponent(DashboardViewerComponent);
  fixture.componentRef.setInput('id', 'd1');
  if (options.draft !== undefined) fixture.componentRef.setInput('draft', options.draft);
  fixture.detectChanges();
  return { fixture, loadTreeSpy, loadPublishedSpy, pageDataSpy };
}

describe('DashboardViewerComponent', () => {
  describe('page tabs render from the loaded tree', () => {
    it('renders one tab per page and selects the first', () => {
      const { fixture } = setup({ pages: [page('p1', 'Overview'), page('p2', 'Details')] });

      expect(fixture.componentInstance.pages().map(p => p.id)).toEqual(['p1', 'p2']);
      expect(fixture.componentInstance.selectedPageId()).toBe('p1');

      const tabs = fixture.nativeElement.querySelectorAll('.xdv-page-tab');
      expect(tabs.length).toBe(2);
      expect(tabs[0].textContent.trim()).toBe('Overview');
      expect(tabs[1].textContent.trim()).toBe('Details');
    });

    it('renders no tab strip at all for a single-page dashboard', () => {
      const { fixture } = setup({ pages: [page('p1', 'Overview')] });

      expect(fixture.nativeElement.querySelector('.xdv-page-tabs')).toBeNull();
    });

    it('selectPage switches the active tab client-side and loads that page\'s data', () => {
      const { fixture, pageDataSpy } = setup({ pages: [page('p1', 'Overview'), page('p2', 'Details')] });

      fixture.componentInstance.selectPage('p2');
      fixture.detectChanges();

      expect(fixture.componentInstance.selectedPageId()).toBe('p2');
      const activeTab = fixture.nativeElement.querySelector('.xdv-page-tab-active');
      expect(activeTab.textContent.trim()).toBe('Details');
      expect(pageDataSpy).toHaveBeenLastCalledWith('d1', 'p2', { parameters: {}, cross_filters: {}, preview: false });
    });

    it('shows the empty-dashboard message when the tree has no pages at all', () => {
      const { fixture } = setup({ pages: [] });

      // The stubbed `LangService` echoes the translation key back.
      expect(fixture.nativeElement.textContent).toContain('dashboard.viewer.noPagesYet');
    });
  });

  describe('published snapshot (D-521)', () => {
    it('reads the published route, never the editor-only tree', () => {
      const { loadTreeSpy, loadPublishedSpy } = setup({ pages: [page('p1', 'Overview')] });

      expect(loadPublishedSpy).toHaveBeenCalledWith('d1');
      expect(loadTreeSpy).not.toHaveBeenCalled();
    });

    it('loads the first page\'s widget data in one request, never per widget', () => {
      const { pageDataSpy } = setup({ pages: [page('p1', 'Overview')] });

      expect(pageDataSpy).toHaveBeenCalledTimes(1);
      expect(pageDataSpy).toHaveBeenCalledWith('d1', 'p1', { parameters: {}, cross_filters: {}, preview: false });
    });

    it('shows a not-published state when nothing is live', () => {
      const { fixture } = setup({ state: 'none' });

      expect(fixture.nativeElement.textContent).toContain('dashboard.viewer.notPublished');
      expect(fixture.nativeElement.querySelector('.xdv-page-tabs')).toBeNull();
    });

    it('draft preview reads the tree and asks for preview data', () => {
      const { fixture, loadTreeSpy, loadPublishedSpy, pageDataSpy } = setup({ pages: [page('p1', 'Overview')], draft: '1' });

      expect(loadTreeSpy).toHaveBeenCalledWith('d1');
      expect(loadPublishedSpy).not.toHaveBeenCalled();
      expect(pageDataSpy.mock.calls[0][2].preview).toBe(true);
      expect(fixture.nativeElement.querySelector('.xdv-draft-banner')).not.toBeNull();
    });
  });

  describe('filter bar sends typed parameter values (Phase 2.4)', () => {
    it('renders the published declarations, typed by parameter type', () => {
      const { fixture } = setup({
        pages: [page('p1', 'Overview')],
        parameters: [parameter('region'), parameter('amount', 'number'), parameter('period', 'date_range')],
      });
      const el = fixture.nativeElement as HTMLElement;
      expect(el.querySelector('.xdv-filter-bar')).not.toBeNull();
      expect(el.querySelectorAll('input[type="number"]').length).toBe(1);
      expect(el.querySelectorAll('input[type="date"]').length).toBe(2);
    });

    it('sends a value, never a filter, and a date range only once both ends are set', () => {
      const { fixture, pageDataSpy } = setup({
        pages: [page('p1', 'Overview')],
        parameters: [parameter('region'), parameter('period', 'date_range')],
      });
      const viewer = fixture.componentInstance;

      viewer.setFilterValue('region', 'North');
      expect(pageDataSpy.mock.lastCall![2].parameters).toEqual({ region: 'North' });

      viewer.setFilterValue('period__from', '2026-01-01');
      expect(pageDataSpy.mock.lastCall![2].parameters).toEqual({ region: 'North' });

      viewer.setFilterValue('period__to', '2026-01-31');
      expect(pageDataSpy.mock.lastCall![2].parameters).toEqual({
        region: 'North', period: { start: '2026-01-01', end: '2026-01-31' },
      });
    });

    it('a page-scoped parameter only applies on its own page', () => {
      const { fixture } = setup({
        pages: [page('p1', 'Overview'), page('p2', 'Details')],
        parameters: [parameter('stage', 'text', 'p2')],
      });
      expect(fixture.componentInstance.visibleParameters()).toEqual([]);
      fixture.componentInstance.selectPage('p2');
      expect(fixture.componentInstance.visibleParameters().map(p => p.name)).toEqual(['stage']);
    });

    it('a newer page request supersedes an older, slower one', () => {
      const responses: Subject<PageDataResponse>[] = [];
      const pageData = vi.fn(() => {
        const next = new Subject<PageDataResponse>();
        responses.push(next);
        return next;
      });
      const { fixture } = setup({ pages: [page('p1', 'Overview')], parameters: [parameter('region')], pageData });

      fixture.componentInstance.setFilterValue('region', 'North');
      const newer = pageResponse('p1');
      newer.widgets = [{ widget_id: 'w-new' }];
      responses[1].next(newer);
      const stale = pageResponse('p1');
      stale.widgets = [{ widget_id: 'w-stale' }];
      responses[0].next(stale);

      expect([...fixture.componentInstance.results()!.keys()]).toEqual(['w-new']);
    });

    it('the filter bar only renders when at least one parameter is visible', () => {
      const { fixture } = setup({ pages: [page('p1', 'Overview')], parameters: [] });

      expect(fixture.nativeElement.querySelector('.xdv-filter-bar')).toBeNull();
    });
  });

  describe('refresh policy and freshness (Phase 4.3)', () => {
    afterEach(() => vi.useRealTimers());

    it('reads refresh_interval_minutes from the page settings, ignoring junk', () => {
      expect(refreshIntervalMinutes(page('p', 'P', { refresh_interval_minutes: 5 }))).toBe(5);
      expect(refreshIntervalMinutes(page('p', 'P', { refresh_interval_minutes: 0 }))).toBe(0);
      expect(refreshIntervalMinutes(page('p', 'P'))).toBe(0);
      expect(refreshIntervalMinutes({ ...page('p', 'P'), data: { settings: '{not json' } })).toBe(0);
    });

    it('reloads on the interval while visible and keeps the numbers on screen meanwhile', () => {
      vi.useFakeTimers();
      const pending: Subject<PageDataResponse>[] = [];
      const pageData = vi.fn(() => {
        const next = new Subject<PageDataResponse>();
        pending.push(next);
        return next;
      });
      const { fixture } = setup({ pages: [page('p1', 'Overview', { refresh_interval_minutes: 5 })], pageData });
      const viewer = fixture.componentInstance;
      const first = pageResponse('p1');
      first.widgets = [{ widget_id: 'w1' }];
      pending[0].next(first);
      expect(viewer.loadedAt()).not.toBeNull();

      TestBed.flushEffects();
      vi.advanceTimersByTime(5 * 60_000);
      expect(pageData).toHaveBeenCalledTimes(2);
      expect(viewer.refreshing()).toBe(true);
      expect([...viewer.results()!.keys()]).toEqual(['w1']);
    });

    it('a failed refresh keeps the previous numbers and says so; two intervals without data is stale', () => {
      vi.useFakeTimers();
      let call = 0;
      const pageData = vi.fn((_: string, pageId: string) => (call++ === 0
        ? of({ ...pageResponse(pageId), widgets: [{ widget_id: 'w1' }] })
        : throwError(() => ({ message: 'down' }))));
      const { fixture } = setup({ pages: [page('p1', 'Overview', { refresh_interval_minutes: 1 })], pageData });
      const viewer = fixture.componentInstance;

      viewer.refresh();
      expect(viewer.refreshFailed()).toBe(true);
      expect(viewer.dataError()).toBeNull();
      expect([...viewer.results()!.keys()]).toEqual(['w1']);

      expect(viewer.stale()).toBe(false);
      viewer.now.set(Date.now() + 3 * 60_000);
      expect(viewer.stale()).toBe(true);
      fixture.detectChanges();
      expect(fixture.nativeElement.querySelector('.xdv-freshness-stale')).not.toBeNull();
    });

    it('a page without an interval never polls but can be refreshed by hand', () => {
      vi.useFakeTimers();
      const { fixture, pageDataSpy } = setup({ pages: [page('p1', 'Overview')] });
      TestBed.flushEffects();
      vi.advanceTimersByTime(60 * 60_000);
      expect(pageDataSpy).toHaveBeenCalledTimes(1);
      fixture.detectChanges();
      fixture.nativeElement.querySelector('.xdv-freshness button').click();
      expect(pageDataSpy).toHaveBeenCalledTimes(2);
      expect(fixture.componentInstance.stale()).toBe(false);
    });
  });
});
