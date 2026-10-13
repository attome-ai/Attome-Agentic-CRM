import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DashboardService, DashboardTree, PageWidgetTree, PublishedView } from './dashboard.service';

/**
 * Runs `DashboardService` against a real `EntityService` (only the HTTP
 * transport is mocked via `HttpTestingController`). `httpMock.verify()` after
 * every test proves no request beyond the ones each test expects was issued —
 * in particular that no read path provisions a section (D-527) and the tree
 * loads in one call (D-520).
 */
describe('DashboardService', () => {
  let service: DashboardService;
  let httpMock: HttpTestingController;

  const API = 'http://localhost:7865';

  const treeRecord = (id: string, data: Record<string, unknown> = {}, rowVersion = 0) => ({
    id, row_version: rowVersion, data: { id, ...data },
  });

  const draftTree = () => ({
    dashboard: treeRecord('dash-1', { name: 'Sales' }, 4),
    pages: [treeRecord('page-1', { dashboard_id: 'dash-1', name: 'Overview' }), treeRecord('page-2', { dashboard_id: 'dash-1' })],
    sections: [
      treeRecord('sec-1', { page_id: 'page-1', parent_section_id: null }),
      treeRecord('sec-2', { page_id: 'page-2', parent_section_id: null }),
    ],
    widgets: [
      treeRecord('w-2', { section_id: 'sec-1', sequence: 20 }, 7),
      treeRecord('w-1', { section_id: 'sec-1', sequence: 10 }),
      treeRecord('w-3', { section_id: 'sec-2', sequence: 0 }),
    ],
    pages_needing_root_section: [],
  });

  const pageRecord = (id: string, data: Record<string, unknown>) => ({
    id, entity_id: '', data, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', row_version: 0,
  });

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
        { provide: LangService, useValue: { intlLocale: () => 'en-US' } },
      ],
    });
    service = TestBed.inject(DashboardService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  describe('loadTree', () => {
    it('issues exactly one tree call and maps it into pages, sections and widgets by section', () => {
      let tree: DashboardTree | undefined;
      service.loadTree('dash-1').subscribe(t => (tree = t));

      const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/tree`);
      expect(req.request.method).toBe('GET');
      req.flush(draftTree());

      expect(tree!.dashboard.id).toBe('dash-1');
      expect(tree!.dashboard.row_version).toBe(4);
      expect(tree!.pages.map(p => p.id)).toEqual(['page-1', 'page-2']);
      expect(tree!.sections).toHaveLength(2);
      expect(tree!.widgetsBySection.get('sec-1')!.map(w => w.id)).toEqual(['w-1', 'w-2']);
      expect(tree!.widgetsBySection.get('sec-1')![1].row_version).toBe(7);
      expect(tree!.widgetsBySection.get('sec-2')!.map(w => w.id)).toEqual(['w-3']);
    });
  });

  describe('widget data (Phase 2.3)', () => {
    it('posts values only to the widget and page data routes', () => {
      service.widgetData('dash-1', 'w-1', { parameters: { stage: 'won' }, preview: true }).subscribe();
      const widgetReq = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/widgets/w-1/data`);
      expect(widgetReq.request.method).toBe('POST');
      expect(widgetReq.request.body).toEqual({ parameters: { stage: 'won' }, preview: true });
      widgetReq.flush({});

      service.pageData('dash-1', 'p-1', { cross_filters: { region: 'North' } }).subscribe();
      const pageReq = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/pages/p-1/data`);
      expect(pageReq.request.body).toEqual({ cross_filters: { region: 'North' } });
      pageReq.flush({ page_id: 'p-1', widgets: [] });
    });

    it('asks for unsupported widget types only when told to', () => {
      service.widgetTypes().subscribe();
      httpMock.expectOne(`${API}/api/v1/attome-dashboard/widget-types`).flush([]);
      service.widgetTypes(true).subscribe();
      httpMock.expectOne(`${API}/api/v1/attome-dashboard/widget-types?include_unsupported=true`).flush([]);
    });
  });

  describe('loadPublished', () => {
    it('maps a published snapshot into the tree shape and reads its parameter declarations', () => {
      let view: PublishedView | undefined;
      service.loadPublished('dash-1').subscribe(v => (view = v));

      httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/published`).flush({
        state: 'published',
        version_id: 'ver-2',
        version_number: 2,
        snapshot: {
          snapshot_format: 2,
          name: 'Sales',
          pages: [{
            id: 'p1', name: 'Overview',
            sections: [{
              id: 's1', breakpoints: [], widgets: [{ id: 'w1', query_id: 'q1', sequence: 0 }],
              children: [{ id: 's2', breakpoints: [], widgets: [{ id: 'w2', sequence: 0 }], children: [] }],
            }],
          }],
          dependencies: [{ widget_id: 'w1', view_id: null, query_id: 'q1', query_version_id: 'qv1' }],
          parameters: [
            { id: 'par1', page_id: null, name: 'stage', name_ar: null, parameter_type: 'choice', default_value: 'open' },
            { id: 'par2', page_id: 'p1', name: 'odd', parameter_type: 'unheard_of' },
          ],
        },
      });

      expect(view!.state).toBe('published');
      expect(view!.versionNumber).toBe(2);
      const tree = view!.tree!;
      expect(tree.dashboard.data['name']).toBe('Sales');
      expect(tree.dashboard.data['pages']).toBeUndefined();
      expect(tree.pages.map(p => p.id)).toEqual(['p1']);
      const s1 = tree.sections.find(s => s.id === 's1')!;
      const s2 = tree.sections.find(s => s.id === 's2')!;
      expect(s1.data).toMatchObject({ page_id: 'p1', parent_section_id: null });
      expect(s2.data).toMatchObject({ page_id: 'p1', parent_section_id: 's1' });
      expect(tree.widgetsBySection.get('s1')![0].data).toMatchObject({ id: 'w1', section_id: 's1' });
      expect(tree.widgetsBySection.get('s2')![0].id).toBe('w2');
      expect(tree.dashboard.data['parameters']).toBeUndefined();
      expect(view!.parameters).toEqual([
        { id: 'par1', page_id: null, name: 'stage', name_ar: null, parameter_type: 'choice', default_value: 'open' },
        { id: 'par2', page_id: 'p1', name: 'odd', name_ar: null, parameter_type: 'text', default_value: null },
      ]);
    });

    it('reports nothing to render for state none', () => {
      let view: PublishedView | undefined;
      service.loadPublished('dash-1').subscribe(v => (view = v));
      httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/published`).flush({ state: 'none' });
      expect(view!.state).toBe('none');
      expect(view!.tree).toBeNull();
    });
  });

  describe('loadPageWidgets', () => {
    it("reads the page's own sections and widgets through its dashboard's tree", () => {
      let result: PageWidgetTree | undefined;
      service.loadPageWidgets('page-1').subscribe(t => (result = t));

      httpMock.expectOne(`${API}/api/v1/dashboard_page/page-1`).flush(pageRecord('page-1', { dashboard_id: 'dash-1' }));
      httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/tree`).flush(draftTree());

      expect(result!.dashboardId).toBe('dash-1');
      expect(result!.rootSectionId).toBe('sec-1');
      expect(result!.needsRootSection).toBe(false);
      expect(result!.widgets.map(w => w.id)).toEqual(['w-1', 'w-2']);
    });

    it('reports a page with no section instead of provisioning one', () => {
      let result: PageWidgetTree | undefined;
      service.loadPageWidgets('page-3').subscribe(t => (result = t));

      httpMock.expectOne(`${API}/api/v1/dashboard_page/page-3`).flush(pageRecord('page-3', { dashboard_id: 'dash-1' }));
      httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/tree`).flush(draftTree());

      // `verify()` in afterEach proves no section create was issued.
      expect(result!.rootSectionId).toBeNull();
      expect(result!.needsRootSection).toBe(true);
      expect(result!.widgets).toEqual([]);
    });

    it('returns no dashboard for a page nothing owns, without a tree call', () => {
      let result: PageWidgetTree | undefined;
      service.loadPageWidgets('page-9').subscribe(t => (result = t));

      httpMock.expectOne(`${API}/api/v1/dashboard_page/page-9`).flush(pageRecord('page-9', {}));

      expect(result!.dashboardId).toBeNull();
    });
  });

  it('createPage posts the page fields to the pages route', () => {
    service.createPage('dash-1', { name: 'Details', sequence: 10, is_visible: true }).subscribe();
    const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/pages`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ name: 'Details', sequence: 10, is_visible: true });
    req.flush({ id: 'page-9', root_section_id: 'sec-9' });
  });

  it('repairRootSection posts to the root-section route', () => {
    service.repairRootSection('dash-1', 'page-3').subscribe();
    const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/pages/page-3/root-section`);
    expect(req.request.method).toBe('POST');
    req.flush({ id: 'sec-new' });
  });

  it('activateVersion posts row_version to the activate route', () => {
    service.activateVersion('dash-1', 'ver-1', 5).subscribe();
    const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/versions/ver-1/activate`);
    expect(req.request.body).toEqual({ row_version: 5 });
    req.flush({ id: 'dash-1', row_version: 6, approval_pending: false });
  });

  describe('transition', () => {
    it("posts publish's row_version in the JSON body — this route family has no If-Match support", () => {
      let response: unknown;
      service.transition('dash-1', 'publish', 7).subscribe(r => (response = r));

      const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/publish`);
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ row_version: 7 });
      expect(req.request.headers.has('If-Match')).toBe(false);

      req.flush({ id: 'dash-1', lifecycle_status: 'published', row_version: 8 });
      expect(response).toEqual({ id: 'dash-1', lifecycle_status: 'published', row_version: 8 });
    });

    it('start-revision uses the same body shape', () => {
      service.transition('dash-1', 'start-revision', 2).subscribe();
      const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/start-revision`);
      expect(req.request.body).toEqual({ row_version: 2 });
      req.flush({ id: 'dash-1', lifecycle_status: 'draft', row_version: 3 });
    });

    it('merges an extra body onto row_version for actions that take one', () => {
      service.transition('dash-1', 'archive', 3, { note: 'no longer needed' }).subscribe();

      const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/archive`);
      expect(req.request.body).toEqual({ row_version: 3, note: 'no longer needed' });
      req.flush({ id: 'dash-1', lifecycle_status: 'archived', row_version: 4 });
    });
  });

  it('clone posts with no body', () => {
    service.clone('dash-1').subscribe();
    const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/clone`);
    expect(req.request.body).toEqual({});
    req.flush({ id: 'dash-2' });
  });

  it('healthCheck GETs the health-check route', () => {
    service.healthCheck('dash-1').subscribe();
    const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/dash-1/health-check`);
    expect(req.request.method).toBe('GET');
    req.flush({ checked: 0, broken: [] });
  });

  it('widgetTypes GETs the widget-types route', () => {
    service.widgetTypes().subscribe();
    const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/widget-types`);
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('duplicateWidget posts widget_id and an optional target_section_id', () => {
    service.duplicateWidget('w-1', 'sec-2').subscribe();
    const req = httpMock.expectOne(`${API}/api/v1/attome-dashboard/widget/duplicate`);
    expect(req.request.body).toEqual({ widget_id: 'w-1', target_section_id: 'sec-2' });
    req.flush({ id: 'w-2' });
  });
});
