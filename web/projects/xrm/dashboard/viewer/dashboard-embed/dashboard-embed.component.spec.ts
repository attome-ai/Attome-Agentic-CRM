import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { EntityRecord } from '@attome/xrm';
import { EntityRecordResponse, EntityService } from '@attome/xrm/core/entity';
import { DashboardService, PublishedView } from '@attome/xrm/dashboard/data';
import { DashboardEmbedComponent } from './dashboard-embed.component';

// R-16 (M26-dashboard-remediation) — this component's first spec. Covers:
//   1. the id-based lookup path (`dashboardId` input — no query at all),
//   2. the tag-based lookup path (`tags` input, via `tag_item`), and
//   3. the empty-state card R-10 added (neither input resolves a dashboard).

/** R-19: `tag_item` has no `name` column — a tag is a `(category_id, entity_name, record_id)`
 * join, and the label lives on `tag_category.name`. The old fixture invented a `name` here,
 * which is what let the broken lookup ship. */
function tagItem(id: string, recordId: string, categoryId = 'cat-sales'): EntityRecord {
  return {
    id,
    entity_id: 'tag_item',
    data: { entity_name: 'attome_dashboard', category_id: categoryId, record_id: recordId },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    row_version: 0,
  };
}

/** The label half of a tag — `tag_category` is where a tag NAME actually lives. */
function tagCategory(id: string, name: string): EntityRecord {
  return {
    id,
    entity_id: 'tag_category',
    data: { name },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    row_version: 0,
  };
}

function dashboardResponse(id: string, name: string): EntityRecordResponse {
  return { id, entity_id: 'attome_dashboard', data: { name, dashboard_type: 'team' }, row_version: 0 };
}

/** D-521: the embedded viewer reads what viewers see — the published route. */
const emptyPublished = (id: string): PublishedView => ({
  state: 'published',
  versionId: 'ver-1',
  versionNumber: 1,
  tree: { dashboard: dashboardResponse(id, 'Whatever'), pages: [], sections: [], widgetsBySection: new Map() },
  parameters: [],
});

function setup(options: {
  dashboardId?: string | null;
  tags?: string[];
  listImpl?: (entity: string, params: unknown) => ReturnType<EntityService['list']>;
  getImpl?: (entity: string, id: string) => ReturnType<EntityService['get']>;
} = {}): {
  fixture: ComponentFixture<DashboardEmbedComponent>;
  loadTreeSpy: ReturnType<typeof vi.fn>;
} {
  const loadTreeSpy = vi.fn((id: string) => of(emptyPublished(id)));

  const defaultList = () => of({ data: [] as EntityRecord[], meta: { total: 0, limit: 50, offset: 0 } });
  const defaultGet = (entity: string, id: string) => of(dashboardResponse(id, 'Fallback'));

  TestBed.configureTestingModule({
    imports: [DashboardEmbedComponent],
    providers: [
      // A real (empty) router — the empty-state card's `[routerLink]` (and
      // the mounted `attome-dashboard-viewer`'s own Edit link, when it renders
      // non-embedded) needs a live `ActivatedRoute` to resolve at all.
      provideRouter([]),
      { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      provideAttomeI18n(), provideXrmI18n(),
      {
        provide: EntityService,
        useValue: {
          list: vi.fn(options.listImpl ?? defaultList),
          get: vi.fn(options.getImpl ?? defaultGet),
        },
      },
      {
        provide: DashboardService,
        // Named `loadTreeSpy` in this suite for history; it stands in for
        // `loadPublished`, which is what the mounted viewer calls.
        useValue: { loadPublished: loadTreeSpy, pageData: vi.fn(() => of({ page_id: '', definition_source: 'published', widgets: [] })) },
      },
    ],
  });

  const fixture = TestBed.createComponent(DashboardEmbedComponent);
  if (options.dashboardId !== undefined) fixture.componentRef.setInput('dashboardId', options.dashboardId);
  if (options.tags !== undefined) fixture.componentRef.setInput('tags', options.tags);
  fixture.detectChanges();
  return { fixture, loadTreeSpy };
}

describe('DashboardEmbedComponent', () => {
  describe('id-based lookup path', () => {
    it('renders the named dashboard directly, with no tag/entity query at all', () => {
      const listImpl = vi.fn(() => of({ data: [], meta: { total: 0, limit: 50, offset: 0 } }));
      const { fixture, loadTreeSpy } = setup({ dashboardId: 'd1', listImpl });

      expect(fixture.componentInstance.selectedId()).toBe('d1');
      expect(fixture.componentInstance.emptyState()).toBe(false);
      // The embed component's own lookup query never ran — the child
      // DashboardViewerComponent's own dashboard_parameter list is the
      // only `list` call this path makes.
      expect(listImpl).not.toHaveBeenCalledWith('tag_item', expect.anything());
      expect(loadTreeSpy).toHaveBeenCalledWith('d1');
      expect(fixture.nativeElement.querySelector('attome-dashboard-viewer')).not.toBeNull();
    });

    it('never shows the multi-match picker for a direct id', () => {
      const { fixture } = setup({ dashboardId: 'd1' });

      expect(fixture.nativeElement.querySelector('.xde-picker')).toBeNull();
    });
  });

  describe('tag-based lookup path', () => {
    /** A `list` mock that answers the real three-table tag join: a category named `tagName`,
     * then the join rows. `attome_dashboard` is deliberately never `list`ed by this path (R-19). */
    function tagListImpl(tagName: string, items: EntityRecord[]) {
      return vi.fn((entity: string) => {
        if (entity === 'tag_category') {
          return of({
            data: tagName ? [tagCategory('cat-sales', tagName)] : [],
            meta: { total: tagName ? 1 : 0, limit: 50, offset: 0 },
          });
        }
        if (entity === 'tag_item') {
          return of({ data: items, meta: { total: items.length, limit: 50, offset: 0 } });
        }
        return of({ data: [], meta: { total: 0, limit: 50, offset: 0 } });
      });
    }

    it('resolves a tag name through tag_category -> tag_item and renders it, no picker', () => {
      const listImpl = tagListImpl('sales', [tagItem('t1', 'd1')]);
      const getImpl = vi.fn((_entity: string, id: string) => of(dashboardResponse(id, 'Sales Overview')));
      const { fixture, loadTreeSpy } = setup({ tags: ['sales'], listImpl, getImpl });

      expect(fixture.componentInstance.matches().map(m => m.id)).toEqual(['d1']);
      expect(fixture.componentInstance.selectedId()).toBe('d1');
      expect(fixture.componentInstance.emptyState()).toBe(false);
      expect(loadTreeSpy).toHaveBeenCalledWith('d1');
      expect(fixture.nativeElement.querySelector('.xde-picker')).toBeNull();

      // The category is looked up by its real `name` column...
      expect(listImpl).toHaveBeenCalledWith('tag_category', expect.objectContaining({
        filters: [{ field: 'name', op: 'eq', value: 'sales' }],
      }));
      // ...and the join is filtered by the real columns (no invented `name` on tag_item).
      expect(listImpl).toHaveBeenCalledWith('tag_item', expect.objectContaining({
        filters: [
          { field: 'entity_name', op: 'eq', value: 'attome_dashboard' },
          { field: 'category_id', op: 'eq', value: 'cat-sales' },
        ],
      }));
      // R-19 regression guard: the dead `attome_dashboard.tags` fallback must never run.
      expect(listImpl).not.toHaveBeenCalledWith('attome_dashboard', expect.anything());
    });

    it('resolves multiple tag matches into a picker, defaulting to the first', () => {
      const listImpl = tagListImpl('sales', [tagItem('t1', 'd1'), tagItem('t2', 'd2')]);
      const getImpl = vi.fn((_entity: string, id: string) => of(dashboardResponse(id, `Dashboard ${id}`)));
      const { fixture } = setup({ tags: ['sales'], listImpl, getImpl });

      expect(fixture.componentInstance.matches().map(m => m.id)).toEqual(['d1', 'd2']);
      expect(fixture.componentInstance.selectedId()).toBe('d1');
      const options = fixture.nativeElement.querySelectorAll('.xde-picker-select option');
      expect(options.length).toBe(2);

      fixture.componentInstance.selectDashboard('d2');
      fixture.detectChanges();
      expect(fixture.componentInstance.selectedId()).toBe('d2');
    });

    it('de-duplicates a dashboard tagged with the same category more than once', () => {
      const listImpl = tagListImpl('sales', [tagItem('t1', 'd1'), tagItem('t2', 'd1')]);
      const getImpl = vi.fn((_entity: string, id: string) => of(dashboardResponse(id, 'Once')));
      const { fixture } = setup({ tags: ['sales'], listImpl, getImpl });

      expect(fixture.componentInstance.matches().map(m => m.id)).toEqual(['d1']);
    });

    it('a tag naming no category lands in the empty state, not an error', () => {
      const listImpl = tagListImpl('', []);
      const { fixture } = setup({ tags: ['nonexistent-tag'], listImpl });

      expect(fixture.componentInstance.emptyState()).toBe(true);
      expect(fixture.componentInstance.error()).toBeNull();
    });

    it('no matches for any tag lands in the empty state, not an error', () => {
      const listImpl = vi.fn(() => of({ data: [], meta: { total: 0, limit: 50, offset: 0 } }));
      const { fixture } = setup({ tags: ['nonexistent-tag'], listImpl });

      expect(fixture.componentInstance.emptyState()).toBe(true);
      expect(fixture.componentInstance.error()).toBeNull();
    });
  });

  describe('empty state (R-10)', () => {
    it('shows the empty-state card when neither dashboardId nor tags resolve anything', () => {
      const { fixture } = setup({ dashboardId: null, tags: [] });

      expect(fixture.componentInstance.emptyState()).toBe(true);
      const card = fixture.nativeElement.querySelector('.xde-empty-state');
      expect(card).not.toBeNull();
      expect(card.querySelector('a[href]')).not.toBeNull();
    });

    it('the empty state is not rendered when a dashboardId is given', () => {
      const { fixture } = setup({ dashboardId: 'd1' });

      expect(fixture.nativeElement.querySelector('.xde-empty-state')).toBeNull();
    });
  });
});
