import { TestBed } from '@angular/core/testing';
import { DefaultUrlSerializer, NavigationEnd, Router, UrlTree } from '@angular/router';
import { Subject, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { EntityRecord } from '@attome/xrm';
import { AvailableView, ViewAdminService, ViewKind } from '@attome/xrm/core/query/data';
import { CHART_VIEW_LOADER, EntityListPageComponent } from './entity-list-page.component';

function view(id: string, kind: ViewKind, isDefault = false): AvailableView {
  return {
    id, name: id, icon: '', is_default: isDefault, kind, view_metadata: {},
    scope: 'system', is_mine: false,
  };
}

describe('EntityListPageComponent', () => {
  const serializer = new DefaultUrlSerializer();
  const navigate = vi.fn();
  const navigateByUrl = vi.fn();
  let events: Subject<unknown>;
  let url: string;
  let listAvailable: ReturnType<typeof vi.fn>;
  let loadChart: ReturnType<typeof vi.fn>;
  class FakeChartView {}

  beforeEach(() => {
    navigate.mockReset();
    navigateByUrl.mockReset();
    events = new Subject();
    url = '/xrm/entity/contact/list';
    listAvailable = vi.fn(() => of([] as AvailableView[]));
    loadChart = vi.fn(() => Promise.resolve(FakeChartView));
    const router = {
      navigate,
      navigateByUrl: (tree: UrlTree) => { navigateByUrl(serializer.serialize(tree)); },
      parseUrl: (value: string) => serializer.parse(value),
      events,
      get url() { return url; },
    };
    TestBed.configureTestingModule({
      imports: [EntityListPageComponent],
      providers: [
        { provide: Router, useValue: router },
        { provide: ViewAdminService, useValue: { listAvailable } },
        { provide: CHART_VIEW_LOADER, useValue: loadChart },
      ],
    });
    TestBed.overrideComponent(EntityListPageComponent, { set: { template: '' } });
  });

  function create(name = 'contact') {
    const fixture = TestBed.createComponent(EntityListPageComponent);
    fixture.componentRef.setInput('name', name);
    fixture.detectChanges();
    return fixture;
  }

  it('uses the route-bound name input when opening the create form', () => {
    const fixture = create('user_account');

    fixture.componentInstance.onCreate();

    expect(navigate).toHaveBeenCalledWith(['/xrm', 'entity', 'user_account', 'form']);
  });

  it('opens the create form for the record type picked (A27-T4)', () => {
    const fixture = create('account');

    fixture.componentInstance.onCreate('partner');

    expect(navigate).toHaveBeenCalledWith(
      ['/xrm', 'entity', 'account', 'form'],
      { queryParams: { record_type: 'partner' } },
    );
  });

  it('preserves the record id when opening the edit form', () => {
    const fixture = create();

    fixture.componentInstance.onEdit({ id: 'record-1' } as EntityRecord);

    expect(navigate).toHaveBeenCalledWith(['/xrm', 'entity', 'contact', 'form'], {
      queryParams: { id: 'record-1' },
    });
  });

  it('opens a card or calendar entry through the same edit route', () => {
    const fixture = create();

    fixture.componentInstance.onEditId('card-7');

    expect(navigate).toHaveBeenCalledWith(['/xrm', 'entity', 'contact', 'form'], {
      queryParams: { id: 'card-7' },
    });
  });

  it('renders the list by default and offers only the kinds the entity has views for', () => {
    listAvailable.mockReturnValue(of([
      view('all', 'list', true), view('board', 'kanban'), view('cal', 'calendar'), view('chart', 'chart'),
    ]));
    const page = create().componentInstance;

    expect(listAvailable).toHaveBeenCalledWith('contact');
    expect(page.activeKind()).toBe('list');
    expect(page.availableKinds()).toEqual(['list', 'kanban', 'calendar', 'chart']);
    // The chart renderer's chunk is only fetched once a chart view is shown.
    expect(loadChart).not.toHaveBeenCalled();
  });

  it('picks the renderer from the ?view= parameter', () => {
    url = '/xrm/entity/contact/list?view=board';
    listAvailable.mockReturnValue(of([view('all', 'list', true), view('board', 'kanban')]));
    const page = create().componentInstance;

    expect(page.selectedView()?.id).toBe('board');
    expect(page.activeKind()).toBe('kanban');
  });

  it('falls back to the default view when ?view= names an unknown view', () => {
    url = '/xrm/entity/contact/list?view=gone';
    listAvailable.mockReturnValue(of([view('board', 'kanban'), view('tl', 'timeline', true)]));
    const page = create().componentInstance;

    expect(page.activeKind()).toBe('timeline');
  });

  it('renders a chart view with the lazily loaded chart renderer', async () => {
    listAvailable.mockReturnValue(of([view('chart', 'chart', true)]));
    const fixture = create();
    const page = fixture.componentInstance;

    expect(page.activeKind()).toBe('chart');
    expect(page.availableKinds()).toEqual(['chart']);
    expect(loadChart).toHaveBeenCalledTimes(1);
    await fixture.whenStable();
    expect(page.chartViewComponent()).toBe(FakeChartView);
    expect(page.chartLoadFailed()).toBe(false);
  });

  it('keeps chart views out of the list picker', () => {
    const page = create().componentInstance;

    expect(page.listPickerKinds).toEqual(['list']);
  });

  it('reports a chart renderer that failed to load', async () => {
    loadChart.mockReturnValue(Promise.reject(new Error('chunk')));
    listAvailable.mockReturnValue(of([view('chart', 'chart', true)]));
    const fixture = create();
    await fixture.whenStable();

    expect(fixture.componentInstance.chartLoadFailed()).toBe(true);
    expect(fixture.componentInstance.chartViewComponent()).toBeNull();
  });

  it('switching kind writes that kind\'s default view to the URL, keeping other params', () => {
    url = '/xrm/entity/contact/list?filters=abc';
    listAvailable.mockReturnValue(of([
      view('all', 'list', true), view('b1', 'kanban'), view('b2', 'kanban', true),
    ]));
    const page = create().componentInstance;

    page.selectKind('kanban');

    expect(navigateByUrl).toHaveBeenCalledWith('/xrm/entity/contact/list?filters=abc&view=b2');
    expect(page.activeKind()).toBe('kanban');
  });

  it('does not navigate when the selected kind is already active', () => {
    listAvailable.mockReturnValue(of([view('all', 'list', true), view('b1', 'kanban')]));
    const page = create().componentInstance;

    page.selectKind('list');

    expect(navigateByUrl).not.toHaveBeenCalled();
  });

  it('follows the URL when the list\'s own picker or back/forward changes ?view=', () => {
    listAvailable.mockReturnValue(of([view('all', 'list', true), view('cal', 'calendar')]));
    const page = create().componentInstance;
    expect(page.activeKind()).toBe('list');

    url = '/xrm/entity/contact/list?view=cal';
    events.next(new NavigationEnd(1, url, url));

    expect(page.activeKind()).toBe('calendar');
  });

  it('lists only the active kind\'s views for its own picker', () => {
    url = '/xrm/entity/contact/list?view=b1';
    listAvailable.mockReturnValue(of([view('all', 'list', true), view('b1', 'kanban'), view('b2', 'kanban')]));
    const page = create().componentInstance;

    expect(page.kindViews().map(v => v.id)).toEqual(['b1', 'b2']);
  });

  it('falls back to the list when the views cannot be loaded', () => {
    listAvailable.mockReturnValue(throwError(() => new Error('boom')));
    const page = create().componentInstance;

    expect(page.views()).toEqual([]);
    expect(page.activeKind()).toBe('list');
  });
});
