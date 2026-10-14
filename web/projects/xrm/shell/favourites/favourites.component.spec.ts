import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { Observable, of } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FavouritesComponent } from './favourites.component';
import {
  FavouriteList, FavouritesService, RECENT_FLUSH_MS, moved, recordFromUrl,
} from './favourites.service';

const RECORD = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b';

function list(items: Partial<FavouriteList['items'][number]>[], extra: Partial<FavouriteList> = {}): FavouriteList {
  return {
    id: 'list-1', name: 'Mine', team_id: null,
    items: items.map((i, n) => ({
      id: `item-${n}`, kind: 'page', entity: null, ref: `/p${n}`, label: `P${n}`, pinned: false, deleted: false, ...i,
    })),
    ...extra,
  };
}

class StubApi {
  lists: FavouriteList[] = [];
  puts: { path: string; body: unknown }[] = [];
  posts: { path: string; body: unknown }[] = [];
  get(path: string): Observable<unknown> {
    return of({ items: path === '/api/v1/me/favourites' ? this.lists : [] });
  }
  put(path: string, body: unknown): Observable<unknown> { this.puts.push({ path, body }); return of({}); }
  post(path: string, body: unknown): Observable<unknown> { this.posts.push({ path, body }); return of({}); }
  delete(): Observable<void> { return of(undefined); }
}

function setup(api = new StubApi()) {
  TestBed.configureTestingModule({
    imports: [FavouritesComponent],
    providers: [
      provideRouter([]),
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: { current: signal('en'), set: vi.fn(), translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(FavouritesComponent);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, service: TestBed.inject(FavouritesService), api };
}

describe('favourites helpers', () => {
  it('reads the record a form URL opens', () => {
    expect(recordFromUrl(`/xrm/entity/party/form?id=${RECORD}`)).toEqual({ entity: 'party', record_id: RECORD });
    expect(recordFromUrl(`/xrm/entity/party/form?tab=2&id=${RECORD}`)?.entity).toBe('party');
    expect(recordFromUrl('/xrm/entity/party/list')).toBeNull();
    expect(recordFromUrl('/xrm/entity/party/form')).toBeNull();
  });

  it('moves one item and keeps the rest in order', () => {
    expect(moved(['a', 'b', 'c'], 0, 2)).toEqual(['b', 'c', 'a']);
    expect(moved(['a', 'b', 'c'], 2, 0)).toEqual(['c', 'a', 'b']);
    expect(moved(['a', 'b'], 5, 0)).toEqual(['a', 'b']);
  });
});

describe('FavouritesComponent', () => {
  afterEach(() => vi.useRealTimers());

  it('lists pinned items first, with their shortcut, at most nine', () => {
    const api = new StubApi();
    api.lists = [list(Array.from({ length: 11 }, (_, n) => ({ pinned: n !== 1 })))];
    const { service } = setup(api);
    service.reload();
    expect(service.pinned().length).toBe(9);
    expect(service.pinned()[0].id).toBe('item-0');
    expect(service.pinned()[1].id).toBe('item-2');
  });

  it('opens the Nth pinned item on Ctrl+N', () => {
    const api = new StubApi();
    api.lists = [list([{ pinned: true, ref: '/dashboard' }, { pinned: true, ref: '/pipeline' }])];
    const { service } = setup(api);
    service.reload();
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    expect(service.openPinned(2)).toBe(true);
    expect(navigate).toHaveBeenCalledWith('/pipeline');
    expect(service.openPinned(3)).toBe(false);
  });

  it('saves the whole list, in the new order, when an item is dragged', () => {
    const api = new StubApi();
    const mine = list([{}, {}, {}]);
    api.lists = [mine];
    const { component } = setup(api);
    const drag = { dataTransfer: null, preventDefault: vi.fn() } as unknown as DragEvent;
    component.onDragStart(mine, 0, drag);
    component.onDrop(mine, 2, drag);
    expect(api.puts.length).toBe(1);
    expect(api.puts[0].path).toBe('/api/v1/me/favourites/lists/list-1');
    const saved = (api.puts[0].body as { items: { ref: string }[] }).items.map(i => i.ref);
    expect(saved).toEqual(['/p1', '/p2', '/p0']);
  });

  it('saves a team list through the team route', () => {
    const api = new StubApi();
    const shared = list([{}, {}], { id: 'team-list', team_id: 'team-9' });
    api.lists = [shared];
    const { service } = setup(api);
    service.togglePin(shared, shared.items[1]);
    expect(api.puts[0].path).toBe('/api/v1/teams/team-9/favourites/lists/team-list');
    expect((api.puts[0].body as { items: { pinned: boolean }[] }).items[1].pinned).toBe(true);
  });

  it('creates the first list when a record is starred and none exists', () => {
    const { service, api } = setup();
    service.toggleRecord('party', RECORD, 'Acme');
    expect(api.posts[0].path).toBe('/api/v1/me/favourites/lists');
    expect(api.posts[0].body).toMatchObject({ items: [{ kind: 'record', entity: 'party', ref: RECORD }] });
  });

  it('reports record opens together after a pause', () => {
    vi.useFakeTimers();
    const { service, api } = setup();
    service.noteOpen('party', RECORD);
    service.noteOpen('party', RECORD);
    expect(api.posts.length).toBe(0);
    vi.advanceTimersByTime(RECENT_FLUSH_MS);
    expect(api.posts.length).toBe(1);
    expect(api.posts[0]).toEqual({
      path: '/api/v1/me/recent',
      body: { items: [{ entity: 'party', record_id: RECORD }] },
    });
  });
});
