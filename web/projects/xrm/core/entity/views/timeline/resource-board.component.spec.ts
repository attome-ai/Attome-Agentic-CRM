import { TestBed } from '@angular/core/testing';
import { ATTOME_CONFIG, ApiService, LangService, LiveChannel, LiveRecords } from '@attome/base';
import { QueryService } from '@attome/xrm/core/query/data';
import { Subject, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { EntityService } from '@attome/xrm/core/entity';
import { MAP_LIBRARY_LOADER } from '../map/points-map.component';
import {
  BoardJob, BoardTechnician, ResourceBoardComponent, barGeometry, boardPoints, coordinate, lastKnownLocations,
} from './resource-board.component';

const DAY = '2026-10-26';

describe('barGeometry (I3-T1)', () => {
  it('places a job on the 06:00 to 20:00 day', () => {
    // 13:00 to 15:00 is hours 7 to 9 of 14.
    const g = barGeometry(`${DAY}T13:00:00Z`, `${DAY}T15:00:00Z`, DAY)!;
    expect(g.offset).toBeCloseTo(50, 5);
    expect(g.width).toBeCloseTo((2 / 14) * 100, 5);
    expect(barGeometry(null, null, DAY)).toBeNull();
    expect(barGeometry(`${DAY}T21:00:00Z`, null, DAY)).toBeNull();
  });
});

describe('boardPoints (I3-T2)', () => {
  const job = (id: string, assignedTo: string | null, lat: number | null, lng: number | null): BoardJob =>
    ({ id, title: id, start: null, end: null, assignedTo, rowVersion: 1, lat, lng });
  const tech: BoardTechnician = { profileId: 't1', userId: 'u1', name: 'Huda', baseLat: 24.7, baseLng: 46.7 };

  it('places jobs at their sites and technicians at their bases', () => {
    const points = boardPoints([job('a', 'u1', 24.6, 46.6), job('b', null, 24.8, 46.8), job('c', null, null, 46)], [tech],
      name => `${name} base`);
    expect(points.map(p => [p.id, p.tone])).toEqual([['a', 'primary'], ['b', 'warning'], ['technician:t1', 'success']]);
    expect(points[2].label).toBe('Huda base');
    expect(boardPoints([job('d', null, 95, 0)], [], n => n)).toEqual([]);
  });

  it('shows a technician where they last checked in only with consent', () => {
    const last = lastKnownLocations([
      { owner_id: 'u1', location_consent: true, check_in_latitude: 24.9, check_in_longitude: 46.9 },
      { owner_id: 'u1', location_consent: true, check_in_latitude: 1, check_in_longitude: 1 },
      { owner_id: 'u2', location_consent: false, check_in_latitude: 24.1, check_in_longitude: 46.1 },
      { owner_id: 'u3', location_consent: true, check_in_latitude: null, check_in_longitude: 46.1 },
    ]);
    expect([...last.entries()]).toEqual([['u1', { lat: 24.9, lng: 46.9 }]]);
    const points = boardPoints([], [{ ...tech, lastLat: 24.9, lastLng: 46.9 }], n => `${n} base`, n => `${n} now`);
    expect(points.map(p => p.label)).toEqual(['Huda base', 'Huda now']);
  });

  it('reads a coordinate from a number or text', () => {
    expect(coordinate(24.5)).toBe(24.5);
    expect(coordinate('46.1')).toBe(46.1);
    expect(coordinate('')).toBeNull();
    expect(coordinate(null)).toBeNull();
    expect(coordinate('x')).toBeNull();
  });
});

describe('ResourceBoardComponent (I3-T1)', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };
  let update: ReturnType<typeof vi.fn>;
  let execute: ReturnType<typeof vi.fn>;
  let live: { watch: ReturnType<typeof vi.fn>; records: Subject<LiveRecords> };

  beforeEach(() => {
    api = {
      get: vi.fn(() => of({ work_order_id: 'wo2', rules: ['skills', 'hours'], candidates: [{ user_id: 'u-huda' }] })),
      post: vi.fn(() => of({
        assignments: [{ work_order_id: 'wo2', technician_id: 'u-huda', sequence: 1, start: `${DAY}T09:00:00Z`, end: `${DAY}T10:00:00Z`, travel_minutes: 12 }],
        unassigned: [],
      })),
    };
    update = vi.fn(() => of({ row_version: 8 }));
    live = { watch: vi.fn(() => () => undefined), records: new Subject<LiveRecords>() };
    execute = vi.fn((p: { entity: string }) => p.entity === 'activity'
      ? throwError(() => ({ status: 404 }))
      : of(p.entity === 'technician_profile'
      ? { data: { records: [
        { id: 't1', name: 'Huda', user_ref: 'u-huda', base_latitude: 24.7, base_longitude: 46.7 },
        { id: 't2', name: 'Omar', user_ref: 'u-omar' },
      ] } }
      : { data: { records: [
        { id: 'wo1', title: 'Boiler', scheduled_start: `${DAY}T08:00:00Z`, scheduled_end: `${DAY}T09:30:00Z`, assigned_to: 'u-omar', row_version: 3,
          site_latitude: '24.6', site_longitude: '46.6' },
        { id: 'wo2', title: 'AC repair', scheduled_start: `${DAY}T11:00:00Z`, scheduled_end: null, assigned_to: null, row_version: 7 },
      ] } }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [ResourceBoardComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: QueryService, useValue: { execute } },
        { provide: EntityService, useValue: { update } },
        { provide: LiveChannel, useValue: live },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://api.test' } },
        // The map library never loads here: the panel is checked, not drawn.
        { provide: MAP_LIBRARY_LOADER, useValue: () => new Promise(() => undefined) },
        { provide: LangService, useValue: { translate: (k: string, p?: Record<string, unknown>) => (p ? `${k}:${JSON.stringify(p)}` : k), isRtl: () => false, errorText: () => 'failed' } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(ResourceBoardComponent);
    fixture.componentRef.setInput('day', DAY);
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  const row = (root: HTMLElement, user: string) => root.querySelector(`[data-testid="rb-row"][data-user="${user}"]`) as HTMLElement;

  it('rows are technicians, bars are their jobs, and the rest wait aside', () => {
    const root: HTMLElement = render().nativeElement;
    expect(row(root, 'u-omar').querySelector('[data-job="wo1"]')).not.toBeNull();
    expect(row(root, 'u-huda').querySelector('[data-testid="rb-bar"]')).toBeNull();
    expect(root.querySelector('[data-testid="rb-unassigned"]')?.textContent).toContain('AC repair');
    const bar = row(root, 'u-omar').querySelector('[data-job="wo1"]') as HTMLElement;
    expect(bar.style.getPropertyValue('inset-inline-start')).toMatch(/%$/);
  });

  it('a drop on a technician who fails the hard rules is refused', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-job="wo2"]') as HTMLElement).dispatchEvent(new Event('dragstart'));
    row(root, 'u-omar').dispatchEvent(new Event('drop', { cancelable: true }));
    fixture.detectChanges();
    expect(api.get).toHaveBeenCalledWith('/api/v1/service/work-orders/wo2/candidates');
    expect(update).not.toHaveBeenCalled();
    expect(root.querySelector('[data-testid="rb-message"]')?.textContent).toContain('resourceBoard.refused');
  });

  it('a drop on a candidate assigns with the row version', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-job="wo2"]') as HTMLElement).dispatchEvent(new Event('dragstart'));
    row(root, 'u-huda').dispatchEvent(new Event('drop', { cancelable: true }));
    fixture.detectChanges();
    expect(update).toHaveBeenCalledWith('work_order', 'wo2', { assigned_to: 'u-huda' }, 7);
    expect(row(root, 'u-huda').querySelector('[data-job="wo2"]')).not.toBeNull();
  });

  it('a stale board is told so and reloads', () => {
    update.mockReturnValue(throwError(() => ({ status: 409, kind: 'conflict' })));
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-job="wo2"]') as HTMLElement).dispatchEvent(new Event('dragstart'));
    row(root, 'u-huda').dispatchEvent(new Event('drop', { cancelable: true }));
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="rb-message"]')?.textContent).toContain('resourceBoard.stale');
  });

  it('jobs and technicians with coordinates show on the map (I3-T2)', () => {
    const root: HTMLElement = render().nativeElement;
    expect(root.querySelector('[data-testid="rb-map"] xrm-points-map')).not.toBeNull();
    expect(live.watch).toHaveBeenCalledWith('work_order');
    expect(live.watch).toHaveBeenCalledWith('technician_profile');
    expect(live.watch).toHaveBeenCalledWith('activity');
  });

  it('a live work order change reloads the board once (I3-T2)', () => {
    vi.useFakeTimers();
    try {
      render();
      const before = execute.mock.calls.length;
      live.records.next({ changes: [{ entity: 'account', id: 'a1', op: 'update' }] });
      vi.advanceTimersByTime(1000);
      expect(execute.mock.calls.length).toBe(before);
      live.records.next({ changes: [{ entity: 'work_order', id: 'wo1', op: 'update' }] });
      live.records.next({ changes: [{ entity: 'work_order', id: 'wo2', op: 'update' }] });
      vi.advanceTimersByTime(1000);
      // One reload: the technicians, the work orders and the check-ins, once each.
      expect(execute.mock.calls.length).toBe(before + 3);
    } finally {
      vi.useRealTimers();
    }
  });

  it('ghost visits from the planner are accepted or rejected one by one', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-testid="rb-propose"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/service/day-plans/propose', { date: DAY });
    expect(row(root, 'u-huda').querySelector('[data-testid="rb-ghost"]')).not.toBeNull();
    (root.querySelector('[data-testid="rb-accept"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(update).toHaveBeenCalledWith('work_order', 'wo2',
      { assigned_to: 'u-huda', scheduled_start: `${DAY}T09:00:00Z`, scheduled_end: `${DAY}T10:00:00Z` }, 7);
    expect(root.querySelector('[data-testid="rb-ghost"]')).toBeNull();
  });
});
