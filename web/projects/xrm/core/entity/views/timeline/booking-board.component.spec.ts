import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { QueryService } from '@attome/xrm/core/query/data';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { EntityService } from '@attome/xrm/core/entity';
import { BookingBoardComponent, addDays, spanGeometry, weekStart } from './booking-board.component';

const MONDAY = '2026-10-26';

describe('booking board geometry (V4-T1)', () => {
  it('starts on a Monday and places date ranges over the weeks', () => {
    expect(weekStart('2026-10-29')).toBe(MONDAY);
    expect(weekStart(MONDAY)).toBe(MONDAY);
    expect(addDays(MONDAY, 7)).toBe('2026-11-02');
    // Week two of four, inclusive end.
    const g = spanGeometry('2026-11-02', '2026-11-08', MONDAY, 28)!;
    expect(g.offset).toBeCloseTo(25, 5);
    expect(g.width).toBeCloseTo(25, 5);
    // An open end runs to the board's end; a range before it is not shown.
    expect(spanGeometry('2026-11-02', null, MONDAY, 28)!.width).toBeCloseTo(75, 5);
    expect(spanGeometry('2026-10-01', '2026-10-10', MONDAY, 28)).toBeNull();
  });
});

describe('BookingBoardComponent (V4-T1)', () => {
  let api: { get: ReturnType<typeof vi.fn> };
  let update: ReturnType<typeof vi.fn>;
  let create: ReturnType<typeof vi.fn>;
  const person = (id: string, name: string, over = false) => ({
    resource_id: id, resource_name: name, capacity_hours: 320, allocated_hours: over ? 400 : 160,
    actual_hours: 0, utilization_pct: over ? 125 : 50, over_allocated: over,
  });

  beforeEach(() => {
    api = { get: vi.fn(() => of({ items: [person('u-huda', 'Huda', true), person('u-omar', 'Omar')], total: 2, page: 1, page_size: 100 })) };
    update = vi.fn(() => of({ row_version: 5 }));
    create = vi.fn(() => of({ id: 'a-new', row_version: 1 }));
    const execute = vi.fn((p: { entity: string }) => of(p.entity === 'resource_allocation'
      ? { data: { records: [
        { id: 'a1', user_id: 'u-huda', regarding_entity: 'project', regarding_id: 'p1', allocation_percent: 100, start_date: MONDAY, end_date: '2026-11-15', row_version: 4 },
        { id: 'a-old', user_id: 'u-omar', allocation_percent: 50, start_date: '2026-09-01', end_date: '2026-09-30', row_version: 1 },
      ] } }
      : { data: { records: [{ user_id: 'u-omar', leave_start: '2026-11-02', leave_end: '2026-11-06' }] } }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [BookingBoardComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: QueryService, useValue: { execute } },
        { provide: EntityService, useValue: { update, create } },
        { provide: LangService, useValue: { translate: (k: string, p?: Record<string, unknown>) => (p ? `${k}:${JSON.stringify(p)}` : k), isRtl: () => false, errorText: () => 'failed' } },
      ],
    });
  });

  function render(project: string | null = 'p1') {
    const fixture = TestBed.createComponent(BookingBoardComponent);
    fixture.componentRef.setInput('start', MONDAY);
    fixture.componentRef.setInput('weeks', 4);
    fixture.componentRef.setInput('projectId', project);
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  const row = (root: HTMLElement, user: string) => root.querySelector(`[data-testid="bb-row"][data-user="${user}"]`) as HTMLElement;

  it('rows are people with their load, bars are bookings, leave is shaded', () => {
    const root: HTMLElement = render().nativeElement;
    expect(api.get).toHaveBeenCalledWith('/api/v1/resources/capacity', { from: MONDAY, to: '2026-11-22', page: '1', page_size: '100' });
    expect(row(root, 'u-huda').querySelector('[data-booking="a1"]')).not.toBeNull();
    expect(row(root, 'u-huda').querySelector('[data-testid="bb-over"]')).not.toBeNull();
    expect(row(root, 'u-omar').querySelector('[data-testid="bb-over"]')).toBeNull();
    // A booking that ended before the board starts is not shown.
    expect(root.querySelector('[data-booking="a-old"]')).toBeNull();
    expect(row(root, 'u-omar').querySelector('[data-testid="bb-leave"]')).not.toBeNull();
  });

  it('moves a booking to another person with its row version', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-booking="a1"]') as HTMLElement).dispatchEvent(new Event('dragstart'));
    row(root, 'u-omar').dispatchEvent(new Event('drop', { cancelable: true }));
    fixture.detectChanges();
    expect(update).toHaveBeenCalledWith('resource_allocation', 'a1', { user_id: 'u-omar' }, 4);
    expect(row(root, 'u-omar').querySelector('[data-booking="a1"]')).not.toBeNull();
  });

  it('a stale board is told so', () => {
    update.mockReturnValue(throwError(() => ({ status: 409, kind: 'conflict' })));
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-booking="a1"]') as HTMLElement).dispatchEvent(new Event('dragstart'));
    row(root, 'u-omar').dispatchEvent(new Event('drop', { cancelable: true }));
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="bb-message"]')?.textContent).toContain('bookingBoard.stale');
  });

  it('a click on a week books the person on the project', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (row(root, 'u-omar').querySelector('[data-week="2026-11-09"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(create).toHaveBeenCalledWith('resource_allocation', {
      user_id: 'u-omar', regarding_entity: 'project', regarding_id: 'p1',
      allocation_percent: 50, start_date: '2026-11-09', end_date: '2026-11-15',
    });
    expect(row(root, 'u-omar').querySelector('[data-booking="a-new"]')).not.toBeNull();
  });

  it('without a project the board is read only', () => {
    const root: HTMLElement = render(null).nativeElement;
    expect(root.querySelector('[data-testid="bb-cell"]')).toBeNull();
  });
});
