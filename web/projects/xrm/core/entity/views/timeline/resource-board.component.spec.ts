import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { QueryService } from '@attome/xrm/core/query/data';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { EntityService } from '@attome/xrm/core/entity';
import { ResourceBoardComponent, barGeometry } from './resource-board.component';

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

describe('ResourceBoardComponent (I3-T1)', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };
  let update: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    api = {
      get: vi.fn(() => of({ work_order_id: 'wo2', rules: ['skills', 'hours'], candidates: [{ user_id: 'u-huda' }] })),
      post: vi.fn(() => of({
        assignments: [{ work_order_id: 'wo2', technician_id: 'u-huda', sequence: 1, start: `${DAY}T09:00:00Z`, end: `${DAY}T10:00:00Z`, travel_minutes: 12 }],
        unassigned: [],
      })),
    };
    update = vi.fn(() => of({ row_version: 8 }));
    const execute = vi.fn((p: { entity: string }) => of(p.entity === 'technician_profile'
      ? { data: { records: [{ id: 't1', name: 'Huda', user_ref: 'u-huda' }, { id: 't2', name: 'Omar', user_ref: 'u-omar' }] } }
      : { data: { records: [
        { id: 'wo1', title: 'Boiler', scheduled_start: `${DAY}T08:00:00Z`, scheduled_end: `${DAY}T09:30:00Z`, assigned_to: 'u-omar', row_version: 3 },
        { id: 'wo2', title: 'AC repair', scheduled_start: `${DAY}T11:00:00Z`, scheduled_end: null, assigned_to: null, row_version: 7 },
      ] } }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [ResourceBoardComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: QueryService, useValue: { execute } },
        { provide: EntityService, useValue: { update } },
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
