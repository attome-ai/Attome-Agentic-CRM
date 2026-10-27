import { TestBed } from '@angular/core/testing';
import { LangService, UserPreferencesService } from '@attome/base';
import { describe, expect, it, beforeEach } from 'vitest';
import type { ScheduleDetail } from '../workforce-api.service';
import { coverageDays } from '../workforce-api.service';
import { ScheduleGridComponent, dayTotals, gridRows, scheduleDays } from './schedule-grid.component';

const SARA = '01900000-0000-7000-8000-0000000000a1';
const OMAR = '01900000-0000-7000-8000-0000000000a2';

function schedule(): ScheduleDetail {
  return {
    id: 's-1',
    period_from: '2026-11-01',
    period_to: '2026-11-02',
    planning_group_id: 'g-1',
    row_version: 2,
    status: 'draft',
    assignments: [
      { id: 'a1', user_id: SARA, start_at: '2026-11-01T06:00:00Z', end_at: '2026-11-01T14:00:00Z', activity: 'work', row_version: 1 },
      { id: 'a2', user_id: SARA, start_at: '2026-11-01T10:00:00Z', end_at: '2026-11-01T10:30:00Z', activity: 'break', row_version: 1 },
      { id: 'a3', user_id: OMAR, start_at: '2026-11-02T12:00:00Z', end_at: '2026-11-02T20:00:00Z', activity: 'work', row_version: 1 },
    ],
    coverage: coverageDays([
      { day: '2026-11-01', requirement: [1, 2, 2], before: [0, 0, 0], after: [1, 2, 1], under: 1, over: 0 },
    ]),
  };
}

describe('ScheduleGridComponent (G17-T13)', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ScheduleGridComponent],
      providers: [
        {
          provide: LangService,
          useValue: { intlLocale: () => 'en-US', current: () => 'en', translate: (k: string) => k },
        },
        {
          provide: UserPreferencesService,
          useValue: { timezone: () => null, calendar: () => null, digits: () => null },
        },
      ],
    });
  });

  function render(dir: 'ltr' | 'rtl' = 'ltr') {
    const fixture = TestBed.createComponent(ScheduleGridComponent);
    fixture.componentRef.setInput('schedule', schedule());
    fixture.componentRef.setInput('users', [{ id: SARA, label: 'Sara' }, { id: OMAR, label: 'Omar' }]);
    const el: HTMLElement = fixture.nativeElement;
    el.setAttribute('dir', dir);
    fixture.detectChanges();
    return { fixture, el };
  }

  it('grid renders people by days with shifts and breaks', () => {
    expect(scheduleDays('2026-11-01', '2026-11-02')).toEqual(['2026-11-01', '2026-11-02']);
    const rows = gridRows(schedule().assignments, ['2026-11-01', '2026-11-02'], new Map([[SARA, 'Sara'], [OMAR, 'Omar']]));
    expect(rows.map(r => r.label)).toEqual(['Omar', 'Sara']);
    const sara = rows[1];
    expect(sara.days[0].map(b => b.activity)).toEqual(['work', 'break']);
    expect(sara.days[0][0].start).toBeCloseTo(25);
    expect(sara.days[0][0].width).toBeCloseTo(33.33, 1);
    expect(sara.days[1]).toEqual([]);
    expect(dayTotals(schedule().coverage)).toEqual([{ day: '2026-11-01', required: 5, scheduled: 4, under: 1 }]);

    const { el } = render();
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.querySelectorAll('.sg-bar').length).toBe(3);
    expect(el.querySelectorAll('.sg-break').length).toBe(1);
    expect(el.querySelector('[data-testid="schedule-coverage"] li')?.classList.contains('sg-short')).toBe(true);
  });

  it('rtl renders the grid mirrored with logical insets', () => {
    const { el } = render('rtl');
    expect(el.getAttribute('dir')).toBe('rtl');
    const bar = el.querySelector('[data-assignment="a1"]') as HTMLElement;
    expect(bar.style.getPropertyValue('inset-inline-start')).toBe('25%');
    expect(bar.style.getPropertyValue('left')).toBe('');
  });
});
