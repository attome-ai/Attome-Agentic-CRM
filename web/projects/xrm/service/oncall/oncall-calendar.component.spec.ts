import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { OncallCalendarComponent } from './oncall-calendar.component';
import { byDay, weekStart, type OnCallStretch } from './oncall-calendar.service';

const stretch = (start: string, end: string, user: string, via = 'layer', layer: number | null = 0): OnCallStretch => ({
  start, end, user_id: user, user_name: `name-${user}`, via, layer,
});

describe('on-call calendar (H7-T2)', () => {
  it('starts the week on Monday, UTC', () => {
    // Wednesday 4 November 2026.
    expect(weekStart(new Date('2026-11-04T15:30:00Z')).toISOString()).toBe('2026-11-02T00:00:00.000Z');
    expect(weekStart(new Date('2026-11-02T00:00:00Z')).toISOString()).toBe('2026-11-02T00:00:00.000Z');
    // A Sunday belongs to the week that began six days before.
    expect(weekStart(new Date('2026-11-08T23:00:00Z')).toISOString()).toBe('2026-11-02T00:00:00.000Z');
  });

  it('splits stretches by day, clipped to each day', () => {
    const days = byDay(
      [stretch('2026-11-02T09:00:00Z', '2026-11-03T09:00:00Z', 'u1')],
      new Date('2026-11-02T00:00:00Z'),
      3,
    );
    expect(days.map(d => d.stretches.length)).toEqual([1, 1, 0]);
    expect(days[0].stretches[0].start).toBe('2026-11-02T09:00:00.000Z');
    expect(days[0].stretches[0].end).toBe('2026-11-03T00:00:00.000Z');
    expect(days[1].stretches[0].start).toBe('2026-11-03T00:00:00.000Z');
    expect(days[1].stretches[0].end).toBe('2026-11-03T09:00:00.000Z');
  });

  function create() {
    const list = vi.fn(() => of({ data: [{ id: 's1', data: { name: 'Network' } }], meta: { total: 1 } }));
    const get = vi.fn(() => of({
      items: [
        stretch('2026-11-02T09:00:00Z', '2026-11-02T18:00:00Z', 'u1'),
        stretch('2026-11-02T18:00:00Z', '2026-11-03T06:00:00Z', 'u9', 'override', null),
      ],
      total: 2, page: 1, page_size: 2,
    }));
    TestBed.configureTestingModule({
      imports: [OncallCalendarComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get } },
        { provide: EntityService, useValue: { list } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('ar'), errorText: () => 'error', intlLocale: () => 'ar-SA' },
        },
      ],
    });
    const fixture = TestBed.createComponent(OncallCalendarComponent);
    fixture.componentInstance.from.set(new Date('2026-11-02T00:00:00Z'));
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, get };
  }

  it('loads the first schedule\'s week and marks overrides', () => {
    const { el, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/service/oncall/schedules/s1/calendar', {
      from: '2026-11-02T00:00:00.000Z',
      to: '2026-11-09T00:00:00.000Z',
    });
    const monday = el.querySelector('[data-day="2026-11-02T00:00:00.000Z"]');
    expect(monday?.querySelectorAll('[data-user]').length).toBe(2);
    expect(monday?.querySelector('[data-via="override"]')?.textContent).toContain('name-u9');
    expect(monday?.textContent).toContain('oncallCalendar.override');
    const tuesday = el.querySelector('[data-day="2026-11-03T00:00:00.000Z"]');
    expect(tuesday?.querySelector('[data-user="u9"]')).not.toBeNull();
  });

  it('moves a week at a time', () => {
    const { cmp, get } = create();
    cmp.shift(1);
    expect(get).toHaveBeenLastCalledWith('/api/v1/service/oncall/schedules/s1/calendar', {
      from: '2026-11-09T00:00:00.000Z',
      to: '2026-11-16T00:00:00.000Z',
    });
    cmp.shift(-2);
    expect(cmp.from().toISOString()).toBe('2026-10-26T00:00:00.000Z');
  });
});
