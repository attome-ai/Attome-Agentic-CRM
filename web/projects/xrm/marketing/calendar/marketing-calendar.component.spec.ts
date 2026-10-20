import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CalendarCampaign, MarketingCalendarComponent, budgetRows, entriesForMonth, monthRange,
} from './marketing-calendar.component';

const launch: CalendarCampaign = {
  id: 'c1', name: 'Ramadan launch', type: 'email', status: 'active',
  start: '2026-03-02', end: '2026-03-28', budget: 10000,
};

describe('marketing calendar helpers (E29-T1)', () => {
  it('knows the days of a month', () => {
    expect(monthRange(2026, 2)).toEqual({ first: '2026-02-01', last: '2026-02-28' });
    expect(monthRange(2028, 2).last).toBe('2028-02-29');
  });

  it('places campaign starts, ends and events on their days', () => {
    const entries = entriesForMonth(
      [launch, { ...launch, id: 'c2', name: 'Earlier', start: '2026-02-01', end: '2026-03-05' }],
      [{ id: 'e1', name: 'Expo', nameAr: 'المعرض', start: '2026-03-10T09:00:00Z', campaignId: 'c1' }],
      '2026-03-01', '2026-03-31',
    );
    expect(entries.map(e => `${e.day} ${e.kind} ${e.label}`)).toEqual([
      '2026-03-02 campaign_start Ramadan launch',
      '2026-03-05 campaign_end Earlier',
      '2026-03-10 event Expo',
      '2026-03-28 campaign_end Ramadan launch',
    ]);
  });

  it('sets budget against the lines that name the campaign', () => {
    const rows = budgetRows([launch, { ...launch, id: 'c3', name: 'No budget', budget: null }], [
      { campaignCode: 'C1', amount: 6000, actual: 4000 },
      { campaignCode: 'Ramadan Launch ', amount: 4000, actual: 7000 },
      { campaignCode: 'no budget', amount: 500, actual: 200 },
      { campaignCode: 'other', amount: 999, actual: 999 },
    ]);
    expect(rows[0]).toMatchObject({ planned: 10000, actual: 11000, remaining: -1000 });
    // Without its own budget, the planned lines are the budget.
    expect(rows[1]).toMatchObject({ budget: null, planned: 500, actual: 200, remaining: 300 });
  });
});

describe('MarketingCalendarComponent (E29-T1)', () => {
  const entities = { list: vi.fn() };

  beforeEach(() => {
    vi.resetAllMocks();
    entities.list.mockImplementation((entity: string) => {
      if (entity === 'campaign') {
        return of({ data: [{ id: 'c1', data: { name: 'Ramadan launch', start_date: '2026-03-02', end_date: '2026-03-28', budget: '10000' } }] });
      }
      if (entity === 'marketing_event') {
        return of({ data: [{ id: 'e1', data: { name: 'Expo', name_ar: 'المعرض', starts_at: '2026-03-10T09:00:00Z' } }] });
      }
      // No finance pack on this deployment.
      return throwError(() => ({ kind: 'not_found', message: 'no entity' }));
    });
    TestBed.configureTestingModule({
      imports: [MarketingCalendarComponent],
      providers: [
        { provide: EntityService, useValue: entities },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-GB' },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(MarketingCalendarComponent);
    fixture.componentInstance.year.set(2026);
    fixture.componentInstance.month.set(3);
    fixture.componentInstance.shift(0);
    fixture.detectChanges();
    return fixture;
  }

  it('shows the month and the budget without the finance pack', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="mc-month"]')?.textContent).toContain('March 2026');
    expect(el.querySelectorAll('[data-testid="mc-entry"]').length).toBe(3);
    expect(el.querySelector('[data-campaign="c1"] [data-remaining]')?.textContent).toContain('10,000');
  });

  it('asks for the next month', () => {
    const fixture = render();
    (fixture.nativeElement.querySelector('[data-testid="mc-next"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(entities.list).toHaveBeenLastCalledWith('budget_line', expect.anything());
    const campaignCalls = entities.list.mock.calls.filter(c => c[0] === 'campaign');
    expect(campaignCalls.at(-1)?.[1].filters[0]).toEqual({ field: 'start_date', op: 'lte', value: '2026-04-30' });
  });
});
