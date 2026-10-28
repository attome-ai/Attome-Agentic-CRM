import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, UserPreferencesService } from '@attome/base';
import { AdminService, ChangesetContextService } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { CalendarManagerComponent, blankRule, ruleBody } from './calendar-manager.component';

const CALENDAR = {
  id: 'cal-sa', name: 'Saudi Arabia', name_ar: 'السعودية', description: null, tz: 'Asia/Riyadh',
  working_days: ['sun', 'mon', 'tue', 'wed', 'thu'], hours: {}, is_default: false, is_active: true,
  owner_layer: 'customer',
};

function create() {
  const confirmSighting = vi.fn((_body: unknown) => of({}));
  const service = {
    listCalendars: vi.fn(() => of([CALENDAR])),
    listHolidays: vi.fn(() => of([])),
    listExceptions: vi.fn(() => of([])),
    getCalendar: vi.fn(() => of({ ...CALENDAR, current_version: 1, rules: [], seasons: [] })),
    expandedRules: vi.fn(() => of({
      from_year: 2026, years: 2,
      rules: [{
        rule_id: 'r-fitr', name: 'Eid al-Fitr', name_ar: 'عيد الفطر', needs_sighting: true, error: null,
        days: [
          { date: '2026-03-20', hijri: '1447-10-01' },
          { date: '2027-03-09', hijri: '1448-10-01' },
        ],
      }],
    })),
    listFeeds: vi.fn(() => of([])),
    listSightings: vi.fn(() => of([{
      calendar_id: 'cal-sa', rule_id: 'r-fitr', rule_name: 'Eid al-Fitr', hijri_year: 1447,
      expected_start: '2026-03-20', confirmed_start: null,
    }])),
    confirmSighting,
  };
  TestBed.configureTestingModule({
    imports: [CalendarManagerComponent],
    providers: [
      { provide: AdminService, useValue: service },
      { provide: ChangesetContextService, useValue: { editingLayer: signal<string | null>(null) } },
      {
        provide: LangService,
        useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' },
      },
      { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
    ],
  });
  const fixture = TestBed.createComponent(CalendarManagerComponent);
  fixture.detectChanges();
  fixture.componentInstance.select(CALENDAR as never);
  fixture.detectChanges();
  return { fixture, service, confirmSighting };
}

function click(fixture: ReturnType<typeof create>['fixture'], selector: string): void {
  (fixture.nativeElement.querySelector(selector) as HTMLElement).click();
  fixture.detectChanges();
}

describe('CalendarManagerComponent (Z12-T13)', () => {
  it('shows expanded Hijri rule dates', () => {
    const { fixture } = create();
    click(fixture, '[data-tab="rules"]');
    const table: HTMLElement = fixture.nativeElement.querySelector('[data-expanded]');
    expect(table).not.toBeNull();
    const hijri = [...table.querySelectorAll('[data-hijri]')].map(c => c.textContent?.trim());
    expect(hijri).toEqual(['1447-10-01', '1448-10-01']);
    expect(table.querySelector('[data-day="2026-03-20"]')?.textContent).toContain('Eid al-Fitr');
  });

  it('confirm sighting posts once', () => {
    const { fixture, confirmSighting } = create();
    click(fixture, '[data-tab="sightings"]');
    const button = fixture.nativeElement.querySelector('[data-confirm-sighting]') as HTMLButtonElement;
    // The second click finds the date already confirmed and posts nothing.
    button.click();
    fixture.detectChanges();
    expect(button.disabled).toBe(true);
    fixture.componentInstance.confirmSighting(fixture.componentInstance.calendarSightings()[0]);
    fixture.detectChanges();
    expect(confirmSighting).toHaveBeenCalledOnce();
    expect(confirmSighting).toHaveBeenCalledWith({
      rule_id: 'r-fitr', hijri_year: 1447, confirmed_start: '2026-03-20',
    });
    const row = fixture.componentInstance.calendarSightings()[0];
    expect(row.confirmed_start).toBe('2026-03-20');
  });

  it('builds the rule body each kind needs', () => {
    const hijri = ruleBody({ ...blankRule(), name: ' Eid ', kind: 'hijri', month: 10, day: 1, span_days: 3, needs_sighting: true });
    expect(hijri).toEqual({
      name: 'Eid', name_ar: null, needs_sighting: true,
      rule: { kind: 'hijri', month: 10, day: 1, span_days: 3 },
    });
    const fixed = ruleBody({ ...blankRule(), name: 'National Day', kind: 'fixed', month: 9, day: 23, span_days: 40, needs_sighting: true });
    expect(fixed.needs_sighting).toBe(false);
    expect(fixed.rule).toEqual({ kind: 'fixed', month: 9, day: 23, span_days: 15 });
  });
});
