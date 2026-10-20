import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { xrmAr } from '@attome/xrm/core/i18n-ar';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { CommissionStatementComponent, StatementRow } from './commission-statement.component';

const PERIOD = '0190a000-0000-7000-8000-0000000000p1';

const ROWS: StatementRow[] = [
  {
    id: 'l1', kind: 'line', participant_id: 'p', run_id: 'r', component_id: 'c', credit_id: 'cr',
    amount: '1250.50',
    explanation: [
      { key: 'commission.retroactive_rate', values: { attainment: '104', rate: '5' } },
      { key: 'commission.capped_per_deal', values: { cap: '1250.50' } },
    ],
  },
  {
    id: 'a1', kind: 'adjustment', participant_id: 'p', run_id: null, component_id: null, credit_id: null,
    amount: null, explanation: 'Late renewal',
  },
];

/** Looks a key up in a catalogue, the way the real `LangService` does. */
function lookup(catalog: object, key: string): string {
  const value = key.split('.').reduce<unknown>(
    (node, part) => (node as Record<string, unknown> | undefined)?.[part], catalog);
  return typeof value === 'string' ? value : key;
}

function mount(options: { arabic?: boolean; calendar?: 'gregorian' | 'hijri' } = {}) {
  const get = vi.fn(() => of({ items: ROWS, total: ROWS.length, page: 1, page_size: 200 }));
  const list = vi.fn(() => of({
    data: [{ id: PERIOD, entity_id: '', created_at: '', updated_at: '', row_version: 1,
      data: { fiscal_period: 'FY27-Q1', starts_on: '2027-01-01', ends_on: '2027-03-31' } }],
    meta: { total: 1, limit: 24, offset: 0 },
  }));
  const arabic = options.arabic ?? false;
  TestBed.configureTestingModule({
    imports: [CommissionStatementComponent],
    providers: [
      { provide: ApiService, useValue: { get } },
      { provide: EntityService, useValue: { list } },
      {
        provide: LangService,
        useValue: {
          translate: arabic ? (key: string) => lookup(xrmAr, key) : (key: string) => key,
          current: signal(arabic ? 'ar' : 'en'),
          isRtl: signal(arabic),
          intlLocale: signal('en'),
        },
      },
      {
        provide: UserPreferencesService,
        useValue: {
          timezone: signal('UTC'),
          calendar: signal(options.calendar ?? 'gregorian'),
          digits: signal('latn'),
        },
      },
    ],
  });
  const fixture = TestBed.createComponent(CommissionStatementComponent);
  fixture.detectChanges();
  return { fixture, get };
}

describe('CommissionStatementComponent (F10-T15)', () => {
  it('renders explanation steps', () => {
    const { fixture, get } = mount();
    expect(get).toHaveBeenCalledWith('/api/v1/commission/statements/me', { period_id: PERIOD, page_size: '200' });
    const el = fixture.nativeElement as HTMLElement;
    const steps = [...el.querySelectorAll('[data-row="l1"] [data-step]')].map(s => s.textContent?.trim());
    expect(steps).toEqual(['commission.retroactive_rate', 'commission.capped_per_deal']);
    expect(el.querySelector('[data-row="a1"]')?.textContent).toContain('Late renewal');
    expect(el.querySelector('[data-row="a1"]')?.textContent).toContain('commission.statement.hidden');
  });

  it('sets dir rtl in Arabic', () => {
    const { fixture } = mount({ arabic: true });
    const section = (fixture.nativeElement as HTMLElement).querySelector('section');
    expect(section?.getAttribute('dir')).toBe('rtl');
    expect(section?.textContent).toContain('كشف عمولتي');
  });

  it('formats period in Hijri when the user calendar is Hijri', () => {
    const { fixture } = mount({ calendar: 'hijri' });
    const option = (fixture.nativeElement as HTMLElement).querySelector(`[data-period="${PERIOD}"]`);
    // 1 January 2027 is in Rajab 1448 on the Umm al-Qura calendar.
    expect(option?.textContent).toContain('1448');
    expect(option?.textContent).not.toContain('2027');
  });
});
