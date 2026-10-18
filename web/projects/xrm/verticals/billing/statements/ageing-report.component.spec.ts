import { computed, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AgeingRow, AgeingTotals } from '../data/billing.service';
import { formatAmount, minorUnits } from '../data/money';
import { AgeingReportComponent } from './ageing-report.component';

const ROWS: AgeingRow[] = [
  {
    account_id: 'a1', account_name: 'Gulf Trading', currency: 'KWD',
    current: '10.5', days_1_30: '0', days_31_60: '2.125', days_61_90: '0', over_90: '0', total: '12.625',
  },
  {
    account_id: 'a2', account_name: 'Riyadh Supplies', currency: 'SAR',
    current: '115', days_1_30: '230', days_31_60: '0', days_61_90: '0', over_90: '460', total: '805',
  },
];
const TOTALS: AgeingTotals[] = [
  { currency: 'SAR', current: '115', days_1_30: '230', days_31_60: '0', days_61_90: '0', over_90: '460', total: '805' },
];

describe('AgeingReportComponent (F4-T16)', () => {
  function create() {
    const get = vi.fn((url: string) =>
      of(url.includes('/totals')
        ? { items: TOTALS, total: 1, page: 1, page_size: 1 }
        : { items: ROWS, total: 2, page: 1, page_size: 50 }));
    const current = signal('en');
    TestBed.configureTestingModule({
      imports: [AgeingReportComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: { get } },
        {
          provide: LangService,
          useValue: {
            translate: (k: string) => k,
            current,
            isRtl: computed(() => current() === 'ar'),
            intlLocale: computed(() => 'en-GB'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(AgeingReportComponent);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('formats KWD with three decimals', () => {
    const { fixture } = create();
    const kwd = (fixture.nativeElement as HTMLElement).querySelector('tr[data-account="a1"]');
    const cells = Array.from(kwd?.querySelectorAll('td.num') ?? []).map(c => c.textContent?.trim());
    expect(cells).toEqual(['10.500', '0.000', '2.125', '0.000', '0.000', '12.625']);
    expect(minorUnits('kwd')).toBe(3);
    expect(formatAmount('1234.5', 'SAR', 'en-GB')).toBe('1,234.50');
    expect(formatAmount('7', 'JPY', 'en-GB')).toBe('7');
  });

  it('shows the totals per currency and links each account to its statement', () => {
    const { fixture, get } = create();
    expect(get.mock.calls.some(([url]) => url.startsWith('/api/v1/billing/ageing?as_of='))).toBe(true);
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('tr[data-totals="SAR"]')).not.toBeNull();
    const link = el.querySelector('tr[data-account="a2"] a');
    expect(link?.getAttribute('href')).toBe('/xrm/billing/accounts/a2/statement');
  });
});
