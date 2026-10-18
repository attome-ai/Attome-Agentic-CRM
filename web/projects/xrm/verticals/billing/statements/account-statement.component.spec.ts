import { computed, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AccountStatement } from '../data/billing.service';
import { AccountStatementComponent, monthStart } from './account-statement.component';

const STATEMENT: AccountStatement = {
  account_id: 'a1',
  from: '2026-10-01',
  to: '2026-10-18',
  currencies: [{
    currency: 'SAR',
    opening_balance: '100',
    entries: [
      { date: '2026-10-05', kind: 'invoice', reference: 'INV-2026-000007', invoice_id: 'i1', amount: '115' },
      { date: '2026-10-09', kind: 'payment', reference: 'PAY-1', invoice_id: 'i1', amount: '-50' },
    ],
    closing_balance: '165',
  }],
};

describe('AccountStatementComponent (F4-T16)', () => {
  function create(lang: 'en' | 'ar', calendar: 'gregorian' | 'hijri' | null = null) {
    const get = vi.fn((_: string) => of(STATEMENT));
    const current = signal(lang);
    TestBed.configureTestingModule({
      imports: [AccountStatementComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        {
          provide: LangService,
          useValue: {
            translate: (k: string) => k,
            current,
            isRtl: computed(() => current() === 'ar'),
            intlLocale: computed(() => (current() === 'ar' ? 'ar-SA-u-nu-latn' : 'en-GB')),
          },
        },
        {
          provide: UserPreferencesService,
          useValue: { calendar: signal(calendar), digits: signal(null), timezone: signal(null) },
        },
      ],
    });
    const fixture = TestBed.createComponent(AccountStatementComponent);
    fixture.componentRef.setInput('id', 'a1');
    fixture.detectChanges();
    return { fixture, get };
  }

  it('renders right to left in Arabic', () => {
    const { fixture } = create('ar');
    const section = (fixture.nativeElement as HTMLElement).querySelector('section');
    expect(section?.getAttribute('dir')).toBe('rtl');
  });

  it('asks for this month and shows opening, entries and closing per currency', () => {
    const { fixture, get } = create('en');
    const url = get.mock.calls[0][0];
    expect(url).toContain('/api/v1/billing/accounts/a1/statement?from=');
    const el = fixture.nativeElement as HTMLElement;
    const table = el.querySelector('table[data-currency="SAR"]');
    expect(table).not.toBeNull();
    expect(table?.querySelectorAll('tbody tr').length).toBe(3);
    expect(el.textContent).toContain('INV-2026-000007');
    expect(el.textContent).toContain('billingStatement.kind.payment');
    expect(table?.querySelector('tfoot td')?.textContent).toContain('165.00');
    expect(el.querySelector('section')?.getAttribute('dir')).toBe('ltr');
  });

  it('shows the period in the Hijri calendar for a viewer who reads dates in it', () => {
    const { fixture } = create('en', 'hijri');
    fixture.componentInstance.from.set('2026-10-01');
    fixture.componentInstance.to.set('2026-10-18');
    fixture.detectChanges();
    expect(fixture.componentInstance.hijriPeriod()).toContain('1448');
  });

  it('shows no Hijri period to a viewer who reads Gregorian dates', () => {
    const { fixture } = create('en', 'gregorian');
    expect(fixture.componentInstance.hijriPeriod()).toBeNull();
  });

  it('starts a period on the first of the month', () => {
    expect(monthStart('2026-10-18')).toBe('2026-10-01');
  });
});
