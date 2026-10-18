import { computed, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { PayPageComponent, PayView, formatPayAmount } from './pay-page.component';

const VIEW: PayView = {
  amount: '115.00',
  currency: 'SAR',
  invoice_number: 'INV-2026-000042',
  seller_name: 'Acme Trading',
  locale: 'en',
  expires_at: '2026-10-21T10:00:00Z',
};

function create(answer: 'view' | 'missing', locale: 'en' | 'ar' = 'en') {
  const get = vi.fn(() =>
    answer === 'view' ? of({ ...VIEW, locale }) : throwError(() => ({ status: 404 })),
  );
  const post = vi.fn(() => of({ payment_id: 'p1', redirect_url: null, widget: null }));
  const current = signal<string>('en');
  TestBed.configureTestingModule({
    imports: [PayPageComponent],
    providers: [
      { provide: ApiService, useValue: { get, post } },
      {
        provide: LangService,
        useValue: {
          translate: (k: string) => k,
          current,
          set: (lang: string) => {
            current.set(lang);
            return Promise.resolve();
          },
          toggle: () => {
            current.set(current() === 'ar' ? 'en' : 'ar');
            return Promise.resolve();
          },
          isRtl: computed(() => current() === 'ar'),
          intlLocale: computed(() => (current() === 'ar' ? 'ar-SA-u-nu-latn' : 'en-GB')),
        },
      },
    ],
  });
  const fixture = TestBed.createComponent(PayPageComponent);
  fixture.componentRef.setInput('token', 'pub.secret');
  fixture.detectChanges();
  return { fixture, el: fixture.nativeElement as HTMLElement, get, post };
}

describe('PayPageComponent (F5-T15)', () => {
  it('shows_amount_and_invoice', () => {
    const { el, get } = create('view');
    expect(get).toHaveBeenCalledWith('/api/v1/pay/pub.secret');
    expect(el.textContent).toContain('INV-2026-000042');
    expect(el.textContent).toContain('Acme Trading');
    expect(el.textContent).toContain('115.00');
    expect(el.querySelector('.pay-button')).not.toBeNull();
  });

  it('unknown_token_shows_not_found', () => {
    const { el } = create('missing');
    expect(el.querySelector('[role="alert"]')?.textContent).toContain('pay.notFound');
    expect(el.querySelector('.pay-button')).toBeNull();
  });

  it('arabic_sets_rtl', () => {
    const { fixture, el } = create('view', 'ar');
    fixture.detectChanges();
    expect(el.querySelector('main')?.getAttribute('dir')).toBe('rtl');
    expect(el.querySelector('main')?.getAttribute('lang')).toBe('ar');
  });

  it('pays through the checkout', () => {
    const { fixture, el, post } = create('view');
    (el.querySelector('.pay-button') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/pay/pub.secret/checkout', {});
  });

  it('formats three-decimal currencies with three decimals', () => {
    expect(formatPayAmount('1.5', 'KWD', 'en-GB')).toContain('1.500');
    expect(formatPayAmount('115', 'SAR', 'en-GB')).toContain('115.00');
  });
});
