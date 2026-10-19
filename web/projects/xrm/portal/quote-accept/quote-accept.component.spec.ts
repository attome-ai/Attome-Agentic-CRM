import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { QuoteAcceptComponent, QuoteView, money } from './quote-accept.component';

const quote: QuoteView = {
  quote_number: 'Q-1447-0012', name: 'Fleet maintenance', currency: 'SAR', valid_from: null,
  expires_on: '2026-11-30T00:00:00Z', payment_terms: '30 days', terms: 'Prices exclude delivery.',
  subtotal: '10000.00', discount_total: '500.00', vat_estimate: '1425.00', grand_total: '10925.00',
  status: 'sent', accepted_by_name: null, decided_at: null,
  lines: [{ product: 'Service plan', quantity: '2', unit_price: '5000.00', discount_amount: null, tax_amount: null, line_total: '10000.00' }],
};
const lang = {
  translate: (k: string) => k, current: () => 'en', isRtl: () => false, intlLocale: () => 'en-US', toggle: vi.fn(),
};

describe('QuoteAcceptComponent (D9-T3)', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = {
      get: vi.fn(() => of(quote)),
      post: vi.fn(() => of({ ...quote, status: 'accepted', accepted_by_name: 'Fahad Al-Harbi' })),
    };
    TestBed.configureTestingModule({
      imports: [QuoteAcceptComponent],
      providers: [{ provide: ApiService, useValue: api }, { provide: LangService, useValue: lang }],
    });
  });

  function render(token = 'tok.sig') {
    const fixture = TestBed.createComponent(QuoteAcceptComponent);
    fixture.componentRef.setInput('token', token);
    fixture.detectChanges();
    return fixture;
  }

  it('formats exact amounts in the quote currency', () => {
    expect(money('10925.00', 'SAR', 'en-US')).toContain('10,925.00');
    expect(money(null, 'SAR', 'en-US')).toBe('');
    expect(money('12.5', null, 'en-US')).toBe('12.5');
  });

  it('shows the quote and accepts it with the customer\'s name', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    expect(api.get).toHaveBeenCalledWith('/api/v1/quote-acceptance/tok.sig');
    expect(el.querySelector('[data-testid="qa-total"]')?.textContent).toContain('10,925.00');
    expect(el.querySelectorAll('[data-testid="qa-lines"] tbody tr').length).toBe(1);
    const cmp = fixture.componentInstance;
    cmp.name = 'Fahad Al-Harbi';
    cmp.decide('accept');
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/quote-acceptance/tok.sig', {
      decision: 'accept', name: 'Fahad Al-Harbi', note: null,
    });
    expect(el.querySelector('[data-testid="qa-decided"]')?.textContent).toContain('quoteAccept.status.accepted');
    expect(el.querySelector('[data-testid="qa-form"]')).toBeNull();
  });

  it('does not decide without a name, and shows an invalid link plainly', () => {
    const fixture = render();
    fixture.componentInstance.decide('reject');
    expect(api.post).not.toHaveBeenCalled();

    api.get.mockReturnValue(throwError(() => ({ status: 404 })));
    const missing = render('altered');
    expect((missing.nativeElement as HTMLElement).querySelector('[data-testid="qa-missing"]')).not.toBeNull();
  });
});
