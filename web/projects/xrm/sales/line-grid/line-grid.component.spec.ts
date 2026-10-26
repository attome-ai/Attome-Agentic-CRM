import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SalesApiService } from '../sales-api.service';
import type { SalesLine } from '../sales-api.service';
import { LineGridComponent, formatMoney, lineTotal, minorUnits } from './line-grid.component';

const OPP = '01900000-0000-7000-8000-0000000000d1';

function line(id: string, extra: Partial<SalesLine> = {}): SalesLine {
  return {
    id, product_ref: `p-${id}`, name: `Product ${id}`, quantity: '2', list_price: '10.000',
    sales_price: null, discount_percent: null, discount_amount: null, line_total: '20.000',
    line_kind: 'one_time', recurrence: null, term_months: null, ...extra,
  };
}

describe('LineGridComponent (D6-T10)', () => {
  let sales: Record<string, ReturnType<typeof vi.fn>>;
  let lines: SalesLine[];

  beforeEach(() => {
    lines = [line('a'), line('b', { quantity: '1', list_price: '5.500' })];
    sales = {
      lines: vi.fn(() => of(lines)),
      updateLine: vi.fn(() => of({})),
      addLine: vi.fn(() => of({})),
      products: vi.fn(() => of([])),
      sync: vi.fn(() => of({ status: 'synced' })),
      featureOn: vi.fn(() => of(true)),
      opportunity: vi.fn(() => of({ data: { currency: 'KWD', price_list_ref: 'pl-1' }, row_version: 3 })),
    };
    TestBed.configureTestingModule({
      imports: [LineGridComponent],
      providers: [
        { provide: SalesApiService, useValue: sales },
        {
          provide: LangService,
          useValue: { intlLocale: () => 'en-US', translate: (k: string) => k, errorText: (e: { message: string }) => e.message },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(LineGridComponent);
    fixture.componentRef.setInput('recordId', OPP);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    return { fixture, el };
  }

  it('kwd shows three decimals', () => {
    expect(minorUnits('KWD')).toBe(3);
    expect(minorUnits('bhd')).toBe(3);
    expect(minorUnits('SAR')).toBe(2);
    expect(minorUnits('JPY')).toBe(0);
    expect(formatMoney(25.5, 'KWD', 'en-US')).toBe('25.500 KWD');
    expect(formatMoney(25.5, 'SAR', 'en-US')).toBe('25.50 SAR');
    const { el } = render();
    expect(el.querySelector('[data-testid="line-grid-total"]')!.textContent).toBe('25.500 KWD');
  });

  it('totals update while typing', () => {
    expect(lineTotal(line('x'), { quantity: '3', sales_price: '', discount_percent: '10' })).toBeCloseTo(27);
    const { fixture, el } = render();
    const qty = el.querySelector<HTMLInputElement>('[data-line="a"] [data-field="quantity"]')!;
    qty.value = '4';
    qty.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="line-grid-total"]')!.textContent).toBe('45.500 KWD');
    expect(sales['updateLine']).not.toHaveBeenCalled();

    qty.dispatchEvent(new Event('blur'));
    expect(sales['updateLine']).toHaveBeenCalledWith(OPP, 'a', 3, { quantity: '4' });
  });

  it('cost hidden without grant', () => {
    const { fixture, el } = render();
    expect(el.querySelector('[data-testid="line-grid-cost"]')).toBeNull();
    lines = [line('a', { unit_cost: '4.000' })];
    fixture.componentInstance.load(OPP);
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="line-grid-cost"]')).not.toBeNull();
  });

  it('rtl grid mirrors columns', () => {
    document.documentElement.setAttribute('dir', 'rtl');
    try {
      const { el } = render();
      // Logical CSS mirrors the columns; every number stays left to right.
      const numbers = el.querySelectorAll('[data-field="total"], .lg-num, [data-testid="line-grid-total"]');
      expect(numbers.length).toBeGreaterThan(0);
      numbers.forEach(n => expect(n.getAttribute('dir')).toBe('ltr'));
    } finally {
      document.documentElement.removeAttribute('dir');
    }
  });

  it('asks which lines to keep when both sides changed', () => {
    sales['sync']
      .mockReturnValueOnce(throwError(() => ({ kind: 'conflict', status: 409, code: 'sync_both_changed', message: '' })))
      .mockReturnValue(of({ status: 'synced' }));
    const { fixture, el } = render();
    el.querySelector<HTMLButtonElement>('[data-testid="line-grid-sync"]')!.click();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="line-grid-conflict"]')).not.toBeNull();
    el.querySelector<HTMLButtonElement>('[data-testid="line-grid-take"]')!.click();
    expect(sales['sync']).toHaveBeenLastCalledWith(OPP, 'from_quote', true);
  });

  it('adds a product from the price list', () => {
    sales['products'].mockReturnValue(of([{ product_id: 'p9', name: 'Router', name_ar: null, sku: null, list_price: '99' }]));
    const { fixture, el } = render();
    fixture.componentInstance.search('rou');
    fixture.detectChanges();
    expect(sales['products']).toHaveBeenCalledWith('pl-1', 'rou');
    el.querySelector<HTMLButtonElement>('[data-product="p9"]')!.click();
    expect(sales['addLine']).toHaveBeenCalledWith(OPP, 3, { product_ref: 'p9', quantity: '1' });
  });
});
