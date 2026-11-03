import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { PageContext } from '@attome/xrm/core/page-runtime';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { StoreService } from '../store.service';
import { StoreBasket, basketTotal, cents } from './store-basket';
import {
  StoreCartComponent, StoreCheckoutComponent, StoreProductDetailComponent, StoreProductGridComponent, checkoutMissing, validCode,
} from './store-blocks';

const LAMP = {
  product_id: 'p1', name: 'Lamp', name_ar: 'مصباح', sku: 'LAMP-1', price: '100', currency: 'SAR',
  vat: '15.00', price_with_vat: '115.00', stock: 'low' as const,
};
const GONE = { ...LAMP, product_id: 'p2', name: 'Chair', name_ar: 'كرسي', stock: 'sold_out' as const };

describe('store blocks (F8-T10)', () => {
  const store = {
    guestCatalogue: vi.fn(() => of([LAMP, GONE])),
    shipping: vi.fn(() => of([{ rate_id: 'r1', zone: 'KSA', method: 'flat', amount: '25', cod_fee: '10' }])),
    guestStart: vi.fn(() => of({ checkout_id: 'k1', expires_at: '2026-11-03T10:10:00Z' })),
    guestConfirm: vi.fn(() => of({
      order_id: 'o1', subtotal: '230', discount_total: '0', shipping: '25', vat: '38.25', total: '293.25', payment_url: null,
    })),
    orders: vi.fn(() => of([])),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    try {
      sessionStorage.clear();
    } catch {
      // no storage in this runner
    }
    TestBed.configureTestingModule({
      providers: [
        PageContext,
        { provide: StoreService, useValue: store },
        {
          provide: LangService,
          useValue: {
            translate: (k: string) => k,
            isRtl: () => false,
            intlLocale: () => 'en-US',
            errorText: () => 'error',
          },
        },
      ],
    });
    TestBed.inject(StoreBasket).open('shop');
  });

  function render<T>(type: new (...args: never[]) => T, arabic = false, props: Record<string, unknown> = {}) {
    const ctx = TestBed.inject(PageContext);
    ctx.site.set('shop');
    ctx.arabic.set(arabic);
    const fixture = TestBed.createComponent(type);
    fixture.componentRef.setInput('node', { id: 'n1', type: 'custom', component: 'store.x', props });
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('shows VAT-inclusive total', () => {
    const basket = TestBed.inject(StoreBasket);
    basket.add(LAMP, 'Lamp', 2);
    const { el } = render(StoreCartComponent);
    expect(el.querySelector('[data-total]')?.textContent).toContain('storeBlocks.totalWithVat');
    expect(basketTotal(basket.lines())).toBe('230.00');

    const grid = render(StoreProductGridComponent);
    expect(store.guestCatalogue).toHaveBeenCalledWith('shop', '');
    const first = grid.el.querySelector('[data-product="p1"] [data-price]')?.textContent ?? '';
    expect(first).toContain('115');
  });

  it('sets dir=rtl for Arabic', () => {
    const { el } = render(StoreProductGridComponent, true);
    expect(el.querySelector('[data-testid="store-product-grid"]')?.getAttribute('dir')).toBe('rtl');
    expect(el.textContent).toContain('مصباح');
    const english = render(StoreProductGridComponent, false);
    expect(english.el.querySelector('[data-testid="store-product-grid"]')?.getAttribute('dir')).toBe('ltr');
  });

  it('blocks checkout without code', () => {
    TestBed.inject(StoreBasket).add(LAMP, 'Lamp');
    const { fixture, cmp, el } = render(StoreCheckoutComponent);
    cmp.phone.set('0501234567');
    cmp.start();
    fixture.detectChanges();
    expect(store.guestStart).toHaveBeenCalledWith('shop', '0501234567', [{ product_id: 'p1', quantity: '1' }]);
    cmp.fullName.set('Sara Ali');
    cmp.address.set('King Fahd Rd');
    fixture.detectChanges();
    const place = el.querySelector<HTMLButtonElement>('[data-place]');
    expect(cmp.missing()).toEqual(['storeBlocks.needCode']);
    expect(place?.disabled).toBe(true);
    cmp.place();
    expect(store.guestConfirm).not.toHaveBeenCalled();

    cmp.code.set('123 456');
    fixture.detectChanges();
    expect(place?.disabled).toBe(false);
    cmp.place();
    expect(store.guestConfirm).toHaveBeenCalledWith('shop', expect.objectContaining({
      checkout_id: 'k1', code: '123456', shipping_rate_id: 'r1', country: 'SA', cash_on_delivery: false,
    }), 'guest-k1');
    expect(TestBed.inject(StoreBasket).lines()).toEqual([]);
  });

  it('does not add a sold-out product', () => {
    const { el } = render(StoreProductGridComponent);
    const buttons = el.querySelectorAll<HTMLButtonElement>('li button');
    expect(buttons[0].disabled).toBe(false);
    expect(buttons[1].disabled).toBe(true);
    expect(el.querySelector('[data-product="p2"] [data-stock]')?.textContent).toContain('storeBlocks.stock.sold_out');
  });

  it('shows one product with its VAT from the page props', () => {
    const { el } = render(StoreProductDetailComponent, false, { product_id: 'p1' });
    expect(el.querySelector('[data-price]')?.textContent).toContain('115');
    expect(el.querySelector('[data-vat]')?.textContent).toContain('storeBlocks.priceBreakdown');
  });

  it('checks codes and the checkout form, and counts in cents', () => {
    expect(validCode('123456')).toBe(true);
    expect(validCode('12345')).toBe(false);
    expect(validCode('12a456')).toBe(false);
    expect(checkoutMissing({ code: '', name: '', address: '', country: 'S', rate: null })).toHaveLength(5);
    expect(cents('0.1') + cents('0.2')).toBe(30);
  });
});
