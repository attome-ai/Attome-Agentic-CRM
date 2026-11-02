import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { StoreComponent, parseQuickOrder } from './store.component';
import { Cart, StoreService } from './store.service';

const EMPTY: Cart = { cart_id: null, currency: 'SAR', lines: [], total: '0', can_check_out: false };
const ONE: Cart = {
  cart_id: 'c1', currency: 'SAR', total: '300.00', can_check_out: true,
  lines: [{ product_id: 'p1', name: 'Widget', quantity: '3', unit_price: '100', line_total: '300.00' }],
};

describe('StoreComponent (F7-T2)', () => {
  const current = signal<'en' | 'ar'>('en');
  const store = {
    catalogue: vi.fn((_k: string, search: string) => of(
      search === 'NOPE' ? [] : [{ product_id: 'p1', name: 'Widget', name_ar: 'قطعة', sku: 'WID-1', price: '100', currency: 'SAR' }])),
    cart: vi.fn(() => of(EMPTY)),
    setLine: vi.fn(() => of(ONE)),
    checkout: vi.fn(() => of({ order_id: 'o1', total: '300.00', needs_approval: true })),
    orders: vi.fn(() => of([{ id: 'o1', name: 'Portal order', status: 'draft', currency: 'SAR', grand_total: '300.00' }])),
    orderLines: vi.fn(() => of({ order_id: 'o1', lines: [] })),
  };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    TestBed.configureTestingModule({
      imports: [StoreComponent],
      providers: [
        { provide: StoreService, useValue: store },
        {
          provide: LangService,
          useValue: {
            current,
            translate: (k: string) => k,
            isRtl: () => current() === 'ar',
            intlLocale: () => (current() === 'ar' ? 'ar-SA' : 'en-US'),
            errorText: () => 'error',
          },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(StoreComponent);
    fixture.componentRef.setInput('keyword', 'acme');
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  it('renders the products in English', () => {
    const { el } = render();
    expect(el.querySelector('section')?.getAttribute('dir')).toBe('ltr');
    expect(store.catalogue).toHaveBeenCalledWith('acme', '');
    expect(el.querySelector('[data-testid="ps-items"]')?.textContent).toContain('Widget');
  });

  it('renders right to left in Arabic with Arabic names', () => {
    current.set('ar');
    const { el } = render();
    expect(el.querySelector('section')?.getAttribute('dir')).toBe('rtl');
    expect(el.querySelector('[data-testid="ps-items"]')?.textContent).toContain('قطعة');
  });

  it('adds a product to the cart', () => {
    const { fixture, el } = render();
    (el.querySelector('[data-testid="ps-add-p1"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(store.setLine).toHaveBeenCalledWith('acme', 'p1', 1);
    expect(el.querySelector('[data-testid="ps-notice"]')?.textContent).toContain('portalStore.added');
  });

  it('checks out and shows the orders, noting the approval', () => {
    const { fixture, el } = render();
    fixture.componentInstance.setTab('cart');
    fixture.componentInstance.cart.set(ONE);
    fixture.detectChanges();
    (el.querySelector('[data-testid="ps-checkout"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(store.checkout).toHaveBeenCalledWith('acme');
    expect(el.querySelector('[data-testid="ps-orders"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="ps-notice"]')?.textContent).toContain('portalStore.orderedNeedsApproval');
  });

  it('removes a line', () => {
    const { fixture, el } = render();
    fixture.componentInstance.setTab('cart');
    fixture.componentInstance.cart.set(ONE);
    fixture.detectChanges();
    (el.querySelector('[data-testid="ps-remove-p1"]') as HTMLButtonElement).click();
    expect(store.setLine).toHaveBeenCalledWith('acme', 'p1', 0);
  });

  it('adds a quick order by SKU and names what is not on sale', () => {
    const { fixture } = render();
    const c = fixture.componentInstance;
    c.quickText.set('WID-1 3\nNOPE 2');
    c.quickOrder(new Event('submit'));
    expect(store.setLine).toHaveBeenCalledWith('acme', 'p1', 3);
    expect(c.error()).toBe('portalStore.notFound');
  });

  it('asks to sign in on a 401', () => {
    store.catalogue.mockReturnValueOnce(throwError(() => ({ status: 401 })));
    const { el } = render();
    expect(el.querySelector('[data-testid="ps-signed-out"]')).not.toBeNull();
  });
});

describe('parseQuickOrder (F7-T2)', () => {
  it('reads SKU and quantity lines, 1 by default', () => {
    expect(parseQuickOrder('A-1 2\n\nB-2\nC-3,4')).toEqual({
      lines: [{ sku: 'A-1', quantity: 2 }, { sku: 'B-2', quantity: 1 }, { sku: 'C-3', quantity: 4 }],
      bad: null,
    });
  });

  it('names a bad line', () => {
    expect(parseQuickOrder('A-1 two').bad).toBe('A-1 two');
    expect(parseQuickOrder('A-1 -1').bad).toBe('A-1 -1');
  });
});
