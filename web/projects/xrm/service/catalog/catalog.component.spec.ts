import { TestBed } from '@angular/core/testing';
import { AuthService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CatalogOffering, ServiceAdminService, itemCancellable } from '../services/service-admin.service';
import { CatalogComponent } from './catalog.component';

const LAPTOP: CatalogOffering = {
  id: 'o1', name: 'Laptop', description: 'A work laptop', category: 'it', category_ref: null,
  category_name: 'Hardware', default_priority: 'medium', requires_approval: true,
};
const BADGE: CatalogOffering = {
  id: 'o2', name: 'Badge', description: null, category: null, category_ref: null,
  category_name: null, default_priority: 'low', requires_approval: false,
};

describe('itemCancellable', () => {
  it('lets an item be cancelled only before it finishes', () => {
    expect(itemCancellable('awaiting_approval')).toBe(true);
    expect(itemCancellable('fulfilling')).toBe(true);
    expect(itemCancellable('fulfilled')).toBe(false);
    expect(itemCancellable('cancelled')).toBe(false);
  });
});

describe('CatalogComponent', () => {
  const svc = {
    searchCatalog: vi.fn(),
    placeOrder: vi.fn(),
    myOrders: vi.fn(),
    cancelOrderItem: vi.fn(),
    listRecipients: vi.fn(),
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.resetAllMocks();
    svc.searchCatalog.mockReturnValue(of([LAPTOP, BADGE]));
    svc.placeOrder.mockReturnValue(of({ work_request_id: 'w1', reference: 'REQ-2026-00001', items: [] }));
    svc.myOrders.mockReturnValue(of([{
      work_request_id: 'w0', title: 'Order of 2 items', reference: 'REQ-2026-00000', created_at: null,
      items: [
        { id: 'i1', offering_id: 'o1', offering_name: 'Laptop', quantity: 1, status: 'awaiting_approval' },
        { id: 'i2', offering_id: 'o2', offering_name: 'Badge', quantity: 1, status: 'fulfilled' },
      ],
    }]));
    svc.cancelOrderItem.mockReturnValue(of({}));
    svc.listRecipients.mockReturnValue(of([{ id: 'u2', label: 'Sara' }]));
    TestBed.configureTestingModule({
      imports: [CatalogComponent],
      providers: [
        { provide: ServiceAdminService, useValue: svc },
        { provide: AuthService, useValue: { userId: () => 'u1' } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render() {
    const fixture = TestBed.createComponent(CatalogComponent);
    fixture.detectChanges();
    vi.advanceTimersByTime(300);
    fixture.detectChanges();
    return fixture;
  }

  it('lists the catalog and searches as you type', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('[data-testid="catalog-offering"]').length).toBe(2);
    const box = el.querySelector('[data-testid="catalog-search"]') as HTMLInputElement;
    box.value = 'إجازة';
    box.dispatchEvent(new Event('input'));
    vi.advanceTimersByTime(300);
    expect(svc.searchCatalog).toHaveBeenLastCalledWith('إجازة');
  });

  it('adds to the cart, merging a repeat, and places the order for the chosen person', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    const add = el.querySelectorAll('[data-testid="catalog-add"]');
    (add[0] as HTMLButtonElement).click();
    (add[0] as HTMLButtonElement).click();
    (add[1] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelectorAll('[data-testid="cart-line"]').length).toBe(2);
    const forWhom = el.querySelector('[data-testid="order-for"]') as HTMLSelectElement;
    forWhom.value = 'u2';
    forWhom.dispatchEvent(new Event('change'));
    (el.querySelector('[data-testid="place-order"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc.placeOrder).toHaveBeenCalledWith('u2', [
      { offering: LAPTOP, quantity: 2 },
      { offering: BADGE, quantity: 1 },
    ]);
    expect(el.querySelector('[data-testid="order-placed"]')).not.toBeNull();
  });

  it('shows my orders and cancels only an unfinished item', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    const cancels = el.querySelectorAll('[data-testid="cancel-item"]');
    expect(cancels.length).toBe(1);
    (cancels[0] as HTMLButtonElement).click();
    expect(svc.cancelOrderItem).toHaveBeenCalledWith('i1');
  });
});
