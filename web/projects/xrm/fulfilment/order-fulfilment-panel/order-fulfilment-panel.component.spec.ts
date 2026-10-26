import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import {
  OrderFulfilment, OrderFulfilmentPanelComponent, trackingUrl,
} from './order-fulfilment-panel.component';

const ORDER: OrderFulfilment = {
  order_id: 'o1',
  lines: [
    {
      line_id: 'l1', fulfilment_order_id: 'f1', order_line_ref: 'Line 1', product_ref: null,
      ordered: 10, shipped: 6, delivered: 4, backordered: 4, promised_date: '2026-11-02T00:00:00Z',
      status: 'partly_shipped',
      shipments: [
        { shipment_id: 's1', carrier: 'aramex', tracking_number: 'AX123', status: 'in_transit', quantity: 6 },
      ],
    },
  ],
};

function setup(rtl: boolean) {
  const get = vi.fn(() => of(ORDER));
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    imports: [OrderFulfilmentPanelComponent],
    providers: [
      { provide: ApiService, useValue: { get } },
      {
        provide: LangService,
        useValue: {
          translate: (key: string) => key,
          isRtl: signal(rtl),
          intlLocale: () => (rtl ? 'ar-SA' : 'en-GB'),
          current: () => (rtl ? 'ar' : 'en'),
        },
      },
      {
        provide: UserPreferencesService,
        useValue: { timezone: () => 'UTC', calendar: () => 'gregorian', digits: () => 'latn' },
      },
    ],
  });
  const fixture = TestBed.createComponent(OrderFulfilmentPanelComponent);
  fixture.componentRef.setInput('recordId', 'o1');
  fixture.detectChanges();
  return { fixture, get };
}

describe('OrderFulfilmentPanelComponent (F6-T17)', () => {
  it('shows_line_rollup', () => {
    const { fixture, get } = setup(false);
    expect(get).toHaveBeenCalledWith('/api/v1/fulfilment/orders', { order_id: 'o1' });
    const el: HTMLElement = fixture.nativeElement;
    const rows = el.querySelectorAll('[data-testid="order-fulfilment-line"]');
    expect(rows.length).toBe(1);
    const text = rows[0].textContent ?? '';
    for (const n of ['10', '6', '4']) expect(text).toContain(n);
    const link = el.querySelector<HTMLAnchorElement>('[data-testid="order-fulfilment-tracking"]');
    expect(link?.href).toContain('AX123');
    expect(trackingUrl('own_fleet', 'X')).toBeNull();
    expect(trackingUrl('dhl', null)).toBeNull();
  });

  it('mirrors_in_rtl', () => {
    const { fixture } = setup(true);
    const section = (fixture.nativeElement as HTMLElement).querySelector('[data-testid="order-fulfilment"]');
    expect(section?.getAttribute('dir')).toBe('rtl');
  });
});
