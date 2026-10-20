import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SubscriptionTimelineComponent, TimelineRow, axis, place } from './subscription-timeline.component';

const rows: TimelineRow[] = [{
  lineId: 'l1', label: 'Line 1',
  segments: [
    { from: '2026-01-01', to: '2026-07-01', quantity: 5, unitPrice: 100, kind: 'new' },
    { from: '2026-07-01', to: null, quantity: 8, unitPrice: 100, kind: 'add' },
  ],
}];

describe('subscription timeline helpers (F3-T14)', () => {
  it('lays segments on an axis from the first start', () => {
    const { start, end } = axis(rows, '2026-10-20');
    expect(new Date(start).toISOString().slice(0, 10)).toBe('2026-01-01');
    expect(end).toBeGreaterThan(Date.parse('2026-10-20T00:00:00Z'));
    const first = place(rows[0].segments[0], start, end);
    expect(first.start).toBe(0);
    const second = place(rows[0].segments[1], start, end);
    expect(second.start).toBeCloseTo(first.width, 5);
    expect(second.start + second.width).toBeCloseTo(100, 5);
  });
});

describe('SubscriptionTimelineComponent (F3-T14)', () => {
  const api = { get: vi.fn() };
  const entities = { list: vi.fn() };
  const current = signal<'en' | 'ar'>('en');

  beforeEach(() => {
    vi.resetAllMocks();
    current.set('en');
    api.get.mockReturnValue(of({
      id: 's1', as_of: '2026-10-20', subscription: {},
      lines: [
        { line_id: 'l1', quantity: 8, unit_price: 100 },
        { line_id: 'l2', quantity: null, unit_price: null },
      ],
    }));
    entities.list.mockImplementation((_e: string, params: { filters: { value: string }[] }) => of({
      data: params.filters[0].value === 'l1'
        ? [
            { id: 'g1', data: { valid_from: '2026-01-01', valid_to: '2026-07-01', quantity: 5, unit_price: 100, change_kind: 'new' } },
            { id: 'g2', data: { valid_from: '2026-07-01', valid_to: null, quantity: 8, unit_price: 100, change_kind: 'add' } },
          ]
        : [{ id: 'g3', data: { valid_from: '2026-02-01', valid_to: '2026-05-01', quantity: 1, unit_price: 50, change_kind: 'new' } }],
    }));
    TestBed.configureTestingModule({
      imports: [SubscriptionTimelineComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: EntityService, useValue: entities },
        {
          provide: LangService,
          useValue: {
            translate: (k: string) => k, current, errorText: () => 'failed', isRtl: () => current() === 'ar',
            intlLocale: () => (current() === 'ar' ? 'ar-SA' : 'en-GB'),
          },
        },
        {
          provide: UserPreferencesService,
          useValue: { timezone: () => null, calendar: () => null, digits: () => null },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(SubscriptionTimelineComponent);
    fixture.componentRef.setInput('subscriptionId', 's1');
    fixture.componentRef.setInput('asOf', '2026-10-20');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  it('renders_one_row_per_line', () => {
    const fixture = render();
    expect(api.get).toHaveBeenCalledWith('/api/v1/billing/subscriptions/s1', { as_of: '2026-10-20' });
    const rowsEl = fixture.nativeElement.querySelectorAll('[data-testid="st-row"]');
    expect(rowsEl.length).toBe(2);
    expect(rowsEl[0].querySelectorAll('.st-seg').length).toBe(2);
    expect(rowsEl[1].textContent).toContain('billingSubscriptionTimeline.notInForce');
  });

  it('mirrors_in_rtl', () => {
    current.set('ar');
    const fixture = render();
    const panel = fixture.nativeElement.querySelector('[data-testid="st"]') as HTMLElement;
    expect(panel.getAttribute('dir')).toBe('rtl');
    // Segments are placed with logical insets: in a right-to-left panel the
    // axis start (0%) is on the right.
    const first = fixture.nativeElement.querySelector('.st-seg') as HTMLElement;
    expect(first.style.getPropertyValue('--st-start')).toBe('0%');
    expect(first.style.getPropertyValue('left')).toBe('');
  });
});
