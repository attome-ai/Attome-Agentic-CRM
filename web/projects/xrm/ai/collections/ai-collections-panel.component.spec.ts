import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiCollectionsPanelComponent } from './ai-collections-panel.component';
import { PaymentPromise, awaitsReview, stillOpen } from './ai-collections.service';

const PENDING: PaymentPromise = {
  id: 'p1', promised_amount: 1250.5, promised_date: '2027-03-04', source: 'agent', status: 'open',
  review_status: 'pending', note: 'سأدفع يوم الخميس', created_at: '2027-03-01T08:00:00Z', row_version: 3,
};
const CONFIRMED: PaymentPromise = { ...PENDING, id: 'p2', review_status: 'confirmed', row_version: 5 };

function page<T>(items: T[]) {
  return { items, total: items.length, page: 1, page_size: 100 };
}

describe('AiCollectionsPanelComponent (AI5-T7)', () => {
  function create(promises: PaymentPromise[] = [PENDING, CONFIRMED], reminders: unknown[] = []) {
    const get = vi.fn((path: string) => of(path.includes('/promises') ? page(promises) : page(reminders)));
    const post = vi.fn((_: string, __: unknown, ___?: unknown) => of({ id: 'p1', row_version: 4 }));
    TestBed.configureTestingModule({
      imports: [AiCollectionsPanelComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-US' },
        },
      ],
    });
    const fixture = TestBed.createComponent(AiCollectionsPanelComponent);
    fixture.componentRef.setInput('invoiceId', 'inv1');
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('lists the invoice promises and reminders', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/ai/collections/invoices/inv1/promises?page=1&page_size=100');
    expect(get).toHaveBeenCalledWith('/api/v1/ai/collections/invoices/inv1/reminders?page=1&page_size=100');
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('li[data-promise]').length).toBe(2);
    expect(el.textContent).toContain('سأدفع يوم الخميس');
  });

  it('confirms with the row version as If-Match', () => {
    const { fixture, post } = create();
    fixture.componentInstance.review(PENDING, true);
    expect(post).toHaveBeenCalledWith('/api/v1/ai/collections/promises/p1/confirm', {}, { ifMatch: 3 });
    fixture.componentInstance.mark(CONFIRMED, 'kept');
    expect(post).toHaveBeenCalledWith('/api/v1/ai/collections/promises/p2/status', { status: 'kept' }, { ifMatch: 5 });
  });

  it('says when there is nothing yet', () => {
    const { fixture } = create([], []);
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-no-promises]')).not.toBeNull();
    expect(el.querySelector('[data-no-reminders]')).not.toBeNull();
  });

  it('offers review only while pending, and kept or broken only while open', () => {
    expect(awaitsReview(PENDING)).toBe(true);
    expect(awaitsReview(CONFIRMED)).toBe(false);
    expect(stillOpen(CONFIRMED)).toBe(true);
    expect(stillOpen({ ...CONFIRMED, status: 'kept' })).toBe(false);
    expect(stillOpen({ ...PENDING, review_status: 'rejected' })).toBe(false);
  });
});
