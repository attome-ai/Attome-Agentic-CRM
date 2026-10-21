import { Injectable, inject } from '@angular/core';
import { ApiService, type Page } from '@attome/base';
import { Observable } from 'rxjs';

/** `attome_ai::collections_routes::AiPaymentPromise`. */
export interface PaymentPromise {
  id: string;
  promised_amount: number | null;
  promised_date: string | null;
  source: 'agent' | 'staff' | 'portal' | string | null;
  status: 'open' | 'kept' | 'broken' | string | null;
  review_status: 'pending' | 'confirmed' | 'rejected' | string | null;
  note: string | null;
  created_at: string | null;
  row_version: number;
}

/** `attome_ai::collections_routes::AiCollectionsReminder`. */
export interface CollectionsReminder {
  id: string;
  reason: 'invoice_due' | 'invoice_overdue' | string;
  status: string;
  window_start: string;
  updated_at: string | null;
}

/** `attome_ai::collections_routes::AiPromiseChanged`. */
export interface PromiseChanged {
  id: string;
  row_version: number;
}

/** Whether a promise waits for a person's review. */
export function awaitsReview(promise: PaymentPromise): boolean {
  return promise.review_status === 'pending';
}

/** Whether a promise can still be marked kept or broken. */
export function stillOpen(promise: PaymentPromise): boolean {
  return promise.status === 'open' && promise.review_status !== 'rejected';
}

/** AI5-T7: the collections routes (AI5-T6). */
@Injectable({ providedIn: 'root' })
export class AiCollectionsService {
  private readonly api = inject(ApiService);

  promises(invoiceId: string): Observable<Page<PaymentPromise>> {
    return this.api.get<Page<PaymentPromise>>(
      `/api/v1/ai/collections/invoices/${encodeURIComponent(invoiceId)}/promises?page=1&page_size=100`,
    );
  }

  reminders(invoiceId: string): Observable<Page<CollectionsReminder>> {
    return this.api.get<Page<CollectionsReminder>>(
      `/api/v1/ai/collections/invoices/${encodeURIComponent(invoiceId)}/reminders?page=1&page_size=100`,
    );
  }

  review(promise: PaymentPromise, confirm: boolean): Observable<PromiseChanged> {
    const action = confirm ? 'confirm' : 'reject';
    return this.api.post<PromiseChanged>(
      `/api/v1/ai/collections/promises/${encodeURIComponent(promise.id)}/${action}`,
      {},
      { ifMatch: promise.row_version },
    );
  }

  setStatus(promise: PaymentPromise, status: 'kept' | 'broken'): Observable<PromiseChanged> {
    return this.api.post<PromiseChanged>(
      `/api/v1/ai/collections/promises/${encodeURIComponent(promise.id)}/status`,
      { status },
      { ifMatch: promise.row_version },
    );
  }
}
