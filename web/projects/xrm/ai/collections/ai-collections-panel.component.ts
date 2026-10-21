import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { forkJoin } from 'rxjs';

import {
  AiCollectionsService,
  CollectionsReminder,
  PaymentPromise,
  awaitsReview,
  stillOpen,
} from './ai-collections.service';

/**
 * AI5-T7: an invoice's collections — the reminders the collections run
 * sent or found, and the customer's payment promises with their amount,
 * date and words. A promise an agent read from a reply waits for a person
 * to confirm or reject it; an open promise is marked kept or broken. Every
 * change carries the promise's `row_version`. Dates follow the viewer's
 * calendar (`localDate`: Gregorian, Hijri, or both); logical CSS only, so
 * the panel mirrors in Arabic.
 */
@Component({
  selector: 'xrm-ai-collections-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="acp">
      <h3>{{ 'aiCollections.title' | translate }}</h3>
      @if (error(); as message) { <p class="acp-error" role="alert">{{ message }}</p> }

      <h4>{{ 'aiCollections.promises' | translate }}</h4>
      <ul class="acp-list">
        @for (p of promises(); track p.id) {
          <li [attr.data-promise]="p.id">
            <span class="acp-main">
              @if (p.promised_amount !== null) { <strong>{{ p.promised_amount }}</strong> }
              @if (p.promised_date) { <span>{{ p.promised_date | localDate }}</span> }
            </span>
            <small class="acp-tag">{{ 'aiCollections.status.' + (p.status ?? 'open') | translate }}</small>
            @if (p.review_status) {
              <small class="acp-tag">{{ 'aiCollections.review.' + p.review_status | translate }}</small>
            }
            @if (p.note) { <q class="acp-note">{{ p.note }}</q> }
            <span class="acp-actions">
              @if (pending(p)) {
                <button type="button" (click)="review(p, true)" [disabled]="busy()">{{ 'aiCollections.confirm' | translate }}</button>
                <button type="button" (click)="review(p, false)" [disabled]="busy()">{{ 'aiCollections.reject' | translate }}</button>
              } @else if (open(p)) {
                <button type="button" (click)="mark(p, 'kept')" [disabled]="busy()">{{ 'aiCollections.kept' | translate }}</button>
                <button type="button" (click)="mark(p, 'broken')" [disabled]="busy()">{{ 'aiCollections.broken' | translate }}</button>
              }
            </span>
          </li>
        } @empty {
          <li class="acp-muted" data-no-promises>{{ 'aiCollections.noPromises' | translate }}</li>
        }
      </ul>

      <h4>{{ 'aiCollections.reminders' | translate }}</h4>
      <ul class="acp-list">
        @for (r of reminders(); track r.id) {
          <li [attr.data-reminder]="r.id">
            <span class="acp-main">{{ 'aiCollections.reason.' + r.reason | translate }}</span>
            <span>{{ r.window_start | localDate }}</span>
            <small class="acp-tag">{{ 'aiCollections.reminderStatus.' + r.status | translate }}</small>
          </li>
        } @empty {
          <li class="acp-muted" data-no-reminders>{{ 'aiCollections.noReminders' | translate }}</li>
        }
      </ul>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .acp { display: flex; flex-direction: column; gap: 0.5rem; }
    .acp h3 { margin-block: 0; font-size: 1rem; }
    .acp h4 { margin-block: 0.5rem 0; font-size: 0.875rem; }
    .acp-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.375rem; }
    .acp-list li { display: flex; flex-wrap: wrap; gap: 0.5rem 0.75rem; align-items: baseline;
      padding-block: 0.375rem; border-block-end: 1px solid var(--color-border); }
    .acp-main { display: inline-flex; gap: 0.5rem; flex: 1 1 10rem; }
    .acp-tag { color: var(--color-text-secondary); }
    .acp-note { flex-basis: 100%; color: var(--color-text-secondary); font-size: 0.8125rem; }
    .acp-actions { display: inline-flex; gap: 0.375rem; margin-inline-start: auto; }
    .acp-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .acp-error { color: var(--color-danger); }
  `],
})
export class AiCollectionsPanelComponent implements OnInit {
  private readonly collections = inject(AiCollectionsService);
  private readonly lang = inject(LangService);

  /** The invoice's id. */
  readonly invoiceId = input.required<string>();

  readonly promises = signal<PaymentPromise[]>([]);
  readonly reminders = signal<CollectionsReminder[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly pending = awaitsReview;
  readonly open = stillOpen;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    const id = this.invoiceId();
    forkJoin({
      promises: this.collections.promises(id),
      reminders: this.collections.reminders(id),
    }).subscribe({
      next: ({ promises, reminders }) => {
        this.promises.set(promises.items);
        this.reminders.set(reminders.items);
      },
      // Not found is a deployment without AI collections: nothing to show.
      error: (e: ApiError) => this.error.set(e.status === 404 ? null : this.lang.errorText(e)),
    });
  }

  review(promise: PaymentPromise, confirm: boolean): void {
    this.busy.set(true);
    this.collections.review(promise, confirm).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }

  mark(promise: PaymentPromise, status: 'kept' | 'broken'): void {
    this.busy.set(true);
    this.collections.setStatus(promise, status).subscribe({
      next: () => { this.busy.set(false); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
