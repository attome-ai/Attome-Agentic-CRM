import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, output, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError, ApiService, LangService, TranslatePipe, type Page } from '@attome/base';
import { catchError, interval, of, startWith, switchMap } from 'rxjs';

/** `attome_service::router::QueueOffer` (J10-T1). */
export interface WorkOffer {
  id: string;
  item_id: string;
  queue_id: string;
  channel: string;
  status: string;
  offered_at: string;
  expires_at: string;
  record_entity: string | null;
  record_id: string | null;
}

/** What accepting an offer opens. */
export interface AcceptedOffer {
  entity: string;
  recordId: string;
  title: string;
}

/** How often the open offers are read. */
export const OFFER_POLL_MS = 5000;

/** Whole seconds left before `expiresAt` at `nowMs`, never below zero. Pure. */
export function secondsLeft(expiresAt: string, nowMs: number): number {
  const at = Date.parse(expiresAt);
  return Number.isNaN(at) ? 0 : Math.max(0, Math.ceil((at - nowMs) / 1000));
}

/** The offer to show: the soonest to expire still open at `nowMs`. Pure. */
export function currentOffer(offers: readonly WorkOffer[], nowMs: number): WorkOffer | null {
  return [...offers]
    .filter(o => o.status === 'offered' && secondsLeft(o.expires_at, nowMs) > 0)
    .sort((a, b) => a.expires_at.localeCompare(b.expires_at))[0] ?? null;
}

/**
 * J10-T2: the work offer toast. Reads the caller's open offers from the
 * unified router (J10-T1) every few seconds and shows the soonest with a
 * live countdown; Accept takes it and emits the record to open as a
 * session, Decline passes it to the next agent.
 */
@Component({
  selector: 'xrm-service-offer-toast',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (offer(); as o) {
      <div class="offer" role="alertdialog" aria-live="assertive" [attr.aria-label]="'serviceOffer.title' | translate"
           [attr.data-offer]="o.id">
        <i [class]="icon(o.channel)" aria-hidden="true"></i>
        <div class="offer-text">
          <strong>{{ 'serviceOffer.title' | translate }}</strong>
          <span>{{ ('serviceOffer.channel.' + o.channel) | translate }}</span>
          <span class="offer-left" data-testid="offer-left">{{ 'serviceOffer.left' | translate: { seconds: left() } }}</span>
        </div>
        <button type="button" class="btn-primary" (click)="accept(o)" [disabled]="busy()" data-testid="offer-accept">
          {{ 'serviceOffer.accept' | translate }}
        </button>
        <button type="button" class="btn-secondary" (click)="decline(o)" [disabled]="busy()" data-testid="offer-decline">
          {{ 'serviceOffer.decline' | translate }}
        </button>
      </div>
    }
    @if (error(); as message) { <p class="offer-error" role="alert">{{ message }}</p> }
  `,
  styles: [`
    :host { display: block; }
    .offer {
      display: flex; flex-wrap: wrap; gap: 0.5rem 0.75rem; align-items: center;
      padding-block: 0.6rem; padding-inline: 0.85rem;
      border: 1px solid var(--color-border); border-inline-start: 4px solid var(--color-primary);
      border-radius: 6px; background: var(--color-bg);
    }
    .offer i { font-size: 1.4rem; }
    .offer-text { display: flex; flex-direction: column; flex: 1 1 12rem; }
    .offer-left { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .offer-error { color: var(--color-danger); margin: 0; }
  `],
})
export class OfferToastComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly accepted = output<AcceptedOffer>();

  readonly offers = signal<WorkOffer[]>([]);
  readonly now = signal(Date.now());
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly offer = computed(() => currentOffer(this.offers(), this.now()));
  readonly left = computed(() => {
    const o = this.offer();
    return o ? secondsLeft(o.expires_at, this.now()) : 0;
  });

  constructor() {
    const destroy = inject(DestroyRef);
    interval(OFFER_POLL_MS).pipe(
      startWith(0),
      switchMap(() => this.api.get<Page<WorkOffer>>('/api/v1/queue-offers/mine').pipe(catchError(() => of(null)))),
      takeUntilDestroyed(destroy),
    ).subscribe(page => {
      if (page) this.offers.set(page.items);
    });
    interval(1000).pipe(takeUntilDestroyed(destroy)).subscribe(() => this.now.set(Date.now()));
  }

  icon(channel: string): string {
    switch (channel) {
      case 'chat': return 'las la-comments';
      case 'call': return 'las la-phone';
      case 'email': return 'las la-envelope';
      case 'social': return 'las la-hashtag';
      default: return 'las la-inbox';
    }
  }

  accept(o: WorkOffer): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.post<WorkOffer>(`/api/v1/queue-offers/${encodeURIComponent(o.id)}/accept`, {}).subscribe({
      next: taken => {
        this.busy.set(false);
        this.offers.update(list => list.filter(x => x.id !== o.id));
        const entity = taken.record_entity ?? o.record_entity;
        const recordId = taken.record_id ?? o.record_id;
        if (entity && recordId) {
          this.accepted.emit({ entity, recordId, title: this.lang.translate('serviceOffer.channel.' + o.channel) });
        }
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.offers.update(list => list.filter(x => x.id !== o.id));
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  decline(o: WorkOffer): void {
    this.busy.set(true);
    this.api.post<WorkOffer>(`/api/v1/queue-offers/${encodeURIComponent(o.id)}/decline`, {}).subscribe({
      next: () => { this.busy.set(false); this.offers.update(list => list.filter(x => x.id !== o.id)); },
      error: () => { this.busy.set(false); this.offers.update(list => list.filter(x => x.id !== o.id)); },
    });
  }
}
