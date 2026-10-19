import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, LangService, TranslatePipe } from '@attome/base';

/** `GET /api/v1/quote-acceptance/{token}`. */
export interface QuoteView {
  quote_number: string | null;
  name: string | null;
  currency: string | null;
  valid_from: string | null;
  expires_on: string | null;
  payment_terms: string | null;
  terms: string | null;
  subtotal: string | null;
  discount_total: string | null;
  vat_estimate: string | null;
  grand_total: string | null;
  status: 'sent' | 'accepted' | 'rejected' | 'expired';
  accepted_by_name: string | null;
  decided_at: string | null;
  lines: {
    product: string | null; quantity: string | null; unit_price: string | null;
    discount_amount: string | null; tax_amount: string | null; line_total: string | null;
  }[];
}

type Stage = 'loading' | 'ready' | 'sending' | 'missing' | 'failed';

/** An exact decimal amount in the reader's language and the quote's currency. Pure. */
export function money(amount: string | null, currency: string | null, locale: string): string {
  if (amount === null || amount === '') return '';
  const value = Number(amount);
  if (!Number.isFinite(value)) return amount;
  if (!currency || !/^[A-Z]{3}$/.test(currency)) {
    return new Intl.NumberFormat(locale, { maximumFractionDigits: 4 }).format(value);
  }
  return new Intl.NumberFormat(locale, { style: 'currency', currency }).format(value);
}

/**
 * D9-T3: the public quote page at `/quote/:token`, from the link the
 * salesperson sends. No session: it shows the quote (lines, totals, terms)
 * and lets the customer accept or reject it with their name. An altered,
 * expired or superseded link shows a message and no quote. Both languages,
 * with a toggle, and logical CSS only.
 */
@Component({
  selector: 'xrm-quote-accept',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <main class="qa" [attr.dir]="dir()" [attr.lang]="lang.current()">
      <section class="qa-card" aria-labelledby="qa-title">
        <div class="qa-head">
          <h1 id="qa-title">{{ quote()?.name || ('quoteAccept.title' | translate) }}</h1>
          <button type="button" class="qa-lang" (click)="toggleLanguage()">{{ 'quoteAccept.otherLanguage' | translate }}</button>
        </div>
        @switch (stage()) {
          @case ('loading') { <p class="qa-muted" role="status">{{ 'quoteAccept.loading' | translate }}</p> }
          @case ('missing') { <p class="qa-error" role="alert" data-testid="qa-missing">{{ 'quoteAccept.invalidLink' | translate }}</p> }
          @default {
            @if (quote(); as q) {
              @if (q.quote_number) { <p class="qa-muted"><bdi>{{ q.quote_number }}</bdi></p> }
              <table class="qa-lines" data-testid="qa-lines">
                <thead><tr>
                  <th scope="col">{{ 'quoteAccept.item' | translate }}</th>
                  <th scope="col" class="num">{{ 'quoteAccept.quantity' | translate }}</th>
                  <th scope="col" class="num">{{ 'quoteAccept.unitPrice' | translate }}</th>
                  <th scope="col" class="num">{{ 'quoteAccept.lineTotal' | translate }}</th>
                </tr></thead>
                <tbody>
                  @for (l of q.lines; track $index) {
                    <tr>
                      <td><bdi>{{ l.product || '—' }}</bdi></td>
                      <td class="num">{{ l.quantity }}</td>
                      <td class="num">{{ amount(l.unit_price) }}</td>
                      <td class="num">{{ amount(l.line_total) }}</td>
                    </tr>
                  }
                </tbody>
              </table>
              <dl class="qa-totals">
                @if (q.subtotal) { <div><dt>{{ 'quoteAccept.subtotal' | translate }}</dt><dd class="num">{{ amount(q.subtotal) }}</dd></div> }
                @if (q.discount_total) { <div><dt>{{ 'quoteAccept.discount' | translate }}</dt><dd class="num">{{ amount(q.discount_total) }}</dd></div> }
                @if (q.vat_estimate) { <div><dt>{{ 'quoteAccept.vat' | translate }}</dt><dd class="num">{{ amount(q.vat_estimate) }}</dd></div> }
                <div class="qa-grand"><dt>{{ 'quoteAccept.total' | translate }}</dt><dd class="num" data-testid="qa-total">{{ amount(q.grand_total) }}</dd></div>
              </dl>
              @if (q.payment_terms) { <p><strong>{{ 'quoteAccept.paymentTerms' | translate }}:</strong> {{ q.payment_terms }}</p> }
              @if (q.terms) { <p class="qa-terms">{{ q.terms }}</p> }
              @if (q.status === 'sent') {
                <form class="qa-form" (ngSubmit)="decide('accept')" data-testid="qa-form">
                  <label>{{ 'quoteAccept.yourName' | translate }}
                    <input name="name" [(ngModel)]="name" required maxlength="200" autocomplete="name" data-testid="qa-name" />
                  </label>
                  <label>{{ 'quoteAccept.note' | translate }}
                    <textarea name="note" rows="2" [(ngModel)]="note" maxlength="2000"></textarea>
                  </label>
                  @if (stage() === 'failed') { <p class="qa-error" role="alert">{{ 'quoteAccept.failed' | translate }}</p> }
                  <div class="qa-actions">
                    <button type="submit" class="qa-accept" [disabled]="!name.trim() || stage() === 'sending'" data-testid="qa-accept">
                      {{ 'quoteAccept.accept' | translate }}
                    </button>
                    <button type="button" class="qa-reject" [disabled]="!name.trim() || stage() === 'sending'"
                            (click)="decide('reject')" data-testid="qa-reject">
                      {{ 'quoteAccept.reject' | translate }}
                    </button>
                  </div>
                </form>
              } @else {
                <p class="qa-decided" role="status" data-testid="qa-decided">
                  {{ ('quoteAccept.status.' + q.status) | translate }}
                  @if (q.accepted_by_name) { — <bdi>{{ q.accepted_by_name }}</bdi> }
                </p>
              }
            }
          }
        }
      </section>
    </main>
  `,
  styles: [`
    :host { display: block; min-block-size: 100vh; background: var(--color-bg-secondary, #f6f7f9); }
    .qa { display: flex; justify-content: center; padding-block: 2rem; padding-inline: 1rem; }
    .qa-card { inline-size: 100%; max-inline-size: 48rem; background: var(--color-bg, #fff);
      border: 1px solid var(--color-border, #e3e5e8); border-radius: 0.75rem;
      padding-block: 1.5rem; padding-inline: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }
    .qa-head { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
    .qa-head h1 { margin-block: 0; font-size: 1.25rem; }
    .qa-lang { background: none; border: none; color: var(--color-accent, #2563eb); cursor: pointer; }
    .qa-lines { inline-size: 100%; border-collapse: collapse; }
    .qa-lines th, .qa-lines td { padding-block: 0.375rem; padding-inline: 0.5rem; text-align: start;
      border-block-end: 1px solid var(--color-border, #e3e5e8); }
    .qa-lines .num, .qa-totals .num { text-align: end; font-variant-numeric: tabular-nums; unicode-bidi: isolate; }
    .qa-totals { margin: 0; display: flex; flex-direction: column; gap: 0.25rem; }
    .qa-totals div { display: flex; justify-content: space-between; gap: 1rem; }
    .qa-totals dd { margin-inline-start: 0; }
    .qa-grand { font-weight: 700; font-size: 1.125rem; }
    .qa-terms { white-space: pre-wrap; color: var(--color-text-secondary, #5b616b); }
    .qa-form { display: flex; flex-direction: column; gap: 0.625rem; }
    .qa-form label { display: flex; flex-direction: column; gap: 0.25rem; }
    .qa-form input, .qa-form textarea { padding-block: 0.5rem; padding-inline: 0.625rem;
      border: 1px solid var(--color-border, #e3e5e8); border-radius: 0.5rem; font: inherit; }
    .qa-actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .qa-accept, .qa-reject { padding-block: 0.625rem; padding-inline: 1rem; border-radius: 0.5rem; cursor: pointer; font: inherit; }
    .qa-accept { border: none; background: var(--color-accent, #2563eb); color: var(--color-on-accent, #fff); }
    .qa-reject { border: 1px solid var(--color-border, #e3e5e8); background: var(--color-bg, #fff); color: inherit; }
    .qa-accept[disabled], .qa-reject[disabled] { opacity: 0.6; cursor: not-allowed; }
    .qa-decided { margin: 0; font-weight: 600; }
    .qa-muted { margin: 0; color: var(--color-text-secondary, #5b616b); }
    .qa-error { margin: 0; color: var(--color-danger, #b42318); }
  `],
})
export class QuoteAcceptComponent implements OnInit {
  private readonly api = inject(ApiService);
  protected readonly lang = inject(LangService);

  /** The guest link's token, from the route. */
  readonly token = input.required<string>();

  readonly stage = signal<Stage>('loading');
  readonly quote = signal<QuoteView | null>(null);
  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));
  name = '';
  note = '';

  private path(): string {
    return `/api/v1/quote-acceptance/${encodeURIComponent(this.token())}`;
  }

  ngOnInit(): void {
    this.api.get<QuoteView>(this.path()).subscribe({
      next: q => {
        this.quote.set(q);
        this.stage.set('ready');
      },
      error: () => this.stage.set('missing'),
    });
  }

  toggleLanguage(): void {
    void this.lang.toggle();
  }

  amount(value: string | null): string {
    return money(value, this.quote()?.currency ?? null, this.lang.intlLocale());
  }

  decide(decision: 'accept' | 'reject'): void {
    if (!this.name.trim() || this.stage() === 'sending') return;
    this.stage.set('sending');
    this.api.post<QuoteView>(this.path(), {
      decision, name: this.name.trim(), note: this.note.trim() || null,
    }).subscribe({
      next: q => {
        this.quote.set(q);
        this.stage.set('ready');
      },
      error: (err: { status?: number }) => {
        if (err?.status === 404) this.stage.set('missing');
        else this.stage.set('failed');
      },
    });
  }
}
