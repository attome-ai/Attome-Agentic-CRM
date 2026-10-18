import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiError, LangService, LocalDatePipe, TranslatePipe, UserPreferencesService, formatHijri, toHijri } from '@attome/base';

import { AccountStatement, BillingService } from '../data/billing.service';
import { formatAmount } from '../data/money';

/** The first day of `iso`'s month. */
export function monthStart(iso: string): string {
  return `${iso.slice(0, 8)}01`;
}

/** Today in UTC, as `YYYY-MM-DD`. */
function today(): string {
  return new Date().toISOString().slice(0, 10);
}

/**
 * An account's statement (roadmap F4-T16): the opening balance, every
 * issued document, payment and write-off in the period, and the closing
 * balance, one section per currency. The period defaults to this month;
 * when the viewer reads dates in the Hijri calendar the chosen days are
 * shown in it too. A print button gives a clean printed page (the shell
 * hides itself in print). Logical CSS only, and the whole page takes the
 * language's direction, so it reads right to left in Arabic.
 */
@Component({
  selector: 'xrm-account-statement',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="ast" [attr.dir]="dir()" aria-labelledby="ast-title">
      <header class="ast-head">
        <h2 id="ast-title">{{ 'billingStatement.title' | translate }}</h2>
        <form class="ast-period" (submit)="$event.preventDefault(); load()">
          <label>{{ 'billingStatement.from' | translate }}
            <input type="date" [value]="from()" (change)="from.set(value($event))" required>
          </label>
          <label>{{ 'billingStatement.to' | translate }}
            <input type="date" [value]="to()" (change)="to.set(value($event))" required>
          </label>
          @if (hijriPeriod(); as period) { <span class="ast-hijri">{{ period }}</span> }
          <button type="submit">{{ 'billingStatement.show' | translate }}</button>
          <button type="button" (click)="print()">{{ 'billingStatement.print' | translate }}</button>
        </form>
      </header>
      @if (error(); as message) { <p class="ast-error" role="alert">{{ message }}</p> }
      @for (section of statement()?.currencies ?? []; track section.currency) {
        <table class="ast-table" [attr.data-currency]="section.currency">
          <caption>{{ section.currency }}</caption>
          <thead>
            <tr>
              <th scope="col">{{ 'billingStatement.date' | translate }}</th>
              <th scope="col">{{ 'billingStatement.document' | translate }}</th>
              <th scope="col">{{ 'billingStatement.reference' | translate }}</th>
              <th scope="col" class="num">{{ 'billingStatement.amount' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            <tr class="ast-opening">
              <td colspan="3">{{ 'billingStatement.opening' | translate }}</td>
              <td class="num">{{ money(section.opening_balance, section.currency) }}</td>
            </tr>
            @for (entry of section.entries; track $index) {
              <tr>
                <td>{{ entry.date | localDate: { dateStyle: 'medium' } }}</td>
                <td>{{ 'billingStatement.kind.' + entry.kind | translate }}</td>
                <td><bdi>{{ entry.reference ?? '' }}</bdi></td>
                <td class="num">{{ money(entry.amount, section.currency) }}</td>
              </tr>
            }
          </tbody>
          <tfoot>
            <tr>
              <th scope="row" colspan="3">{{ 'billingStatement.closing' | translate }}</th>
              <td class="num">{{ money(section.closing_balance, section.currency) }}</td>
            </tr>
          </tfoot>
        </table>
      } @empty {
        @if (statement()) { <p class="ast-muted">{{ 'billingStatement.empty' | translate }}</p> }
      }
    </section>
  `,
  styles: [`
    :host { display: block; padding-block: 1rem; padding-inline: 1rem; }
    .ast { display: flex; flex-direction: column; gap: 1rem; max-inline-size: 64rem; }
    .ast-head { display: flex; flex-wrap: wrap; gap: 1rem; align-items: end; justify-content: space-between; }
    .ast-head h2 { margin-block: 0; font-size: 1.125rem; }
    .ast-period { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; }
    .ast-period label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.8125rem; }
    .ast-table { inline-size: 100%; border-collapse: collapse; }
    .ast-table caption { text-align: start; font-weight: 600; padding-block-end: 0.25rem; }
    .ast-table th, .ast-table td { padding-block: 0.375rem; padding-inline: 0.5rem; text-align: start;
      border-block-end: 1px solid var(--color-border); }
    .ast-table .num { text-align: end; font-variant-numeric: tabular-nums; unicode-bidi: isolate; direction: ltr; }
    .ast-opening td, tfoot th, tfoot td { font-weight: 600; }
    .ast-hijri, .ast-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .ast-error { color: var(--color-danger); }
    @media print { .ast-period { display: none; } :host { padding: 0; } }
  `],
})
export class AccountStatementComponent {
  private readonly billing = inject(BillingService);
  private readonly lang = inject(LangService);
  private readonly prefs = inject(UserPreferencesService);

  /** The account, from the route (`billing/accounts/:id/statement`). */
  readonly id = input.required<string>();

  readonly from = signal(monthStart(today()));
  readonly to = signal(today());
  readonly statement = signal<AccountStatement | null>(null);
  readonly error = signal<string | null>(null);

  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));
  /** The period in the Hijri calendar, for viewers who read dates in it. */
  readonly hijriPeriod = computed(() => {
    const calendar = this.prefs.calendar();
    if (calendar !== 'hijri' && calendar !== 'both') return null;
    const from = toHijri(this.from());
    const to = toHijri(this.to());
    if (!from || !to) return null;
    const lang = this.lang.current();
    const digits = this.prefs.digits();
    return `${formatHijri(from, lang, digits)} – ${formatHijri(to, lang, digits)}`;
  });

  constructor() {
    effect(() => {
      this.id();
      untracked(() => this.load());
    });
  }

  value(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  money(amount: string, currency: string): string {
    return formatAmount(amount, currency, this.lang.intlLocale());
  }

  load(): void {
    this.error.set(null);
    this.billing.statement(this.id(), this.from(), this.to()).subscribe({
      next: statement => this.statement.set(statement),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  print(): void {
    window.print();
  }
}
