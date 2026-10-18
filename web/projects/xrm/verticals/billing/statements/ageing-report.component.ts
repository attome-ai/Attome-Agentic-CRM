import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import { AGEING_BUCKETS, AgeingRow, AgeingTotals, BillingService } from '../data/billing.service';
import { formatAmount } from '../data/money';

/**
 * The receivables ageing (roadmap F4-T16): what each account owes, per
 * currency, in the five buckets by days past due, with the book's totals
 * per currency above. Each account links to its statement. Amounts keep
 * their currency's decimals (three for KWD, BHD, OMR and JOD). Logical CSS
 * only, and the page takes the language's direction.
 */
@Component({
  selector: 'xrm-ageing-report',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    <section class="agr" [attr.dir]="dir()" aria-labelledby="agr-title">
      <header class="agr-head">
        <h2 id="agr-title">{{ 'billingAgeing.title' | translate }}</h2>
        <label>{{ 'billingAgeing.asOf' | translate }}
          <input type="date" [value]="asOf()" (change)="setAsOf($event)">
        </label>
      </header>
      @if (error(); as message) { <p class="agr-error" role="alert">{{ message }}</p> }
      <table class="agr-table">
        <thead>
          <tr>
            <th scope="col">{{ 'billingAgeing.account' | translate }}</th>
            <th scope="col">{{ 'billingAgeing.currency' | translate }}</th>
            @for (bucket of buckets; track bucket) {
              <th scope="col" class="num">{{ 'billingAgeing.bucket.' + bucket | translate }}</th>
            }
            <th scope="col" class="num">{{ 'billingAgeing.total' | translate }}</th>
          </tr>
        </thead>
        <tbody>
          @for (total of totals(); track total.currency) {
            <tr class="agr-totals" [attr.data-totals]="total.currency">
              <th scope="row">{{ 'billingAgeing.allAccounts' | translate }}</th>
              <td>{{ total.currency }}</td>
              @for (bucket of buckets; track bucket) {
                <td class="num">{{ money(total[bucket], total.currency) }}</td>
              }
              <td class="num">{{ money(total.total, total.currency) }}</td>
            </tr>
          }
          @for (row of rows(); track row.account_id + row.currency) {
            <tr [attr.data-account]="row.account_id">
              <th scope="row">
                <a [routerLink]="['/xrm/billing/accounts', row.account_id, 'statement']">
                  <bdi>{{ row.account_name ?? row.account_id }}</bdi>
                </a>
              </th>
              <td>{{ row.currency }}</td>
              @for (bucket of buckets; track bucket) {
                <td class="num">{{ money(row[bucket], row.currency) }}</td>
              }
              <td class="num">{{ money(row.total, row.currency) }}</td>
            </tr>
          } @empty {
            <tr><td [attr.colspan]="buckets.length + 3" class="agr-muted">{{ 'billingAgeing.empty' | translate }}</td></tr>
          }
        </tbody>
      </table>
      @if (pages() > 1) {
        <nav class="agr-pages" [attr.aria-label]="'billingAgeing.pages' | translate">
          <button type="button" (click)="go(page() - 1)" [disabled]="page() <= 1">{{ 'billingAgeing.previous' | translate }}</button>
          <span>{{ page() }} / {{ pages() }}</span>
          <button type="button" (click)="go(page() + 1)" [disabled]="page() >= pages()">{{ 'billingAgeing.next' | translate }}</button>
        </nav>
      }
    </section>
  `,
  styles: [`
    :host { display: block; padding-block: 1rem; padding-inline: 1rem; }
    .agr { display: flex; flex-direction: column; gap: 1rem; }
    .agr-head { display: flex; flex-wrap: wrap; gap: 1rem; align-items: end; justify-content: space-between; }
    .agr-head h2 { margin-block: 0; font-size: 1.125rem; }
    .agr-head label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.8125rem; }
    .agr-table { inline-size: 100%; border-collapse: collapse; }
    .agr-table th, .agr-table td { padding-block: 0.375rem; padding-inline: 0.5rem; text-align: start;
      border-block-end: 1px solid var(--color-border); }
    .agr-table .num { text-align: end; font-variant-numeric: tabular-nums; unicode-bidi: isolate; direction: ltr; }
    .agr-totals th, .agr-totals td { font-weight: 600; background: var(--color-surface-alt, transparent); }
    .agr-pages { display: flex; gap: 0.75rem; align-items: center; justify-content: flex-end; }
    .agr-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .agr-error { color: var(--color-danger); }
  `],
})
export class AgeingReportComponent implements OnInit {
  private readonly billing = inject(BillingService);
  private readonly lang = inject(LangService);

  readonly buckets = AGEING_BUCKETS;
  readonly asOf = signal(new Date().toISOString().slice(0, 10));
  readonly page = signal(1);
  readonly pageSize = 50;
  readonly total = signal(0);
  readonly rows = signal<AgeingRow[]>([]);
  readonly totals = signal<AgeingTotals[]>([]);
  readonly error = signal<string | null>(null);

  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));
  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));

  ngOnInit(): void {
    this.load();
  }

  money(amount: string, currency: string): string {
    return formatAmount(amount, currency, this.lang.intlLocale());
  }

  setAsOf(event: Event): void {
    const value = (event.target as HTMLInputElement).value;
    if (!value) return;
    this.asOf.set(value);
    this.page.set(1);
    this.load();
  }

  go(page: number): void {
    if (page < 1 || page > this.pages()) return;
    this.page.set(page);
    this.load();
  }

  load(): void {
    this.error.set(null);
    this.billing.ageing(this.asOf(), this.page(), this.pageSize).subscribe({
      next: result => {
        this.rows.set(result.items);
        this.total.set(result.total);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.billing.ageingTotals(this.asOf()).subscribe({
      next: result => this.totals.set(result.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
