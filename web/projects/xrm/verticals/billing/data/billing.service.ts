import { Injectable, inject } from '@angular/core';
import { ApiService } from '@attome/base';
import { Observable } from 'rxjs';

/** `attome_billing::statements::StatementEntry`. */
export interface StatementEntry {
  date: string;
  /** `invoice`, `credit_note`, `debit_note`, `deposit`, `payment` or `write_off`. */
  kind: string;
  reference: string | null;
  invoice_id: string;
  /** What it adds to the balance, as decimal text (negative for payments and credits). */
  amount: string;
}

/** `attome_billing::statements::CurrencyStatement`. */
export interface CurrencyStatement {
  currency: string;
  opening_balance: string;
  entries: StatementEntry[];
  closing_balance: string;
}

/** `attome_billing::statements::AccountStatement`. */
export interface AccountStatement {
  account_id: string;
  from: string;
  to: string;
  currencies: CurrencyStatement[];
}

/** `attome_billing::statements::AgeingRow`. */
export interface AgeingRow {
  account_id: string;
  account_name: string | null;
  currency: string;
  current: string;
  days_1_30: string;
  days_31_60: string;
  days_61_90: string;
  over_90: string;
  total: string;
}

/** `attome_billing::statements::AgeingTotals`. */
export type AgeingTotals = Omit<AgeingRow, 'account_id' | 'account_name'>;

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

/** The five ageing buckets, in order. */
export const AGEING_BUCKETS = ['current', 'days_1_30', 'days_31_60', 'days_61_90', 'over_90'] as const;

/**
 * Reads of `/api/v1/billing` (roadmap F4-T16): an account's statement and
 * the receivables ageing. Both answer only what the caller's record scope on
 * accounts allows.
 */
@Injectable({ providedIn: 'root' })
export class BillingService {
  private readonly api = inject(ApiService);

  statement(accountId: string, from: string, to: string): Observable<AccountStatement> {
    const query = new URLSearchParams({ from, to });
    return this.api.get<AccountStatement>(
      `/api/v1/billing/accounts/${encodeURIComponent(accountId)}/statement?${query}`,
    );
  }

  ageing(asOf: string, page: number, pageSize = 50): Observable<Page<AgeingRow>> {
    const query = new URLSearchParams({ as_of: asOf, page: String(page), page_size: String(pageSize) });
    return this.api.get<Page<AgeingRow>>(`/api/v1/billing/ageing?${query}`);
  }

  ageingTotals(asOf: string): Observable<Page<AgeingTotals>> {
    return this.api.get<Page<AgeingTotals>>(`/api/v1/billing/ageing/totals?as_of=${encodeURIComponent(asOf)}`);
  }
}
