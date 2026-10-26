import { inject, Injectable } from '@angular/core';
import { ApiService } from '@attome/base';
import { map, Observable } from 'rxjs';

/** One opportunity line (`GET /api/v1/sales/opportunities/{id}/lines`); amounts are decimal text. */
export interface SalesLine {
  id: string;
  product_ref: string | null;
  name: string | null;
  quantity: string | null;
  list_price: string | null;
  sales_price: string | null;
  discount_percent: string | null;
  discount_amount: string | null;
  line_total: string | null;
  line_kind: string | null;
  recurrence: string | null;
  term_months: string | null;
  /** Present only for a caller whose field security shows the cost. */
  unit_cost?: string | null;
}

/** What a line write changed on the opportunity. */
export interface SalesLinesChanged {
  opportunity_id: string;
  line_id: string | null;
  one_time_total: string;
  recurring_annual: string;
  total_contract_value: string;
}

/** The editable fields of a line. */
export interface SalesLinePatch {
  quantity?: string;
  sales_price?: string;
  discount_percent?: string;
  discount_amount?: string;
}

/** A product a line can use, from the opportunity's price list. */
export interface ProductPrice {
  product_id: string;
  name: string | null;
  name_ar: string | null;
  sku: string | null;
  list_price: string | null;
}

/** What the grid reads of the opportunity itself. */
export interface OpportunityHead {
  row_version: number;
  data: Record<string, unknown>;
}

/** The answer of a quote sync. */
export interface SyncResult {
  status: string;
}

/** D6-T10: the opportunity line routes (D6-T4) and the product picker (D6-T5). */
@Injectable({ providedIn: 'root' })
export class SalesApiService {
  private readonly api = inject(ApiService);

  /** The opportunity's row (its `row_version`, currency and price list). */
  opportunity(id: string): Observable<OpportunityHead> {
    return this.api.get<OpportunityHead>(`/api/v1/opportunity/${encodeURIComponent(id)}`);
  }

  /** Whether `flag` is on for the caller (`GET /api/v1/features`). */
  featureOn(flag: string): Observable<boolean> {
    return this.api
      .get<{ flags: Record<string, boolean> }>('/api/v1/features')
      .pipe(map(r => r.flags?.[flag] === true));
  }

  lines(opportunity: string): Observable<SalesLine[]> {
    return this.api
      .get<{ items: SalesLine[] }>(`/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/lines`, {
        page_size: '500',
      })
      .pipe(map(r => r.items ?? []));
  }

  addLine(opportunity: string, rowVersion: number, body: { product_ref: string } & SalesLinePatch): Observable<SalesLinesChanged> {
    return this.api.post<SalesLinesChanged>(
      `/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/lines`,
      body,
      { ifMatch: rowVersion },
    );
  }

  updateLine(opportunity: string, line: string, rowVersion: number, patch: SalesLinePatch): Observable<SalesLinesChanged> {
    return this.api.patch<SalesLinesChanged>(
      `/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/lines/${encodeURIComponent(line)}`,
      patch,
      rowVersion,
    );
  }

  products(priceList: string, q: string): Observable<ProductPrice[]> {
    return this.api
      .get<{ items: ProductPrice[] }>(`/api/v1/sales/price-lists/${encodeURIComponent(priceList)}/products`, {
        q,
        page_size: '20',
      })
      .pipe(map(r => r.items ?? []));
  }

  sync(opportunity: string, direction: 'from_quote' | 'to_quote', force: boolean): Observable<SyncResult> {
    return this.api.post<SyncResult>(
      `/api/v1/sales/opportunities/${encodeURIComponent(opportunity)}/sync`,
      { direction, force },
    );
  }
}
