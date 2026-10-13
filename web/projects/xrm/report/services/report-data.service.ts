import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';
import { DateRangeConfig } from '../types';

// Wire shapes come from the generated OpenAPI contract (M26 R-15 — same
// migration `dashboard.service.ts`/`metric.service.ts` already made; the old
// hand-mirrored interfaces here duplicated `attome-search::aggregate`'s
// `AggregateRequest`/`AggregateResponse`/`AggregateBucket` field-for-field).
export type AggregateRequest  = ApiComponents['schemas']['AggregateRequest'];
export type AggregateBucket   = ApiComponents['schemas']['AggregateBucket'];
export type AggregateResponse = ApiComponents['schemas']['AggregateResponse'];

@Injectable({ providedIn: 'root' })
export class ReportDataService {
  private readonly api = inject(ApiService);

  // D-479 (M26 R-09) deleted `getWidgetTypes()` along with the backend route
  // it called (`GET /api/v1/report/widget-types`, `attome-report/src/
  // widget_catalog.rs`) and its one caller (`dashboard/builder`, also
  // deleted) — `attome-dashboard`'s own widget registry
  // (`GET /api/v1/attome-dashboard/widget-types`) is the one remaining catalog.

  /** `attome-search::aggregate` — GROUP BY with COUNT/SUM/AVG/MIN/MAX, license-gated
   * by `search` independently of `report` (see that endpoint's own doc comment
   * for why: a `report`-only license still gets List/Table/count-style Metric
   * widgets, just not GROUP BY-backed charts). */
  aggregate(req: AggregateRequest): Observable<AggregateResponse> {
    return this.api.post<AggregateResponse>('/api/v1/search/aggregate', req);
  }
}

/** Resolves a date-range preset into `{from, to}` ISO bounds in the caller's
 * local timezone, for appending as two `gte`/`lt` filters against whichever
 * field the widget names as its `date_field`. No backend involvement — see
 * `attome-search::aggregate`'s and `query_exec.rs`'s `Filter` grammar, which
 * already supports arbitrary field/op/value triples; a preset is purely a
 * client-side convenience for producing two of those.
 *
 * Returns `null` for `"all"` (no date filter at all) and for `"custom"` with
 * either bound missing (not enough information to filter on yet).
 */
export function resolveDateRange(range: DateRangeConfig | undefined): { from: string; to: string } | null {
  if (!range || range.preset === 'all') return null;
  if (range.preset === 'custom') {
    if (!range.from || !range.to) return null;
    return { from: range.from, to: range.to };
  }

  const now = new Date();
  const startOfDay = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const today = startOfDay(now);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);

  switch (range.preset) {
    case 'today':
      return { from: today.toISOString(), to: tomorrow.toISOString() };
    case 'last_week': {
      const from = new Date(today);
      from.setDate(from.getDate() - 7);
      return { from: from.toISOString(), to: tomorrow.toISOString() };
    }
    case 'last_month': {
      const from = new Date(today);
      from.setMonth(from.getMonth() - 1);
      return { from: from.toISOString(), to: tomorrow.toISOString() };
    }
    default:
      return null;
  }
}

/** Appends the resolved date-range bound (if any) to an existing filter list
 * as two `gte`/`lt` `Filter` entries against `dateField` — the shared step
 * every widget's data-fetch call takes before hitting `query/execute` or
 * `search/aggregate`. */
export function withDateRangeFilters(
  filters: { field: string; op: string; value?: string }[],
  dateField: string | undefined,
  range: DateRangeConfig | undefined,
): { field: string; op: string; value?: string }[] {
  if (!dateField) return filters;
  const bounds = resolveDateRange(range);
  if (!bounds) return filters;
  return [
    ...filters,
    { field: dateField, op: 'gte', value: bounds.from },
    { field: dateField, op: 'lt', value: bounds.to },
  ];
}
