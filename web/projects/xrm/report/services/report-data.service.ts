import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';
import { DateRangeConfig } from '../types';

// Wire shapes come from the generated OpenAPI contract (M26 R-15). S4-T11
// removed `POST /api/v1/search/aggregate`; grouped measures run as
// `POST /api/v1/query/run` QuerySpecs with `group_by` and `aggregates`, and
// the answer's `groups` carry each group's `keys` and `values` by alias.
export type QueryRunRequest = ApiComponents['schemas']['RunRequest'];
export type QueryRunResponse = ApiComponents['schemas']['RunResponse'];
export type AggregateResult = ApiComponents['schemas']['AggregateResult'];

@Injectable({ providedIn: 'root' })
export class ReportDataService {
  private readonly api = inject(ApiService);

  // D-479 (M26 R-09) deleted `getWidgetTypes()` along with the backend route
  // it called (`GET /api/v1/report/widget-types`, `attome-report/src/
  // widget_catalog.rs`) and its one caller (`dashboard/builder`, also
  // deleted) — `attome-dashboard`'s own widget registry
  // (`GET /api/v1/attome-dashboard/widget-types`) is the one remaining catalog.

  /** An aggregate QuerySpec through `query/run`: GROUP BY with count, sum,
   * avg, min, max or count_distinct, over the records the caller may read. */
  aggregate(spec: Record<string, unknown>): Observable<AggregateResult> {
    return this.api.post<AggregateResult>('/api/v1/query/run', { spec });
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
 * `query/run`. */
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
