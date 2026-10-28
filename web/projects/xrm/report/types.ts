// Wire/local shapes for the report module's widget data binding.
// `DashboardLayout`/`parseLayout`/`emptyLayout` (the legacy dashboard's
// layout document) had no consumer left and were removed (CLEANUP-REVIEW 4.9).

// D-479 (M26 R-09) deleted `WidgetDataShape`/`WidgetType` (the legacy
// `GET /api/v1/report/widget-types` catalog's wire shape) along with the
// backend route and its `dashboard/builder` consumer — `attome-dashboard`'s own
// `WidgetDescriptor` (`GET /api/v1/attome-dashboard/widget-types`) is the one
// remaining widget catalog.

export type DateRangePreset = 'today' | 'last_week' | 'last_month' | 'all' | 'custom';

export interface DateRangeConfig {
  preset: DateRangePreset;
  /** Only meaningful when `preset === 'custom'` — ISO date strings. */
  from?: string;
  to?: string;
}

export type MetricMode = 'count' | 'aggregate';

/** A widget's data-binding config — shape depends on the widget kind's
 * `data_shape` (see `WidgetType`), but kept as one loose interface rather
 * than a discriminated union: the builder edits it incrementally (e.g. a
 * user can pick an entity before picking a metric_fn), and a strict union
 * would force awkward intermediate states. */
export interface WidgetDataSource {
  mode?: 'query' | 'entity';
  query_id?: string;
  view_id?: string;
  entity?: string;
  filters?: { field: string; op: string; value?: string }[];
  date_field?: string;
  date_range?: DateRangeConfig;
  /** Rows/Table/List widgets only. */
  order_by?: string;
  order_dir?: 'asc' | 'desc';
  /** Metric widgets only — `count` reuses the entity list's honest `total`
   * (no aggregation capability needed); `aggregate` runs a `query/run`
   * aggregate with `metric_fn`/`metric_field` below and no `group_by` (a
   * single unbucketed total). */
  metric_mode?: MetricMode;
  /** Buckets (chart) widgets, and `metric_mode: 'aggregate'` Metric widgets. */
  metric_fn?: 'count' | 'sum' | 'avg' | 'min' | 'max';
  metric_field?: string;
  /** Buckets (chart) widgets only. */
  group_by?: string;
}

export interface DashboardWidget {
  id: string;
  kind: string;
  title?: string;
  x: number;
  y: number;
  w: number;
  h: number;
  data?: WidgetDataSource;
  /** Kind-specific presentation config — e.g. `{ text: "..." }` for a Text
   * widget, `{ childIds: [...] }` for a Container. */
  config?: Record<string, unknown>;
}
