import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { Observable, Subject, of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { xrmEn } from '@attome/xrm/core/i18n-en';
import { EntityRecord } from '@attome/xrm';
import {
  DashboardService, DashboardVariableBusService, PageWidgetResult, WidgetDataResponse,
} from '@attome/xrm/dashboard/data';
import { DashboardWidgetViewComponent } from './dashboard-widget-view.component';

// Dashboard 10/10 Phase 2.4 — the widget renders what the server computed and
// nothing else. Covered here:
//   1. structured buckets render with the server's values and typed keys,
//   2. the page-batch result is used as-is (no second request),
//   3. self-fetch sends values only and a newer request cancels an older one,
//   4. truncation / as_of / unsupported / KPI / table / text states,
//   5. cross-filtering emits the bucket's stored value and re-queries with
//      `cross_filters`, never a filter definition.

function widget(data: Record<string, unknown>): EntityRecord {
  return {
    id: 'widget-1',
    entity_id: 'dashboard_widget',
    data: { widget_type: 'bar_chart', name: 'Test Widget', ...data },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    row_version: 0,
  };
}

function structured(overrides: Partial<WidgetDataResponse> = {}): WidgetDataResponse {
  return {
    widget_id: 'widget-1',
    widget_type: 'bar_chart',
    render_kind: 'chart_bar',
    data_class: 'structured',
    drillability: 'exact',
    definition_source: 'published',
    published_version_number: 3,
    as_of: '2026-09-17T10:00:00Z',
    timezone: 'UTC',
    timezone_source: 'utc',
    definition_fingerprint: 'fp',
    applied_filters: [],
    structured: {
      measures: [{ aggregation: 'count' }],
      group: { field: 'status' },
      buckets: [
        { key: { kind: 'value', value: 'open' }, label: 'open', values: [117] },
        { key: { kind: 'null' }, label: null, values: [4] },
      ],
      truncated: false,
    },
    ...overrides,
  } as WidgetDataResponse;
}

interface Setup {
  fixture: ComponentFixture<DashboardWidgetViewComponent>;
  widgetData: ReturnType<typeof vi.fn>;
  bus: DashboardVariableBusService;
}

function setup(
  data: Record<string, unknown>,
  options: { result?: PageWidgetResult | null; response?: () => Observable<WidgetDataResponse>; preview?: boolean } = {},
): Setup {
  const widgetData = vi.fn(options.response ?? (() => of(structured())));
  TestBed.configureTestingModule({
    imports: [DashboardWidgetViewComponent],
    providers: [
      { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      provideAttomeI18n(), provideXrmI18n(xrmEn),
      provideRouter([]),
      { provide: DashboardService, useValue: { widgetData, widgetRecords: vi.fn(() => of()), widgetExplain: vi.fn(() => of()) } },
      DashboardVariableBusService,
    ],
  });
  const fixture = TestBed.createComponent(DashboardWidgetViewComponent);
  fixture.componentRef.setInput('widget', widget(data));
  fixture.componentRef.setInput('dashboardId', 'd1');
  if (options.preview) fixture.componentRef.setInput('preview', true);
  if (options.result !== undefined) fixture.componentRef.setInput('result', options.result);
  fixture.detectChanges();
  return { fixture, widgetData, bus: TestBed.inject(DashboardVariableBusService) };
}

const text = (fixture: ComponentFixture<unknown>): string =>
  (fixture.nativeElement as HTMLElement).textContent ?? '';

describe('DashboardWidgetViewComponent', () => {
  describe('server-computed rendering', () => {
    it("renders the server's bucket values and a typed NULL bucket, doing no arithmetic", async () => {
      const { fixture } = setup({});
      const buckets = fixture.componentInstance.buckets();
      expect(buckets.map(b => b.value)).toEqual([117, 4]);
      expect(buckets[0].key).toEqual({ kind: 'value', value: 'open' });
      expect(buckets[1].key).toEqual({ kind: 'null' });
      expect(buckets[0].trackKey).not.toEqual(buckets[1].trackKey);
      await vi.waitFor(() => {
        fixture.detectChanges();
        const chart = (fixture.nativeElement as HTMLElement).querySelector('attome-dashboard-chart svg');
        expect(chart?.getAttribute('aria-label')).toContain('117');
      });
      expect(text(fixture)).toContain('(empty)');
    });

    it('uses the page-batch result without a request of its own', () => {
      const { fixture, widgetData } = setup({}, { result: { widget_id: 'widget-1', data: structured() } });
      expect(widgetData).not.toHaveBeenCalled();
      expect(fixture.componentInstance.buckets()).toHaveLength(2);
    });

    it("shows a batch entry's own error without failing the page", () => {
      const { fixture } = setup({}, {
        result: { widget_id: 'widget-1', error: { status: 422, code: 'validation_error', message: 'bad field' } },
      });
      expect(text(fixture)).toContain('bad field');
    });

    it('labels truncation only when no Other bucket folds the rest, and shows as_of', () => {
      const truncated = structured();
      truncated.structured!.truncated = true;
      const { fixture } = setup({}, { result: { widget_id: 'widget-1', data: truncated } });
      expect(fixture.componentInstance.truncated()).toBe(true);
      expect(text(fixture)).toContain('Top groups only');
      expect(fixture.componentInstance.asOf()).not.toBe('');
    });

    it('renders an explicit unsupported state', () => {
      const { fixture } = setup({ widget_type: 'sankey_diagram' }, {
        result: { widget_id: 'widget-1', data: structured({ render_kind: 'unsupported', data_class: 'none', structured: undefined }) },
      });
      expect(text(fixture)).toContain('cannot be shown');
    });

    it('renders a governed KPI as service-scoped and never shows a stale definition', () => {
      const kpi = structured({
        render_kind: 'kpi_scorecard', data_class: 'kpi', drillability: 'explain_only', structured: undefined,
        kpi: {
          service_scoped: true,
          metrics: [
            { metric_id: 'm1', name: 'Win rate', status: 'ok', history: [], current: {
              snapshot_id: 's1', period_start: '2026-09-01', actual: 0.42, status: 'ok', computed_at: '2026-09-17T00:00:00Z',
            } },
            { metric_id: 'm2', name: 'Churn', status: 'definition_changed', history: [], current: null },
          ],
        },
      } as unknown as Partial<WidgetDataResponse>);
      const { fixture } = setup({ widget_type: 'scorecard' }, { result: { widget_id: 'widget-1', data: kpi } });
      expect(text(fixture)).toContain('0.42');
      expect(text(fixture)).toContain('Metric changed; republish.');
      expect(text(fixture)).toContain('not filtered to you');
    });

    it('renders a query widget as a table of the returned rows', () => {
      const rows = structured({
        render_kind: 'table', data_class: 'query', drillability: 'none', structured: undefined,
        query: {
          metadata: { query_id: 'q1', view_id: null, record_no: null, entity_logical_name: null, can_edit_query: false },
          data: {
            columns: [{ name: 'name', display_name: 'Name', data_type: 'text', is_visible: true, is_sortable: false, is_searchable: false, is_clickable: false, route_template: '' }],
            records: [{ name: 'Acme' }],
          },
        },
      } as unknown as Partial<WidgetDataResponse>);
      const { fixture } = setup({ widget_type: 'entity_data_grid' }, { result: { widget_id: 'widget-1', data: rows } });
      expect(text(fixture)).toContain('Acme');
    });

    it('links a record cell with a real anchor, never a role="link" span (Phase 4.4)', () => {
      const rows = structured({
        render_kind: 'table', data_class: 'query', drillability: 'none', structured: undefined,
        query: {
          metadata: { query_id: 'q1', view_id: null, record_no: null, entity_logical_name: 'account', can_edit_query: false },
          data: {
            columns: [{ name: 'name', display_name: 'Name', data_type: 'text', is_visible: true, is_sortable: false, is_searchable: false, is_clickable: true, route_template: '' }],
            records: [{ id: 'a-1', name: 'Acme' }],
          },
        },
      } as unknown as Partial<WidgetDataResponse>);
      const { fixture } = setup({ widget_type: 'entity_data_grid' }, { result: { widget_id: 'widget-1', data: rows } });
      const host = fixture.nativeElement as HTMLElement;
      const anchor = host.querySelector<HTMLAnchorElement>('a.xdv-cell-link');
      expect(anchor?.getAttribute('href')).toContain('id=a-1');
      expect(host.querySelector('[role="link"]')).toBeNull();
    });

    it("draws a series chart with the server's lookup names for series and groups", () => {
      const series = structured({ render_kind: 'chart_line' });
      series.structured!.buckets = [
        { key: { kind: 'value', value: 'open' }, label: 'open', series_key: { kind: 'value', value: 't-1' }, series_label: 'North', values: [2] },
        { key: { kind: 'value', value: 'won' }, label: 'won', series_key: { kind: 'value', value: 't-1' }, series_label: 'North', values: [3] },
        { key: { kind: 'value', value: 'won' }, label: 'won', series_key: { kind: 'value', value: 't-2' }, values: [4] },
      ];
      const { fixture } = setup({ widget_type: 'line_chart' }, { result: { widget_id: 'widget-1', data: series } });
      const view = fixture.componentInstance;
      expect(view.chartCategories().map(c => c.label)).toEqual(['open', 'won']);
      expect(view.chartSeries().map(s => s.name)).toEqual(['North', 't-2']);
      expect(view.chartSeries()[1].points[0]).toBeNull();
      expect(view.chartSeries()[1].points[1]?.value).toBe(4);
    });

    it('a drill from a series mark names the group and the series', () => {
      const series = structured();
      series.structured!.buckets = [
        { key: { kind: 'value', value: 'won' }, label: 'won', series_key: { kind: 'value', value: 't-1' }, series_label: 'North', values: [3] },
      ];
      const { fixture } = setup({}, { result: { widget_id: 'widget-1', data: series } });
      const view = fixture.componentInstance;
      view.onBucketClick(view.chartSeries()[0].points[0]!);
      expect(view.drill()).toEqual({ bucket: { kind: 'value', value: 'won' }, series: { kind: 'value', value: 't-1' }, label: 'won · North' });
    });

    it('renders text content as text, never as HTML', () => {
      const note = structured({ render_kind: 'text', data_class: 'none', drillability: 'none', structured: undefined });
      const { fixture } = setup(
        { widget_type: 'rich_text', config: JSON.stringify({ content: '<b>bold</b>' }) },
        { result: { widget_id: 'widget-1', data: note } },
      );
      const el = fixture.nativeElement as HTMLElement;
      expect(el.querySelector('b')).toBeNull();
      expect(text(fixture)).toContain('<b>bold</b>');
    });
  });

  describe('self-fetch (editor canvas)', () => {
    it('sends values only, with preview', () => {
      const { widgetData } = setup({}, { preview: true });
      expect(widgetData).toHaveBeenCalledTimes(1);
      const [dashboardId, widgetId, inputs] = widgetData.mock.calls[0];
      expect(dashboardId).toBe('d1');
      expect(widgetId).toBe('widget-1');
      expect(inputs).toEqual({ parameters: {}, cross_filters: {}, preview: true });
    });

    it('discards a stale response when a newer request supersedes it', () => {
      const first = new Subject<WidgetDataResponse>();
      const second = new Subject<WidgetDataResponse>();
      const pending = [first, second];
      const { fixture } = setup({}, { response: () => pending.shift()! });

      fixture.componentRef.setInput('parameters', { stage: 'won' });
      fixture.detectChanges();

      const newer = structured();
      newer.structured!.buckets = [{ key: { kind: 'value', value: 'won' }, label: 'won', values: [9] }];
      second.next(newer);
      const stale = structured();
      stale.structured!.buckets = [{ key: { kind: 'value', value: 'old' }, label: 'old', values: [1] }];
      first.next(stale);

      expect(fixture.componentInstance.buckets().map(b => b.label)).toEqual(['won']);
    });
  });

  describe('drill and cross-filtering', () => {
    it('a click on an exactly drillable bucket opens its records, with the typed key', () => {
      const { fixture } = setup({ emits: '["status"]' });
      fixture.componentInstance.onBucketClick(fixture.componentInstance.buckets()[1]);
      expect(fixture.componentInstance.drill()).toEqual({ bucket: { kind: 'null' }, series: null, label: '(empty)' });
      fixture.detectChanges();
      expect((fixture.nativeElement as HTMLElement).querySelector('xrm-widget-records-drawer')).not.toBeNull();
    });

    it("\"filter the dashboard by this\" emits the drilled bucket's stored value, not its label", () => {
      const { fixture, bus } = setup({ emits: '["status"]' });
      const emit = vi.spyOn(bus, 'emit');
      fixture.componentInstance.onBucketClick(fixture.componentInstance.buckets()[0]);
      fixture.componentInstance.crossFilterFromDrill();
      expect(emit).toHaveBeenCalledWith('status', 'open', 'widget-1');
      expect(fixture.componentInstance.drill()).toBeNull();
    });

    it('a click on a non-drillable widget cross-filters directly; a NULL key sets nothing', () => {
      const legacy = structured({ drillability: 'none', data_class: 'query' });
      const { fixture, bus } = setup({ emits: '["status"]' }, { result: { widget_id: 'widget-1', data: legacy } });
      const emit = vi.spyOn(bus, 'emit');
      fixture.componentInstance.onBucketClick(fixture.componentInstance.buckets()[0]);
      expect(emit).toHaveBeenCalledWith('status', 'open', 'widget-1');
      fixture.componentInstance.onBucketClick(fixture.componentInstance.buckets()[1]);
      expect(emit).toHaveBeenCalledTimes(1);
      expect(fixture.componentInstance.drill()).toBeNull();
    });

    it('offers Inspect on a data widget and opens the explanation', () => {
      const { fixture } = setup({});
      const button = (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('.xdv-widget-inspect');
      expect(button?.getAttribute('aria-label')).toContain('Test Widget');
      button!.click();
      fixture.detectChanges();
      expect((fixture.nativeElement as HTMLElement).querySelector('xrm-widget-explain-panel')).not.toBeNull();
    });

    it('re-queries with cross_filters for a variable it listens to, and ignores others', () => {
      const { widgetData, bus } = setup({ listens: '["region"]' });
      expect(widgetData).toHaveBeenCalledTimes(1);

      bus.emit('country', 'AE', 'other-widget');
      expect(widgetData).toHaveBeenCalledTimes(1);

      bus.emit('region', 'North', 'other-widget');
      expect(widgetData).toHaveBeenCalledTimes(2);
      expect(widgetData.mock.calls[1][2]).toEqual({ parameters: {}, cross_filters: { region: 'North' }, preview: false });
    });

    it('degrades malformed emits/listens JSON to no bindings', () => {
      const { fixture } = setup({ emits: 'not-json' });
      expect(fixture.componentInstance.emittedVariables()).toEqual([]);
      expect(fixture.componentInstance.canCrossFilter()).toBe(false);
    });
  });
});
