import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AvailableView, QueryService } from '@attome/xrm/core/query/data';
import { CHART_VIEW_MAX_ROWS, CHART_VIEW_PAGE_SIZE, ChartViewComponent } from './chart-view.component';

function view(metadata: Record<string, unknown>): AvailableView {
  return {
    id: 'v1', name: 'Pipeline', icon: '', is_default: true, kind: 'chart', view_metadata: metadata,
    scope: 'system', is_mine: false,
  };
}

const CONFIGURED = {
  chart_type: 'bar', x_field: 'stage', y_fields: [{ field: 'id', aggregation: 'count', label: 'Deals' }],
};

function page(records: Record<string, unknown>[], total: number) {
  return of({
    metadata: {
      query_id: 'q1', view_id: 'v1', record_no: null, entity_logical_name: null, can_edit_query: false,
      view_kind: 'chart', view_metadata: null,
    },
    data: { columns: [], records, total, page: 1, page_size: CHART_VIEW_PAGE_SIZE },
  });
}

describe('ChartViewComponent', () => {
  let execute: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    execute = vi.fn();
    TestBed.configureTestingModule({
      imports: [ChartViewComponent],
      providers: [
        { provide: QueryService, useValue: { execute } },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, intlLocale: () => 'en-US', isRtl: () => false },
        },
      ],
    });
  });

  function render(v: AvailableView) {
    const fixture = TestBed.createComponent(ChartViewComponent);
    fixture.componentRef.setInput('view', v);
    fixture.detectChanges();
    // The load effect ran during the first pass; render what it produced.
    fixture.detectChanges();
    return fixture;
  }

  it('runs the view\'s own query and draws the grouped rows', () => {
    execute.mockReturnValue(page([
      { id: '1', stage: 'won' }, { id: '2', stage: 'won' }, { id: '3', stage: 'lost' },
    ], 3));
    const fixture = render(view(CONFIGURED));

    expect(execute).toHaveBeenCalledWith({
      view_id: 'v1', page: 1, page_size: CHART_VIEW_PAGE_SIZE, include_total: true,
    });
    const chart = fixture.componentInstance.chart()!;
    expect(chart.categories.map(c => c.label)).toEqual(['lost', 'won']);
    expect(chart.series[0].points.map(p => p?.value)).toEqual([1, 2]);
    expect(fixture.componentInstance.truncatedTotal()).toBeNull();
    expect((fixture.nativeElement as HTMLElement).querySelector('attome-dashboard-chart')).not.toBeNull();
  });

  it('reads further pages, and stops at the row cap saying so', () => {
    const full = Array.from({ length: CHART_VIEW_PAGE_SIZE }, (_, i) => ({ id: String(i), stage: 'a' }));
    execute.mockReturnValue(page(full, 50_000));
    const fixture = render(view(CONFIGURED));

    expect(execute).toHaveBeenCalledTimes(CHART_VIEW_MAX_ROWS / CHART_VIEW_PAGE_SIZE);
    expect(fixture.componentInstance.rows().length).toBe(CHART_VIEW_MAX_ROWS);
    expect(fixture.componentInstance.truncatedTotal()).toBe(50_000);
  });

  it('does not query a chart view that is not configured yet', () => {
    const fixture = render(view({}));

    expect(execute).not.toHaveBeenCalled();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('entityViews.chart.notConfigured');
  });

  it('shows the query error', () => {
    execute.mockReturnValue(throwError(() => ({ message: 'nope' })));
    const fixture = render(view(CONFIGURED));

    expect(fixture.componentInstance.error()).toBe('nope');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('nope');
  });
});
