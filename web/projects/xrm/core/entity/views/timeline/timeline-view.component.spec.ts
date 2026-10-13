import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { of } from 'rxjs';
import { LangService } from '@attome/base';
import { AvailableView, QueryService, ViewAdminService } from '@attome/xrm/core/query/data';
import { TimelineViewComponent } from './timeline-view.component';

const TIMELINE_VIEW: AvailableView = {
  id: 'view-1', name: 'Project Plan', icon: 'las la-table', is_default: true,
  kind: 'timeline', scope: 'system', is_mine: false,
  view_metadata: { start_field: 'start_date', end_field: 'end_date', color_field: 'priority' },
};

describe('TimelineViewComponent', () => {
  let listAvailable: ReturnType<typeof vi.fn>;
  let execute: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    listAvailable = vi.fn().mockReturnValue(of([TIMELINE_VIEW]));
    execute = vi.fn().mockReturnValue(of({
      metadata: { query_id: 'q-1', view_id: 'view-1', record_no: null, entity_logical_name: null, can_edit_query: false },
      data: {
        columns: [
          { name: 'name', display_name: 'Name', data_type: 'text', is_visible: true, is_sortable: true, is_searchable: true, is_clickable: false, route_template: '' },
        ],
        records: [{ id: 'r-1', name: 'Design phase', start_date: '2026-08-02', end_date: '2026-08-04', priority: 'high' }],
        total: 1, page: 1, page_size: 500, total_pages: 1,
      },
    }));

    TestBed.configureTestingModule({
      imports: [TimelineViewComponent],
      providers: [
        { provide: ViewAdminService, useValue: { listAvailable } },
        { provide: QueryService, useValue: { execute } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    TestBed.overrideComponent(TimelineViewComponent, { set: { template: '' } });
  });

  it('positions a bar within the visible window proportional to its date range', async () => {
    const fixture = TestBed.createComponent(TimelineViewComponent);
    fixture.componentInstance.windowStart.set(new Date(2026, 7, 1)); // Aug 1, 2026
    fixture.componentRef.setInput('entityName', 'task');
    fixture.detectChanges();
    await fixture.whenStable();

    expect(listAvailable).toHaveBeenCalledWith('task');
    const bars = fixture.componentInstance.bars();
    expect(bars).toHaveLength(1);
    expect(bars[0].id).toBe('r-1');
    // Aug 2 is day index 1 of a 21-day window -> leftPct ~ 1/21.
    expect(bars[0].leftPct).toBeCloseTo(1 / 21, 2);
    expect(bars[0].widthPct).toBeGreaterThan(0);
  });

  it('advancing the window re-queries with a shifted date-overlap filter', async () => {
    const fixture = TestBed.createComponent(TimelineViewComponent);
    fixture.componentInstance.windowStart.set(new Date(2026, 7, 1));
    fixture.componentRef.setInput('entityName', 'task');
    fixture.detectChanges();
    await fixture.whenStable();

    execute.mockClear();
    fixture.componentInstance.nextWindow();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(execute).toHaveBeenCalledTimes(1);
    const call = execute.mock.calls[0][0];
    // WINDOW_DAYS=21: the window shifted from [Aug 1 .. Aug 21] to [Aug 22 .. Sep 11].
    expect(call.filters[0].value).toBe('2026-08-22'); // end_field >= new window start
    expect(call.filters[1].value).toBe('2026-09-11'); // start_field <= new window end
  });
});
