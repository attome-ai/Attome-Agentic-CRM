import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { of } from 'rxjs';
import { LangService } from '@attome/base';
import { AvailableView, QueryService, ViewAdminService } from '@attome/xrm/core/query/data';
import { CalendarViewComponent } from './calendar-view.component';

const CALENDAR_VIEW: AvailableView = {
  id: 'view-1', name: 'Appointments', icon: 'las la-table', is_default: true,
  kind: 'calendar', scope: 'system', is_mine: false,
  view_metadata: { start_field: 'start_date', end_field: 'end_date', color_field: 'priority' },
};

describe('CalendarViewComponent', () => {
  let listAvailable: ReturnType<typeof vi.fn>;
  let execute: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    listAvailable = vi.fn().mockReturnValue(of([CALENDAR_VIEW]));
    execute = vi.fn().mockReturnValue(of({
      metadata: { query_id: 'q-1', view_id: 'view-1', record_no: null, entity_logical_name: null, can_edit_query: false },
      data: {
        columns: [
          { name: 'name', display_name: 'Name', data_type: 'text', is_visible: true, is_sortable: true, is_searchable: true, is_clickable: false, route_template: '' },
        ],
        records: [{ id: 'r-1', name: 'Kickoff', start_date: '2026-08-15', end_date: '2026-08-15', priority: 'high' }],
        total: 1, page: 1, page_size: 500, total_pages: 1,
      },
    }));

    TestBed.configureTestingModule({
      imports: [CalendarViewComponent],
      providers: [
        { provide: ViewAdminService, useValue: { listAvailable } },
        { provide: QueryService, useValue: { execute } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    TestBed.overrideComponent(CalendarViewComponent, { set: { template: '' } });
  });

  it("resolves the entity's calendar-kind view and places an event on its start day", async () => {
    const fixture = TestBed.createComponent(CalendarViewComponent);
    fixture.componentInstance.monthAnchor.set(new Date(2026, 7, 1)); // August 2026
    fixture.componentRef.setInput('entityName', 'appointment');
    fixture.detectChanges();
    await fixture.whenStable();

    expect(listAvailable).toHaveBeenCalledWith('appointment');
    expect(execute).toHaveBeenCalledWith(expect.objectContaining({ view_id: 'view-1' }));

    const weeks = fixture.componentInstance.weeks();
    const day15 = weeks.flat().find(d => d.date.getFullYear() === 2026 && d.date.getMonth() === 7 && d.date.getDate() === 15);
    expect(day15?.events.map(e => e.id)).toEqual(['r-1']);
  });

  it('sends an overlap filter bounded to the visible 6-week grid, not an unbounded scan', async () => {
    const fixture = TestBed.createComponent(CalendarViewComponent);
    fixture.componentInstance.monthAnchor.set(new Date(2026, 7, 1));
    fixture.componentRef.setInput('entityName', 'appointment');
    fixture.detectChanges();
    await fixture.whenStable();

    const call = execute.mock.calls[0][0];
    expect(call.filters).toHaveLength(2);
    expect(call.filters[0].field).toBe('end_date');
    expect(call.filters[1].field).toBe('start_date');
    expect(call.page_size).toBeLessThanOrEqual(500);
  });
});
