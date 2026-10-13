import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { of } from 'rxjs';
import { LangService } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { AvailableView, QueryService, ViewAdminService } from '@attome/xrm/core/query/data';
import { EntityService } from '@attome/xrm/core/entity';
import { KanbanBoardComponent } from './kanban-board.component';

const KANBAN_VIEW: AvailableView = {
  id: 'view-1', name: 'Pipeline Board', icon: 'las la-table', is_default: true,
  kind: 'kanban', scope: 'system', is_mine: false,
  view_metadata: { state_field: 'status', wip_limits: { in_progress: 1 } },
};

const SCHEMA: EntitySchema = {
  id: 'e-1', name: 'deal', plural_name: 'deals',
  fields: [{
    id: 'f-status', entity_id: 'e-1', name: 'status', display_name: 'Status', field_type: 'choice',
    options: { choices: ['open', 'in_progress', 'won'], multi: false }, sort_order: 0, is_required: true,
  }],
  relationships: [],
};

describe('KanbanBoardComponent', () => {
  let listAvailable: ReturnType<typeof vi.fn>;
  let getSchema: ReturnType<typeof vi.fn>;
  let execute: ReturnType<typeof vi.fn>;
  let listTransitions: ReturnType<typeof vi.fn>;
  let transition: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    listAvailable = vi.fn().mockReturnValue(of([KANBAN_VIEW]));
    getSchema = vi.fn().mockReturnValue(of(SCHEMA));
    execute = vi.fn().mockReturnValue(of({
      metadata: { query_id: 'q-1', view_id: 'view-1', record_no: null, entity_logical_name: null, can_edit_query: false },
      data: {
        columns: [
          { name: 'name', display_name: 'Name', data_type: 'text', is_visible: true, is_sortable: true, is_searchable: true, is_clickable: false, route_template: '' },
          { name: 'status', display_name: 'Status', data_type: 'choice', is_visible: true, is_sortable: false, is_searchable: false, is_clickable: false, route_template: '' },
        ],
        records: [
          { id: 'r-1', name: 'Acme deal', status: 'open' },
          { id: 'r-2', name: 'Widgets deal', status: 'in_progress' },
        ],
        total: 2, page: 1, page_size: 500, total_pages: 1,
      },
    }));
    listTransitions = vi.fn().mockReturnValue(of({
      items: [{ to_state: 'in_progress', name: 'Start', display_order: 0 }],
      page: 1, page_size: 1, total: 1, total_pages: 1,
    }));
    transition = vi.fn().mockReturnValue(of({ record_id: 'r-1', from_state: 'open', to_state: 'in_progress', row_version: 2 }));

    TestBed.configureTestingModule({
      imports: [KanbanBoardComponent],
      providers: [
        { provide: ViewAdminService, useValue: { listAvailable } },
        { provide: QueryService, useValue: { execute } },
        { provide: EntityService, useValue: { getSchema, listTransitions, transition } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    TestBed.overrideComponent(KanbanBoardComponent, { set: { template: '' } });
  });

  it('groups records into columns by the choice field, in schema order', async () => {
    const fixture = TestBed.createComponent(KanbanBoardComponent);
    fixture.componentRef.setInput('entityName', 'deal');
    fixture.detectChanges();
    await fixture.whenStable();

    const cols = fixture.componentInstance.columns();
    expect(cols.map(c => c.value)).toEqual(['open', 'in_progress', 'won']);
    expect(cols[0].cards.map(c => c.id)).toEqual(['r-1']);
    expect(cols[1].cards.map(c => c.id)).toEqual(['r-2']);
    expect(cols[2].cards).toEqual([]);
  });

  it('flags a column over its configured WIP limit, advisory only', async () => {
    const fixture = TestBed.createComponent(KanbanBoardComponent);
    fixture.componentRef.setInput('entityName', 'deal');
    fixture.detectChanges();
    await fixture.whenStable();

    const inProgress = fixture.componentInstance.columns().find(c => c.value === 'in_progress')!;
    expect(inProgress.wipLimit).toBe(1);
    expect(fixture.componentInstance.isOverWip(inProgress)).toBe(false); // exactly at limit, not over
  });

  it('drag start fetches transitions and only those states become drop targets', async () => {
    const fixture = TestBed.createComponent(KanbanBoardComponent);
    fixture.componentRef.setInput('entityName', 'deal');
    fixture.detectChanges();
    await fixture.whenStable();

    const card = fixture.componentInstance.columns()[0].cards[0];
    const dragEvent = { dataTransfer: { setData: vi.fn() } } as unknown as DragEvent;
    fixture.componentInstance.onDragStart(card, dragEvent);

    expect(listTransitions).toHaveBeenCalledWith('deal', 'r-1');
    const allowed = fixture.componentInstance.draggingAllowedStates();
    expect(allowed).toEqual(new Set(['in_progress']));

    const wonColumn = fixture.componentInstance.columns().find(c => c.value === 'won')!;
    const inProgressColumn = fixture.componentInstance.columns().find(c => c.value === 'in_progress')!;
    expect(fixture.componentInstance.isDropTarget(wonColumn)).toBe(false);
    expect(fixture.componentInstance.isDropTarget(inProgressColumn)).toBe(true);
  });

  it('drop never calls the transition endpoint for a column that was not offered', async () => {
    const fixture = TestBed.createComponent(KanbanBoardComponent);
    fixture.componentRef.setInput('entityName', 'deal');
    fixture.detectChanges();
    await fixture.whenStable();

    const card = fixture.componentInstance.columns()[0].cards[0];
    fixture.componentInstance.onDragStart(card, { dataTransfer: { setData: vi.fn() } } as unknown as DragEvent);

    const wonColumn = fixture.componentInstance.columns().find(c => c.value === 'won')!;
    const preventDefault = vi.fn();
    fixture.componentInstance.onDrop(wonColumn, { preventDefault } as unknown as DragEvent);

    expect(transition).not.toHaveBeenCalled();

    const inProgressColumn = fixture.componentInstance.columns().find(c => c.value === 'in_progress')!;
    fixture.componentInstance.onDrop(inProgressColumn, { preventDefault } as unknown as DragEvent);
    expect(transition).toHaveBeenCalledWith('deal', 'r-1', { to_state: 'in_progress' });
  });
});
