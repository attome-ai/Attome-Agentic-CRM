import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { EntityRecord } from '@attome/xrm';
import { DashboardSectionViewComponent } from './dashboard-section-view.component';

// Dashboard 10/10 Phase 4.2 — the responsive model: reading order, authored
// placement as custom properties, and the two-column span rule.

function record(id: string, data: Record<string, unknown>): EntityRecord {
  return { id, entity_id: 'x', data, created_at: '', updated_at: '', row_version: 0 };
}

function create(widgets: EntityRecord[], gridConfig?: Record<string, unknown>): DashboardSectionViewComponent {
  TestBed.configureTestingModule({ imports: [DashboardSectionViewComponent] });
  const fixture = TestBed.createComponent(DashboardSectionViewComponent);
  const section = record('s1', gridConfig ? { grid_config: JSON.stringify(gridConfig) } : {});
  fixture.componentRef.setInput('section', section);
  fixture.componentRef.setInput('widgetsBySection', new Map([['s1', widgets]]));
  return fixture.componentInstance;
}

describe('DashboardSectionViewComponent', () => {
  it('orders widgets by authored row, then column, so collapsed layouts and tab order read correctly', () => {
    const view = create([
      record('c', { grid_row: 1, grid_col: 0 }),
      record('b', { grid_row: 0, grid_col: 6 }),
      record('a', { grid_row: 0, grid_col: 0 }),
    ]);
    expect(view.widgets().map(w => w.id)).toEqual(['a', 'b', 'c']);
  });

  it('exposes the authored placement and a two-column span for the collapsed layout', () => {
    const view = create([], { columns: 12, row_height: 80, gap: 8 });
    expect(view.gridStyle()).toEqual({ '--xdv-columns': '12', '--xdv-row-height': '80px', '--xdv-gap': '8px' });
    const wide = view.widgetStyle(record('w', { grid_col: 2, grid_row: 1, grid_col_span: 8, grid_row_span: 3 }));
    expect(wide).toEqual({
      '--xdv-col': '3', '--xdv-row': '2', '--xdv-col-span': '8', '--xdv-row-span': '3', '--xdv-md-span': '2',
    });
    expect(view.widgetStyle(record('n', { grid_col_span: 6 }))['--xdv-md-span']).toBe('1');
  });
});
