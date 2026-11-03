import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { DashboardService } from '@attome/xrm/dashboard/data';
import type { DashboardTree } from '@attome/xrm/dashboard/data';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { DashboardDesignerComponent } from './dashboard-designer.component';
import { DDoc, misplaced, planSave, previewBoxes, resolveLinks, toDesign } from './dashboard-doc';

function rec(id: string, data: Record<string, unknown>, rowVersion = 1) {
  return { id, entity_id: '', data, row_version: rowVersion, created_at: '', updated_at: '' };
}

const TREE = {
  dashboard: { id: 'd1', entity_id: '', data: { name: 'Sales', visibility: 'private' }, row_version: 1 },
  pages: [rec('p1', { name: 'Overview', sequence: 0, dashboard_id: 'd1' })],
  sections: [
    rec('s1', { name: 'Top', page_id: 'p1', section_type: 'container', layout_mode: 'grid', sequence: 0 }),
    rec('s2', { name: 'Inner', page_id: 'p1', parent_section_id: 's1', section_type: 'row', layout_mode: 'grid', sequence: 0 }),
  ],
  widgetsBySection: new Map([
    ['s1', [rec('w1', { name: 'Revenue', widget_type: 'kpi_card', grid_col: 1, grid_col_span: 6, sequence: 0 }, 3)]],
    ['s2', [rec('w2', { name: 'Pipeline', widget_type: 'bar_chart', grid_col: 7, grid_col_span: 6, sequence: 0 })]],
  ]),
} as unknown as DashboardTree;

describe('dashboard tree and its record writes (P5-T1)', () => {
  it('reads a draft into the canvas tree', () => {
    const doc = toDesign(TREE);
    const page = doc.root.children?.[0];
    expect(page?.props).toEqual({ name: 'Overview' });
    expect(page?.children?.[0].children?.map(n => n.type)).toEqual(['section', 'widget']);
    expect(page?.children?.[0].children?.[0].children?.[0].id).toBe('w2');
    expect(misplaced(doc)).toBe(0);
  });

  it('plans nothing for an unchanged tree', () => {
    expect(planSave(toDesign(TREE), toDesign(TREE)).ops).toEqual([]);
  });

  it('plans an edit, a move, a new section with a new widget, and a delete', () => {
    const before = toDesign(TREE);
    const after: DDoc = structuredClone(before);
    const top = after.root.children![0].children![0];
    // Rename w1, move w2 up into the top section, drop the inner section,
    // and add a new section holding a new widget.
    const inner = top.children!.splice(0, 1)[0];
    top.children![0].props['name'] = 'Revenue (SAR)';
    top.children!.push(inner.children![0]);
    after.root.children![0].children!.push({
      type: 'section', ref: 'new-1', props: { name: 'More', section_type: 'container', layout_mode: 'grid' },
      children: [{ type: 'widget', ref: 'new-2', props: { name: 'Map', widget_type: 'map' } }],
    });
    const { ops, misplaced: bad } = planSave(before, after);
    expect(bad).toBe(0);
    expect(ops).toEqual([
      { kind: 'update', entity: 'dashboard_widget', id: 'w1', rowVersion: 3, patch: { name: 'Revenue (SAR)' }, links: {} },
      { kind: 'update', entity: 'dashboard_widget', id: 'w2', rowVersion: 1, patch: { sequence: 1 }, links: { section_id: { id: 's1' } } },
      { kind: 'create', entity: 'dashboard_section', ref: 'new-1', data: { name: 'More', section_type: 'container', layout_mode: 'grid', sequence: 1 },
        links: { page_id: { id: 'p1' }, parent_section_id: {} } },
      { kind: 'create', entity: 'dashboard_widget', ref: 'new-2', data: { name: 'Map', widget_type: 'map', sequence: 0 },
        links: { section_id: { ref: 'new-1' } } },
      { kind: 'delete', entity: 'dashboard_section', id: 's2' },
    ]);
    expect(resolveLinks({ section_id: { ref: 'new-1' }, parent_section_id: {} }, new Map([['new-1', 's9']])))
      .toEqual({ section_id: 's9', parent_section_id: null });
  });

  it('lays a page out at each breakpoint', () => {
    const page = toDesign(TREE).root.children![0];
    expect(previewBoxes(page, 'desktop').map(b => [b.name, b.col, b.span])).toEqual([['Pipeline', 7, 6], ['Revenue', 1, 6]]);
    expect(previewBoxes(page, 'tablet').map(b => b.span)).toEqual([3, 3]);
    expect(previewBoxes(page, 'phone').map(b => b.span)).toEqual([1, 1]);
  });
});

describe('DashboardDesignerComponent (P5-T1)', () => {
  let records: Record<string, ReturnType<typeof vi.fn>>;
  let dashboards: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    dashboards = {
      loadTree: vi.fn().mockReturnValue(of(TREE)),
      widgetTypes: vi.fn().mockReturnValue(of([{ type_id: 'kpi_card', display_name: 'KPI card' }])),
    };
    records = {
      create: vi.fn().mockReturnValue(of(rec('w9', {}))),
      update: vi.fn().mockReturnValue(of(rec('w1', {}, 4))),
      delete: vi.fn().mockReturnValue(of(undefined)),
    };
    TestBed.configureTestingModule({
      imports: [DashboardDesignerComponent],
      providers: [
        { provide: DashboardService, useValue: dashboards },
        { provide: EntityService, useValue: records },
        { provide: LangService, useValue: { translate: (key: string) => key, errorText: () => 'error' } },
      ],
    });
  });

  it('adds a widget from the registry into a section and saves it', async () => {
    const fixture = TestBed.createComponent(DashboardDesignerComponent);
    fixture.componentRef.setInput('id', 'd1');
    fixture.detectChanges();
    const cmp = fixture.componentInstance;
    expect(cmp.personal()).toBe(true);
    expect(cmp.widgetTypes().map(w => w.type_id)).toEqual(['kpi_card']);
    cmp.addWidget(cmp.widgetTypes()[0]);
    fixture.detectChanges();
    await cmp.save();
    expect(records['create']).toHaveBeenCalledWith('dashboard_widget', {
      name: 'KPI card', widget_type: 'kpi_card', grid_col: 1, grid_row: 1, grid_col_span: 4, grid_row_span: 2,
      sequence: 1, section_id: 's1',
    });
    expect(dashboards['loadTree']).toHaveBeenCalledTimes(2);
  });
});
