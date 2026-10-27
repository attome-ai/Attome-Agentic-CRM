import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ReportBuilderComponent } from './report-builder.component';
import { emptyReport, parameterDecls, pivot, promptValues, ready, reportSpec, summarise } from './report-builder.model';
import { matrixChart, summaryChart } from './report-chart';

describe('ReportBuilderComponent (P1-T1)', () => {
  const schema = {
    fields: [
      { name: 'name', display_name: 'Name', field_type: 'text' },
      { name: 'stage', display_name: 'Stage', field_type: 'choice' },
      { name: 'owner_ref', display_name: 'Owner', field_type: 'lookup' },
      { name: 'amount', display_name: 'Amount', field_type: 'number' },
      { name: 'close_date', display_name: 'Close date', field_type: 'date' },
    ],
  };

  function setUp(answer: unknown) {
    const post = vi.fn(() => of(answer));
    const api = { get: vi.fn(() => of(schema)), post };
    TestBed.configureTestingModule({
      imports: [ReportBuilderComponent],
      providers: [
        { provide: ApiService, useValue: api },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
            errorText: () => 'error',
            current: signal('en'),
            intlLocale: signal('en-US'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(ReportBuilderComponent);
    const cmp = fixture.componentInstance;
    cmp.live.set(false);
    cmp.entityInput.set('opportunity');
    cmp.loadEntity();
    fixture.detectChanges();
    return { fixture, cmp, el: fixture.nativeElement as HTMLElement, post };
  }

  it('previews a table of chosen and related columns, at most 50 rows', () => {
    const { fixture, cmp, el, post } = setUp({ items: [{ name: 'Acme', 'account.industry': 'Retail' }] });
    (el.querySelector('[data-column="name"]') as HTMLInputElement).click();
    cmp.relatedPath.set('account.industry');
    cmp.addRelated();
    cmp.run();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/query/run', {
      spec: { entity: 'opportunity', select: ['name', 'account.industry'], page_size: 50 },
    });
    expect(el.querySelector('[data-table]')?.textContent).toContain('Retail');
  });

  it('summarises a sum by month with its total', () => {
    const { fixture, cmp, el, post } = setUp({ groups: [
      { keys: { close_date: '2026-02-01' }, values: { value: '250.5' } },
      { keys: { close_date: '2026-01-01' }, values: { value: 100 } },
      { keys: { close_date: null }, values: { value: 350.5 }, rolled_up: ['close_date'] },
    ] });
    cmp.setLayout('summary');
    cmp.update({ func: 'sum', field: 'amount' });
    cmp.setGroup('rows', { field: 'close_date' });
    cmp.setGroup('rows', { bucket: 'month' });
    cmp.run();
    fixture.detectChanges();
    expect(post).toHaveBeenLastCalledWith('/api/v1/query/run', { spec: {
      entity: 'opportunity',
      group_by: [{ field: 'close_date', bucket: 'month' }],
      totals: 'rollup',
      aggregates: [{ func: 'sum', field: 'amount', alias: 'value' }],
    } });
    const summary = el.querySelector('[data-summary]') as HTMLElement;
    expect(summary.querySelectorAll('tbody tr')[0].textContent).toContain('2026-01-01');
    expect(el.querySelector('[data-total]')?.textContent).toContain('350.5');
  });

  it('pivots a count by two groupings with totals each way', () => {
    const { fixture, cmp, el } = setUp({ groups: [
      { keys: { stage: 'won', owner_ref: 'sara' }, values: { value: 2 } },
      { keys: { stage: 'won', owner_ref: 'omar' }, values: { value: 1 } },
      { keys: { stage: 'lost', owner_ref: 'sara' }, values: { value: 4 } },
      { keys: { stage: 'won', owner_ref: null }, values: { value: 3 }, rolled_up: ['owner_ref'] },
      { keys: { stage: 'lost', owner_ref: null }, values: { value: 4 }, rolled_up: ['owner_ref'] },
      { keys: { stage: null, owner_ref: 'sara' }, values: { value: 6 }, rolled_up: ['stage'] },
      { keys: { stage: null, owner_ref: 'omar' }, values: { value: 1 }, rolled_up: ['stage'] },
      { keys: { stage: null, owner_ref: null }, values: { value: 7 }, rolled_up: ['stage', 'owner_ref'] },
    ] });
    cmp.setLayout('matrix');
    cmp.setGroup('rows', { field: 'stage' });
    cmp.setGroup('across', { field: 'owner_ref' });
    cmp.run();
    fixture.detectChanges();
    const cells = (row: Element | null) => [...(row?.querySelectorAll('td') ?? [])].map(td => td.textContent?.trim());
    expect(cells(el.querySelector('[data-matrix-row="won"]'))).toEqual(['1', '2', '3']);
    expect(cells(el.querySelector('[data-matrix] [data-total]'))).toEqual(['1', '6', '7']);
  });

  it('runs the preview by itself after a change when live', async () => {
    vi.useFakeTimers();
    const { fixture, cmp, post } = setUp({ items: [] });
    cmp.live.set(true);
    cmp.toggleColumn('name');
    fixture.detectChanges();
    vi.advanceTimersByTime(450);
    expect(post).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });

  it('asks prompts as parameters, saves the report and shares it (P1-T3)', () => {
    const { cmp, post } = setUp({ items: [] });
    const put = vi.fn(() => of({ query_id: 'q-1', shares: [] }));
    (TestBed.inject(ApiService) as unknown as { put: typeof put }).put = put;
    cmp.toggleColumn('name');
    cmp.addPrompt();
    cmp.setPrompt(0, { field: 'stage', name: 'stage', value: 'won' });
    cmp.run();
    expect(post).toHaveBeenLastCalledWith('/api/v1/query/run', {
      spec: {
        entity: 'opportunity', select: ['name'], page_size: 50,
        where: { kind: 'param', field: 'stage', op: 'eq', param: 'stage' },
      },
      params: { stage: 'won' },
    });
    post.mockReturnValueOnce(of({ id: 'q-1' }));
    cmp.reportName.set('Won deals');
    cmp.saveReport();
    expect(post).toHaveBeenLastCalledWith('/api/v1/admin/queries', expect.objectContaining({
      name: 'Won deals', parameters: [{ name: 'stage', type: 'text', required: true }],
    }));
    expect(cmp.savedId()).toBe('q-1');
    cmp.setShare({ type: 'role', id: 'r-1', name: 'Sales' }, 'read');
    cmp.setShare({ type: 'team', id: 't-1', name: 'East' }, 'edit');
    cmp.setShare({ type: 'team', id: 't-1', name: 'East' }, 'none');
    cmp.applyShares();
    expect(put).toHaveBeenCalledWith('/api/v1/admin/query-shares/q-1', {
      shares: [{ principal_type: 'role', principal_id: 'r-1', access: 'read' }],
    });
  });

  it('draws grouped results as chart series (P1-T3)', () => {
    const lines = summaryChart([{ key: 'won', value: 3 }, { key: 'lost', value: null }], 'Count', '#000000');
    expect(lines.categories.map(c => c.label)).toEqual(['won', 'lost']);
    expect(lines.series[0].points[0]?.value).toBe(3);
    expect(lines.series[0].points[1]).toBeNull();
    const m = matrixChart(pivot([
      { keys: { r: 'x', c: 'a' }, values: { value: 1 } }, { keys: { r: 'x', c: 'b' }, values: { value: 2 } },
    ], 'r', 'c'), ['#111111', '#222222']);
    expect(m.series.map(se => se.name)).toEqual(['a', 'b']);
    expect(m.series[1].color).toBe('#222222');
    expect(promptValues([{ field: 'amount', op: 'gt', name: 'min', type: 'number', value: '10' }])).toEqual({ min: 10 });
    expect(parameterDecls([{ field: 'x', op: 'eq', name: 'Bad Name', type: 'text', value: '' }])).toEqual([]);
  });

  it('builds specs and layouts purely', () => {
    const state = { ...emptyReport('deal'), layout: 'matrix' as const, rows: { field: 'a', bucket: '' as const }, across: { field: 'a', bucket: '' as const } };
    expect(ready(state)).toBe(false);
    expect(ready({ ...state, across: { field: 'b', bucket: '' } })).toBe(true);
    expect(reportSpec({ ...emptyReport('deal'), columns: ['x'], conditions: [{ field: 'amount', op: 'gt', value: '10' }] })['where'])
      .toEqual({ kind: 'compare', field: 'amount', op: 'gt', value: 10 });
    expect(summarise([{ keys: { s: 'a' }, values: { value: 3 } }], 's').total).toBeNull();
    const avg = summarise([
      { keys: { s: 'a' }, values: { value: 2 } }, { keys: { s: 'b' }, values: { value: 10 } },
      { keys: { s: null }, values: { value: 4 }, rolled_up: ['s'] },
    ], 's');
    expect(avg.lines).toHaveLength(2);
    expect(avg.total).toBe(4);
    const m = pivot([{ keys: { r: 'x', c: 'y' }, values: { value: 2 } }], 'r', 'c');
    expect(m.total).toBeNull();
    expect(m.cells['x']['y']).toBe(2);
  });
});
