import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EntityService } from '../services/entity.service';
import { EditableGridComponent } from './editable-grid.component';
import type { Col } from './entity-list.component';
import { fillValues, headerTarget, parseTsv, planPaste } from './grid-paste';

const col = (name: string, display_name: string, type: string): Col => ({
  name, display_name, type, sortable: true, is_clickable: false, route_template: '',
});
const COLUMNS = [col('name', 'Name', 'text'), col('employees', 'Employees', 'number'),
  col('since', 'Customer since', 'date'), col('owner', 'Owner', 'lookup')];

describe('grid paste (B6-T3)', () => {
  it('splits Excel text, keeping tabs, line breaks and quotes inside quoted cells', () => {
    expect(parseTsv('a\tb\r\n"x\ty"\t"two\nlines"\n"say ""hi"""\t\n')).toEqual([
      ['a', 'b'],
      ['x\ty', 'two\nlines'],
      ['say "hi"', ''],
    ]);
    expect(headerTarget('customer_since', COLUMNS)).toBe(2);
    expect(headerTarget('nothing', COLUMNS)).toBe(-1);
  });

  it('maps by the header row when it names the columns, and marks cells that do not convert', () => {
    const plan = planPaste(parseTsv('Employees\tName\tColour\n12\tAcme\tred\nmany\tBeta\tblue\n'), COLUMNS,
      { row: 0, col: 0 }, 5);
    expect(plan.byHeader).toBe(true);
    expect(plan.targets).toEqual([1, 0, -1]);
    expect(plan.unmatched).toEqual(['Colour']);
    expect(plan.cells).toEqual([
      { row: 0, col: 1, raw: '12', value: 12 },
      { row: 0, col: 0, raw: 'Acme', value: 'Acme' },
      { row: 1, col: 1, raw: 'many', error: 'invalid' },
      { row: 1, col: 0, raw: 'Beta', value: 'Beta' },
    ]);
  });

  it('places a block without headers from the active cell and skips what falls off the grid', () => {
    const plan = planPaste(parseTsv('3\t2026-01-05\tx\textra\n4\t2026-01-06\ty\n5\t2026-01-07\tz\n'), COLUMNS,
      { row: 1, col: 1 }, 3);
    expect(plan.byHeader).toBe(false);
    expect(plan.targets).toEqual([1, 2, 3, -1]);
    expect(plan.overflowRows).toBe(1);
    expect(plan.cells.filter(c => c.col === 3).every(c => c.error === 'readonly')).toBe(true);
    expect(plan.cells.find(c => c.row === 2 && c.col === 2)?.value).toBe('2026-01-06');
  });

  it('continues a number or date series and copies anything else', () => {
    expect(fillValues([1, 3], 'number', 3)).toEqual([5, 7, 9]);
    expect(fillValues([0.1, 0.2], 'number', 2)).toEqual([0.3, 0.4]);
    expect(fillValues(['2026-01-30', '2026-01-31'], 'date', 2)).toEqual(['2026-02-01', '2026-02-02']);
    expect(fillValues([5], 'number', 2)).toEqual([5, 5]);
    expect(fillValues(['a', 'b'], 'text', 2)).toEqual(['b', 'b']);
  });

  it('previews a paste in the grid and fills only the cells that converted', () => {
    TestBed.configureTestingModule({
      imports: [EditableGridComponent],
      providers: [
        { provide: EntityService, useValue: { update: vi.fn(() => of({})), newDefaults: vi.fn(() => of({})) } },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: () => 'e', isRtl: signal(false) } },
      ],
    });
    const fixture = TestBed.createComponent(EditableGridComponent);
    fixture.componentRef.setInput('entityName', 'account');
    fixture.componentRef.setInput('columns', COLUMNS);
    fixture.componentRef.setInput('records', [
      { id: 'a', row_version: 1, data: { name: 'A', employees: 1 } },
      { id: 'b', row_version: 1, data: { name: 'B', employees: 2 } },
    ] as unknown as EntityRecord[]);
    fixture.detectChanges();
    const cmp = fixture.componentInstance;
    const el = fixture.nativeElement as HTMLElement;

    cmp.previewPaste('Name\tEmployees\nAcme\t10\nBeta\tlots\n');
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="paste-preview"]')).not.toBeNull();
    expect(el.querySelectorAll('.paste-preview td.paste-error').length).toBe(1);
    expect(cmp.pasteValid()).toBe(3);

    cmp.applyPaste();
    expect(cmp.pastePlan()).toBeNull();
    expect(cmp.pending()).toEqual({ a: { name: 'Acme', employees: 10 }, b: { name: 'Beta' } });

    // Dragging the corner of A's employees copies it down; with Ctrl it continues the series.
    cmp.discardAll();
    cmp.select(0, 1);
    cmp.fill(1, false);
    expect(cmp.pending()).toEqual({ b: { employees: 1 } });
    cmp.discardAll();
    cmp.select(1, 1);
    cmp.fill(1, true);
    expect(cmp.pending()).toEqual({});
  });
});
