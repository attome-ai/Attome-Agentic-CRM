import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EntityService } from '../services/entity.service';
import { EditableGridComponent } from './editable-grid.component';
import type { Col } from './entity-list.component';
import { EMPTY_STATE, isNewRow, newRow, record, undoAll, undoLast, withValue } from './grid-undo';

const col = (name: string, type: string): Col => ({
  name, display_name: name, type, sortable: true, is_clickable: false, route_template: '',
});

describe('grid undo (B6-T4)', () => {
  it('takes back the last batch, or returns to how the session started', () => {
    const same = (a: unknown, b: unknown) => a === b;
    const s1 = withValue(EMPTY_STATE, 'a', 'name', 'X', 'A', same);
    const s2 = withValue(s1, 'a', 'name', 'A', 'A', same);
    expect(s1.pending).toEqual({ a: { name: 'X' } });
    expect(s2.pending).toEqual({});
    let history = record(record({ past: [] }, EMPTY_STATE), s1);
    const back = undoLast(history);
    expect(back?.state).toEqual(s1);
    history = back?.history ?? history;
    expect(history.past.length).toBe(1);
    expect(undoAll(record(history, s1))?.state).toEqual(EMPTY_STATE);
    expect(undoLast({ past: [] })).toBeNull();
    expect(isNewRow(newRow(1, { status: 'open' }).id)).toBe(true);
  });

  function setUp() {
    const create = vi.fn(() => of({}));
    const update = vi.fn(() => of({}));
    TestBed.configureTestingModule({
      imports: [EditableGridComponent],
      providers: [
        {
          provide: EntityService,
          useValue: { create, update, newDefaults: vi.fn(() => of({ status: 'open', employees: 5 })) },
        },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: () => 'e', isRtl: signal(false) } },
      ],
    });
    const fixture = TestBed.createComponent(EditableGridComponent);
    fixture.componentRef.setInput('entityName', 'account');
    fixture.componentRef.setInput('columns', [col('name', 'text'), col('employees', 'number')]);
    fixture.componentRef.setInput('records', [
      { id: 'a', row_version: 4, data: { name: 'A', employees: 1 } },
    ] as unknown as EntityRecord[]);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, create, update };
  }

  function edit(cmp: EditableGridComponent, row: number, column: number, text: string) {
    cmp.select(row, column);
    cmp.startEdit();
    cmp.draft.set(text);
    expect(cmp.commit()).toBe(true);
  }

  it('adds a row with the new-record defaults and creates it on save', () => {
    const { cmp, fixture, el, create, update } = setUp();
    cmp.addRow();
    fixture.detectChanges();
    expect(cmp.rows().length).toBe(2);
    expect(el.querySelectorAll('tr.row-new').length).toBe(1);
    expect(cmp.active().row).toBe(1);
    edit(cmp, 1, 0, 'Fresh');
    edit(cmp, 0, 1, '2');
    expect(cmp.changedRows()).toBe(2);
    cmp.saveAll();
    expect(create).toHaveBeenCalledWith('account', { status: 'open', employees: 5, name: 'Fresh' });
    expect(update).toHaveBeenCalledWith('account', 'a', { employees: 2 }, 4, { mergeAttributes: true });
    expect(cmp.rows().length).toBe(1);
    expect(cmp.canUndo()).toBe(false);
  });

  it('undoes edits one batch at a time and discards the whole session', () => {
    const { cmp } = setUp();
    edit(cmp, 0, 0, 'B');
    edit(cmp, 0, 1, '9');
    cmp.addRow();
    expect(cmp.rows().length).toBe(2);
    cmp.undo();
    expect(cmp.rows().length).toBe(1);
    expect(cmp.pending()).toEqual({ a: { name: 'B', employees: 9 } });
    cmp.onKey(new KeyboardEvent('keydown', { key: 'z', ctrlKey: true }));
    expect(cmp.pending()).toEqual({ a: { name: 'B' } });
    edit(cmp, 0, 1, '7');
    cmp.discardAll();
    expect(cmp.pending()).toEqual({});
    expect(cmp.canUndo()).toBe(false);
  });
});
