import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EntityService } from '../services/entity.service';
import { EditableGridComponent } from './editable-grid.component';
import { changed, editable, editorText, keyMove, parseCell } from './editable-grid.model';
import type { Col } from './entity-list.component';

describe('editable grid model (B6-T1)', () => {
  const at = { row: 1, col: 1 };

  it('moves with arrows, swapping left and right in a right-to-left layout', () => {
    expect(keyMove('ArrowRight', false, false, at, 3, 3, false)).toEqual({ kind: 'move', to: { row: 1, col: 2 } });
    expect(keyMove('ArrowRight', false, false, at, 3, 3, true)).toEqual({ kind: 'move', to: { row: 1, col: 0 } });
    expect(keyMove('ArrowLeft', false, false, at, 3, 3, true)).toEqual({ kind: 'move', to: { row: 1, col: 2 } });
    expect(keyMove('ArrowDown', false, false, { row: 2, col: 0 }, 3, 3, false)).toEqual({ kind: 'move', to: { row: 2, col: 0 } });
  });

  it('wraps Tab across rows and starts editing on Enter or F2', () => {
    expect(keyMove('Tab', false, false, { row: 0, col: 2 }, 3, 3, false)).toEqual({ kind: 'move', to: { row: 1, col: 0 } });
    expect(keyMove('Tab', true, false, { row: 1, col: 0 }, 3, 3, false)).toEqual({ kind: 'move', to: { row: 0, col: 2 } });
    expect(keyMove('F2', false, false, at, 3, 3, false)).toEqual({ kind: 'edit' });
    expect(keyMove('Enter', false, false, at, 3, 3, false)).toEqual({ kind: 'edit' });
  });

  it('commits on Enter and Tab while editing, cancels on Escape, and leaves typing to the editor', () => {
    expect(keyMove('Enter', false, true, at, 3, 3, false)).toEqual({ kind: 'commit', to: { row: 2, col: 1 } });
    expect(keyMove('Tab', false, true, at, 3, 3, false)).toEqual({ kind: 'commit', to: { row: 1, col: 2 } });
    expect(keyMove('Escape', false, true, at, 3, 3, false)).toEqual({ kind: 'cancel' });
    expect(keyMove('ArrowLeft', false, true, at, 3, 3, false)).toBeNull();
    expect(keyMove('a', false, false, at, 3, 3, false)).toBeNull();
  });

  it('parses typed text into the saved value, refusing what is not a value of the type', () => {
    expect(parseCell('number', '1,250.5')).toBe(1250.5);
    expect(parseCell('number', 'abc')).toBeUndefined();
    expect(parseCell('currency', '')).toBeNull();
    expect(parseCell('bool', 'true')).toBe(true);
    expect(parseCell('date', '2026-10-27')).toBe('2026-10-27');
    expect(parseCell('date', '27/10/2026')).toBeUndefined();
    expect(parseCell('text', 'hello')).toBe('hello');
    expect(editorText('date', '2026-10-27T00:00:00Z')).toBe('2026-10-27');
    expect(changed(null, undefined)).toBe(false);
    expect(changed('a', 'b')).toBe(true);
    expect(editable('lookup')).toBe(false);
    expect(editable('choice')).toBe(true);
  });
});

describe('EditableGridComponent (B6-T1)', () => {
  const col = (name: string, type: string): Col => ({
    name, display_name: name, type, sortable: true, is_clickable: false, route_template: '',
  });
  const record = (id: string, row_version: number, data: Record<string, unknown>) =>
    ({ id, row_version, data } as unknown as EntityRecord);

  function setUp(rtl = false) {
    const update = vi.fn((_e: string, id: string) =>
      id === 'b' ? throwError(() => ({ kind: 'conflict', status: 409, message: '' })) : of({}));
    TestBed.configureTestingModule({
      imports: [EditableGridComponent],
      providers: [
        { provide: EntityService, useValue: { update, getSchema: () => of(null) } },
        {
          provide: LangService,
          useValue: {
            translate: (key: string) => key,
            errorText: () => 'error',
            isRtl: signal(rtl),
            current: signal(rtl ? 'ar' : 'en'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(EditableGridComponent);
    fixture.componentRef.setInput('entityName', 'account');
    fixture.componentRef.setInput('columns', [col('name', 'text'), col('employees', 'number'), col('owner', 'lookup')]);
    fixture.componentRef.setInput('records', [
      record('a', 3, { name: 'Acme', employees: 10 }),
      record('b', 5, { name: 'Beta', employees: 20 }),
      record('c', 1, { name: 'Gamma', employees: 30 }),
    ]);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, update };
  }

  function edit(cmp: EditableGridComponent, row: number, column: number, text: string) {
    cmp.select(row, column);
    cmp.startEdit();
    cmp.draft.set(text);
    expect(cmp.commit()).toBe(true);
  }

  it('marks changed cells and sends one PATCH per changed row with its version and the merge header', () => {
    const { cmp, fixture, el, update } = setUp();
    edit(cmp, 0, 0, 'Acme Ltd');
    edit(cmp, 0, 1, '12');
    edit(cmp, 2, 1, '31');
    fixture.detectChanges();
    expect(el.querySelectorAll('td.pending').length).toBe(3);
    expect(cmp.changedRows()).toBe(2);
    cmp.saveAll();
    expect(update).toHaveBeenCalledTimes(2);
    expect(update).toHaveBeenCalledWith('account', 'a', { name: 'Acme Ltd', employees: 12 }, 3, { mergeAttributes: true });
    expect(update).toHaveBeenCalledWith('account', 'c', { employees: 31 }, 1, { mergeAttributes: true });
    expect(cmp.changedRows()).toBe(0);
  });

  it('keeps a refused row pending and says it conflicted', () => {
    const { cmp, fixture, el, update } = setUp();
    edit(cmp, 1, 0, 'Beta Co');
    edit(cmp, 2, 0, 'Gamma Co');
    cmp.saveAll();
    expect(update).toHaveBeenCalledTimes(2);
    expect(Object.keys(cmp.pending())).toEqual(['b']);
    fixture.detectChanges();
    expect(el.querySelector('.row-message')?.textContent).toContain('editableGrid.conflict');
  });

  it('refuses an invalid number, ignores a value put back as it was, and discards all', () => {
    const { cmp } = setUp();
    cmp.select(0, 1);
    cmp.startEdit();
    cmp.draft.set('ten');
    expect(cmp.commit()).toBe(false);
    expect(cmp.invalid()).toBe(true);
    cmp.draft.set('10');
    expect(cmp.commit()).toBe(true);
    expect(cmp.changedRows()).toBe(0);
    edit(cmp, 1, 0, 'X');
    cmp.discardAll();
    expect(cmp.pending()).toEqual({});
  });

  it('does not edit a lookup and moves with the keyboard, mirrored in Arabic', () => {
    const { cmp } = setUp(true);
    cmp.select(0, 2);
    cmp.startEdit();
    expect(cmp.editing()).toBe(false);
    cmp.select(0, 1);
    cmp.onKey(new KeyboardEvent('keydown', { key: 'ArrowLeft' }));
    expect(cmp.active()).toEqual({ row: 0, col: 2 });
    cmp.onKey(new KeyboardEvent('keydown', { key: 'ArrowRight' }));
    cmp.onKey(new KeyboardEvent('keydown', { key: 'F2' }));
    expect(cmp.editing()).toBe(true);
    cmp.draft.set('15');
    cmp.onKey(new KeyboardEvent('keydown', { key: 'Enter' }));
    expect(cmp.editing()).toBe(false);
    expect(cmp.active()).toEqual({ row: 1, col: 1 });
  });
});
