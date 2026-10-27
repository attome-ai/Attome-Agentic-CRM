import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntityRecord, EntitySchema, FieldSchema } from '@attome/xrm';
import type { BusinessRuleClient } from '@attome/xrm/core/admin/data';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EntityService } from '../services/entity.service';
import { EditableGridComponent } from './editable-grid.component';
import type { Col } from './entity-list.component';
import { fieldIssue, rowIssues } from './grid-checks';

const field = (name: string, field_type: FieldSchema['field_type'], extra: Partial<FieldSchema> = {}): FieldSchema => ({
  id: `f-${name}`, entity_id: 'e', name, display_name: name, field_type, options: null, sort_order: 0,
  is_required: false, ...extra,
});
const FIELDS: FieldSchema[] = [
  field('name', 'text', { is_required: true }),
  field('email', 'text', { options: { format: 'email' } as unknown as FieldSchema['options'] }),
  field('employees', 'number', { options: { min: 0, max: 1000 } as unknown as FieldSchema['options'] }),
];
const NO_TOP_SECRET: BusinessRuleClient = {
  name: 'no_secret', display_name: 'No secret accounts',
  condition: { field: 'name', op: 'eq', value: 'Secret' },
  policies: [{ type: 'error', field: 'name', message: 'Pick another name', severity: 'error' }],
};

describe('editable grid checks (B6-T2)', () => {
  it('checks what changed with the form checks, and every field of an added row', () => {
    expect(fieldIssue(FIELDS[1], 'not-an-email', true)?.key).toBe('xrmForm.check.format.email');
    expect(fieldIssue(FIELDS[2], 5000, true)?.key).toBe('xrmForm.check.max');
    expect(fieldIssue(FIELDS[0], '', true)?.key).toBe('editableGrid.required');
    expect(fieldIssue(FIELDS[0], '', false)).toBeNull();

    // A stored row is only checked where it changed.
    expect(rowIssues(FIELDS, [], { name: 'A', email: 'bad' }, { employees: 3 }, false)).toEqual({});
    expect(Object.keys(rowIssues(FIELDS, [], { name: 'A' }, { email: 'bad' }, false))).toEqual(['email']);
    // An added row is checked whole.
    expect(Object.keys(rowIssues(FIELDS, [], {}, { email: 'a@b.co' }, true))).toEqual(['name']);
    // A business rule's error lands on its field, with the rule's own message.
    expect(rowIssues(FIELDS, [NO_TOP_SECRET], { name: 'A' }, { name: 'Secret' }, false)['name']?.text)
      .toBe('Pick another name');
  });
});

describe('EditableGridComponent errors (B6-T2)', () => {
  const col = (name: string, type: string): Col => ({
    name, display_name: name, type, sortable: true, is_clickable: false, route_template: '',
  });

  function setUp(update: unknown) {
    const schema = { id: 'e', name: 'account', plural_name: 'accounts', fields: FIELDS, relationships: [],
      business_rules: [NO_TOP_SECRET] } as EntitySchema;
    TestBed.configureTestingModule({
      imports: [EditableGridComponent],
      providers: [
        { provide: EntityService, useValue: { update, getSchema: () => of(schema) } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, errorText: () => 'error', isRtl: signal(false) },
        },
      ],
    });
    const fixture = TestBed.createComponent(EditableGridComponent);
    fixture.componentRef.setInput('entityName', 'account');
    fixture.componentRef.setInput('columns', [col('name', 'text'), col('email', 'text'), col('employees', 'number')]);
    fixture.componentRef.setInput('records', [
      { id: 'a', row_version: 1, data: { name: 'A', email: 'a@x.co', employees: 1 } },
      { id: 'b', row_version: 2, data: { name: 'B', email: 'b@x.co', employees: 2 } },
      { id: 'c', row_version: 3, data: { name: 'C', email: 'c@x.co', employees: 3 } },
    ] as unknown as EntityRecord[]);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  function edit(cmp: EditableGridComponent, row: number, column: number, text: string) {
    cmp.select(row, column);
    cmp.startEdit();
    cmp.draft.set(text);
    expect(cmp.commit()).toBe(true);
  }

  it('marks a failing row and saves the others', () => {
    const update = vi.fn(() => of({}));
    const { cmp, fixture, el } = setUp(update);
    edit(cmp, 0, 1, 'not-an-email');
    edit(cmp, 1, 2, '20');
    edit(cmp, 2, 0, 'Secret');
    fixture.detectChanges();
    expect(el.querySelectorAll('td.cell-error').length).toBe(2);
    expect(cmp.heldRows()).toBe(2);
    cmp.saveAll();
    expect(update).toHaveBeenCalledTimes(1);
    expect(update).toHaveBeenCalledWith('account', 'b', { employees: 20 }, 2, { mergeAttributes: true });
    expect(Object.keys(cmp.pending()).sort()).toEqual(['a', 'c']);
  });

  it('puts a refused save on the cells the server named and keeps the other rows saving', () => {
    const update = vi.fn((_e: string, id: string) => id === 'a'
      ? throwError(() => ({
        kind: 'validation', status: 422, message: '', code: 'validation_error',
        details: [{ field: 'employees', code: 'too_many', message: 'Too many' }],
      }))
      : of({}));
    const { cmp, fixture, el } = setUp(update);
    edit(cmp, 0, 2, '7');
    edit(cmp, 1, 2, '8');
    cmp.saveAll();
    expect(update).toHaveBeenCalledTimes(2);
    expect(Object.keys(cmp.pending())).toEqual(['a']);
    fixture.detectChanges();
    expect(el.querySelector('td[data-cell="0:2"]')?.getAttribute('title')).toBe('Too many');
  });

  it('opens the conflict dialog for one row and saves it again with the newer version', () => {
    let calls = 0;
    const update = vi.fn(() => {
      calls += 1;
      return calls === 1
        ? throwError(() => ({
          kind: 'version_conflict', status: 409, message: '',
          versionConflict: {
            currentVersion: 9, lastChangedBy: 'Sara', lastChangedAt: null, hiddenChanges: 0,
            changedAttributes: [{ name: 'employees', their_value: '50', changed_by: 'Sara', changed_at: null }],
          },
        }))
        : of({});
    });
    const { cmp, fixture, el } = setUp(update);
    edit(cmp, 0, 2, '7');
    edit(cmp, 0, 0, 'A2');
    cmp.saveAll();
    fixture.detectChanges();
    const resolve = el.querySelector<HTMLButtonElement>('[data-testid="grid-resolve"]');
    expect(resolve).not.toBeNull();
    resolve?.click();
    fixture.detectChanges();
    expect(el.querySelector('[data-conflict-dialog]')).not.toBeNull();
    cmp.resolveConflict({ employees: 'theirs' });
    expect(update).toHaveBeenLastCalledWith('account', 'a', { name: 'A2' }, 9, { mergeAttributes: true });
    expect(cmp.pending()).toEqual({});
    expect(cmp.openConflict()).toBeNull();
  });
});
