import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { CustomerTestEditorComponent } from './customer-test-editor.component';
import { type CustomerTest, fromTest, parseValue, toDefinition } from './customer-test.model';

const ENTITIES = [{ id: 'e1', logicalname: 'account', name: 'Account' }];

describe('CustomerTestEditorComponent (Z15-T15)', () => {
  function create(test: CustomerTest | null = null) {
    const post = vi.fn((_: string, body: unknown) => of({ id: 'new', ...(body as object) }));
    const patch = vi.fn((_: string, _body: unknown, _version?: number) => of({ id: 't1' }));
    const getEntity = vi.fn(() => of({ attributes: [{ logicalname: 'name' }, { logicalname: 'amount' }] }));
    TestBed.configureTestingModule({
      imports: [CustomerTestEditorComponent],
      providers: [
        { provide: ApiService, useValue: { post, patch } },
        { provide: AdminService, useValue: { listEntities: () => of(ENTITIES), getEntity } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(CustomerTestEditorComponent);
    fixture.componentRef.setInput('test', test);
    fixture.detectChanges();
    return { fixture, post, patch, getEntity };
  }

  it('adds a given row', () => {
    const { fixture } = create();
    fixture.componentInstance.addGiven();
    fixture.detectChanges();
    expect(fixture.componentInstance.draft.given.length).toBe(1);
    expect(fixture.nativeElement.querySelectorAll('[data-section="given"]').length).toBe(1);
  });

  it('loads an entity attributes once for its picker', () => {
    const { fixture, getEntity } = create();
    fixture.componentInstance.loadAttributes('account');
    fixture.componentInstance.loadAttributes('account');
    expect(getEntity).toHaveBeenCalledTimes(1);
    expect(fixture.componentInstance.attributesOf('account')).toEqual(['amount', 'name']);
  });

  it('saves a new test as a definition', () => {
    const { fixture, post } = create();
    const editor = fixture.componentInstance;
    editor.draft.name = 'Rename keeps the record';
    editor.addGiven();
    editor.draft.given[0].entity = 'account';
    editor.draft.given[0].values.push({ attribute: 'name', value: 'Acme' });
    editor.addExpect();
    editor.draft.expect[0] = { kind: 'error', entity: '', ref: '', attribute: '', equals: '', error: 'forbidden' };
    editor.save();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/customer-tests', {
      name: 'Rename keeps the record',
      description: null,
      blocking: false,
      definition: {
        given: [{ entity: 'account', ref: 'r1', record: { name: 'Acme' } }],
        when: [],
        expect: [{ error: 'forbidden' }],
      },
    });
  });

  it('changes an existing test under its row version', () => {
    const test = {
      id: 't1', name: 'x', description: null, blocking: true, is_active: true, row_version: 4,
      definition: { as_role: 'Sales', when: [{ op: 'delete', entity: 'account', ref: 'a' }], expect: [{ error: 'forbidden' }] },
      created_at: '', updated_at: '', created_by: null, last_passed: null, last_run_at: null,
    } as CustomerTest;
    const { fixture, patch } = create(test);
    expect(fixture.componentInstance.draft.asRole).toBe('Sales');
    fixture.componentInstance.save();
    expect(patch).toHaveBeenCalledWith('/api/v1/admin/customer-tests/t1', expect.anything(), 4);
  });

  it('round-trips a definition and types values', () => {
    const definition = {
      given: [{ entity: 'account', ref: 'a', record: { name: 'Acme', amount: 12 } }],
      when: [{ op: 'update', entity: 'account', ref: 'a', values: { name: 'Acme 2' } }],
      expect: [{ entity: 'account', ref: 'a', attribute: 'name', equals: 'Acme 2' }],
    };
    const draft = fromTest({ definition } as unknown as CustomerTest);
    expect(toDefinition(draft)).toEqual(definition);
    expect(parseValue('12')).toBe(12);
    expect(parseValue('true')).toBe(true);
    expect(parseValue('Acme')).toBe('Acme');
  });
});
