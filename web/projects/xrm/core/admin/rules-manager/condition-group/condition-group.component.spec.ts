import { TestBed } from '@angular/core/testing';
import { beforeEach, describe, expect, it } from 'vitest';
import { LangService } from '@attome/base';
import type { ConditionLeaf } from '@attome/xrm/core/admin/data';
import {
  ConditionEditorField, ConditionGroup, ConditionGroupComponent, MAX_CONDITION_DEPTH, scalarFromInput,
} from './condition-group.component';

const FIELDS: ConditionEditorField[] = [
  { name: 'amount', label: 'Amount', kind: 'number', choices: [] },
  { name: 'is_vip', label: 'VIP', kind: 'bool', choices: [] },
  { name: 'status', label: 'Status', kind: 'choice', choices: ['open', 'closed'] },
];

describe('ConditionGroupComponent (D-789 section 10)', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ConditionGroupComponent],
      providers: [{ provide: LangService, useValue: { translate: (k: string) => k } }],
    });
  });

  function render(group: ConditionGroup, depth = 1) {
    const fixture = TestBed.createComponent(ConditionGroupComponent);
    fixture.componentRef.setInput('group', group);
    fixture.componentRef.setInput('fields', FIELDS);
    fixture.componentRef.setInput('depth', depth);
    fixture.detectChanges();
    const emitted: ConditionGroup[] = [];
    fixture.componentInstance.groupChange.subscribe(g => emitted.push(g));
    return { fixture, c: fixture.componentInstance, emitted };
  }

  it('offers the operators of the field type only', () => {
    const { c } = render({ all: [] });
    expect(c.opsFor({ field: 'amount', op: 'eq' })).toContain('gt');
    expect(c.opsFor({ field: 'is_vip', op: 'eq' })).toEqual(['eq', 'is_empty', 'is_not_empty']);
    expect(c.opsFor({ field: 'status', op: 'eq' })).not.toContain('gt');
  });

  it('renders the operator options of a leaf from its type', () => {
    const { fixture } = render({ all: [{ field: 'is_vip', op: 'eq', value: true }] });
    const ops = (fixture.nativeElement as HTMLElement).querySelectorAll('select.cg-op option');
    expect([...ops].map(o => (o as HTMLOptionElement).value)).toEqual(['eq', 'is_empty', 'is_not_empty']);
  });

  it('shows "always" for an empty root group', () => {
    const { fixture } = render({ all: [] });
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('businessRules.condition.always');
  });

  it('adds a leaf on the first field and switches AND to OR', () => {
    const { c, emitted } = render({ all: [] });
    c.addLeaf();
    expect(emitted[0]).toEqual({ all: [{ field: 'amount', op: 'eq' }] });
    c.setMode('any');
    expect(emitted[1]).toEqual({ any: [] });
  });

  it('resets the operator and value when the field changes', () => {
    const leaf: ConditionLeaf = { field: 'amount', op: 'gt', value: 5 };
    const { c, emitted } = render({ all: [leaf] });
    c.setField(0, leaf, 'status');
    expect(emitted[0]).toEqual({ all: [{ field: 'status', op: 'eq' }] });
  });

  it('types a value by the field kind and a list one per line', () => {
    const leaf: ConditionLeaf = { field: 'amount', op: 'in' };
    const { c, emitted } = render({ all: [leaf] });
    c.setListText(0, leaf, '1\n 2 \n\n3');
    expect(emitted[0]).toEqual({ all: [{ field: 'amount', op: 'in', value: [1, 2, 3] }] });
  });

  it('stops offering nested groups at the depth limit', () => {
    const { c } = render({ all: [] }, MAX_CONDITION_DEPTH);
    expect(c.canNest()).toBe(false);
  });
});

describe('scalarFromInput', () => {
  it('converts by kind and keeps an unparsable number for the server to name', () => {
    expect(scalarFromInput('number', '12.5')).toBe(12.5);
    expect(scalarFromInput('number', 'abc')).toBe('abc');
    expect(scalarFromInput('bool', 'false')).toBe(false);
    expect(scalarFromInput('text', '  hi ')).toBe('hi');
    expect(scalarFromInput('date', '')).toBeUndefined();
  });
});
