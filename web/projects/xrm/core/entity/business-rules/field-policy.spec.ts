import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import type { ApiError } from '@attome/base';
import { fieldKindResolver } from './business-rule-condition';
import type { BusinessRuleClient } from '@attome/xrm/core/admin/data';
import {
  computeFieldPolicies, fieldErrorsFromApiError, isEmptyFieldValue, writeWarnings,
  XRM_FIELD_POLICY, type FieldLockState, type XrmFieldPolicy,
} from './field-policy';
import { XrmFieldVisibleDirective } from './field-visible.directive';

const kindOf = fieldKindResolver([
  { name: 'status', field_type: 'choice', options: { choices: ['open', 'closed'], multi: false } },
  { name: 'amount', field_type: 'number', options: null },
]);

function rule(name: string, condition: BusinessRuleClient['condition'], policies: BusinessRuleClient['policies']): BusinessRuleClient {
  return { name, display_name: null, condition, policies };
}

describe('computeFieldPolicies (D-789 section 3.3)', () => {
  it('most restrictive wins; the first rule names a tie', () => {
    const rules = [
      rule('a', { all: [] }, [{ type: 'disabled', field: 'amount' }]),
      rule('b', { all: [] }, [{ type: 'disabled', field: 'amount' }, { type: 'hidden', field: 'status' }]),
      rule('c', { all: [] }, [{ type: 'disabled', field: 'status' }]),
    ];
    const { locks } = computeFieldPolicies(rules, {}, kindOf);
    expect(locks.get('amount')).toEqual({ effect: 'disabled', ruleName: 'a' });
    expect(locks.get('status')).toEqual({ effect: 'hidden', ruleName: 'b' });
  });

  it('a false condition applies nothing; an undecidable one fails closed', () => {
    const rules = [
      rule('off', { field: 'status', op: 'eq', value: 'closed' }, [{ type: 'hidden', field: 'amount' }]),
      rule('unknown', { expression: 'amount > 1' }, [{ type: 'disabled', field: 'status' }]),
    ];
    const { locks } = computeFieldPolicies(rules, { status: 'open' }, kindOf);
    expect(locks.has('amount')).toBe(false);
    expect(locks.get('status')?.effect).toBe('disabled');
  });

  it('collects field-attached error policies with their severity', () => {
    const rules = [
      rule('big', { field: 'amount', op: 'gt', value: 10 }, [
        { type: 'error', field: 'amount', message: 'Too big', severity: 'error' },
        { type: 'error', message: 'no field: not shown under a field', severity: 'error' },
      ]),
    ];
    const { errors } = computeFieldPolicies(rules, { amount: 11 }, kindOf);
    expect(errors.get('amount')).toEqual([{ message: 'Too big', severity: 'error', ruleName: 'big' }]);
    expect(errors.size).toBe(1);
  });
});

describe('fieldErrorsFromApiError', () => {
  const base: ApiError = { kind: 'validation', status: 422, message: '' };

  it('puts every failing field of a validation error under its field (A3-T7)', () => {
    const err = {
      ...base, code: 'validation_error', message: 'two fields failed',
      details: [
        { field: 'email', code: 'invalid', message: 'email: not an email address' },
        { field: 'name', code: 'required', message: 'name: field is required' },
      ],
    } as ApiError;
    const plain = fieldErrorsFromApiError(err);
    expect(plain.get('email')).toBe('email: not an email address');
    expect(plain.get('name')).toBe('name: field is required');
    const arabic = fieldErrorsFromApiError(err, code => (code === 'required' ? 'هذا الحقل مطلوب.' : 'x'));
    expect(arabic.get('name')).toBe('هذا الحقل مطلوب.');
  });

  it('reads the structured lock list when present', () => {
    const err = {
      ...base, code: 'field_locked', message: 'm',
      details: { fields: [{ field: 'amount' }, { field: 'notes' }] },
    } as ApiError;
    expect([...fieldErrorsFromApiError(err).keys()]).toEqual(['amount', 'notes']);
  });

  it('reads the top-level field when details carries no list', () => {
    const err: ApiError = { ...base, code: 'field_locked', message: 'm', field: 'amount', ruleName: 'R', effect: 'hidden' };
    expect([...fieldErrorsFromApiError(err).keys()]).toEqual(['amount']);
  });

  it('prefers the structured members over the message text', () => {
    const err: ApiError = {
      ...base, code: 'field_locked', field: 'notes',
      message: "'amount' is locked by the rule 'R' and cannot be changed",
      details: { fields: [{ field: 'notes' }] },
    };
    expect([...fieldErrorsFromApiError(err).keys()]).toEqual(['notes']);
  });

  it('falls back to the message shape for both lock codes', () => {
    const locked = { ...base, code: 'field_locked', message: "'amount' is locked by the rule 'R' and cannot be changed" };
    const required = { ...base, code: 'field_locked_required', message: "'owner_note' is required but the rule 'R' locks it for your role" };
    expect([...fieldErrorsFromApiError(locked).keys()]).toEqual(['amount']);
    expect([...fieldErrorsFromApiError(required).keys()]).toEqual(['owner_note']);
  });

  it('maps a field-attached rule_violation and ignores everything else', () => {
    const violation = { ...base, kind: 'rule_violation', message: 'no', details: { field: 'amount', rules: [] } } as ApiError;
    expect(fieldErrorsFromApiError(violation).get('amount')).toBe('no');
    expect(fieldErrorsFromApiError({ ...base, message: "'x' something" }).size).toBe(0);
    expect(fieldErrorsFromApiError(null).size).toBe(0);
  });
});

describe('writeWarnings / isEmptyFieldValue', () => {
  it('reads the additive warnings list and tolerates its absence', () => {
    expect(writeWarnings({ id: 'r' })).toEqual([]);
    expect(writeWarnings({ warnings: [{ rule_id: 'x', rule_name: 'R', message: 'm' }, { junk: true }] }))
      .toEqual([{ rule_id: 'x', rule_name: 'R', message: 'm' }]);
  });

  it('treats null, blanks and empty lists as empty', () => {
    expect(isEmptyFieldValue(null)).toBe(true);
    expect(isEmptyFieldValue('  ')).toBe(true);
    expect(isEmptyFieldValue([])).toBe(true);
    expect(isEmptyFieldValue(0)).toBe(false);
    expect(isEmptyFieldValue(false)).toBe(false);
  });
});

describe('*xrmFieldVisible', () => {
  const lock = signal<FieldLockState | null>(null);
  const policy: XrmFieldPolicy = {
    lock: () => lock(),
    ruleErrors: () => [],
    serverError: () => null,
    requiredLocked: () => false,
    value: () => null,
  };

  @Component({
    standalone: true,
    imports: [XrmFieldVisibleDirective],
    template: `<span *xrmFieldVisible="'amount'" class="probe">x</span>`,
  })
  class HostComponent {}

  it('removes the content while the field is hidden and restores it after', () => {
    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [{ provide: XRM_FIELD_POLICY, useValue: policy }],
    });
    const fixture = TestBed.createComponent(HostComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.probe')).not.toBeNull();

    lock.set({ effect: 'hidden', ruleName: 'R' });
    fixture.detectChanges();
    expect(el.querySelector('.probe')).toBeNull();

    lock.set({ effect: 'disabled', ruleName: 'R' });
    fixture.detectChanges();
    expect(el.querySelector('.probe')).not.toBeNull();
  });
});
