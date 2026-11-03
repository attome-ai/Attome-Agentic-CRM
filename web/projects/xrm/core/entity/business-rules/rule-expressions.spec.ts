import { describe, expect, it } from 'vitest';

import type { BusinessRuleClient } from '@attome/xrm/core/admin/data';
import { evaluateBusinessRuleCondition, fieldKindResolver, rulesTypesOf } from './business-rule-condition';
import { computeFieldPolicies, ruleExpressions } from './field-policy';

const kindOf = fieldKindResolver([
  { name: 'amount', field_type: 'number', options: null },
  { name: 'reason', field_type: 'text', options: null },
]);

const big: BusinessRuleClient = {
  name: 'big_needs_reason',
  display_name: 'Big amounts need a reason',
  condition: { all: [{ expression: 'amount > 1000' }] },
  policies: [
    { type: 'required', field: 'reason' },
    { type: 'error', field: 'amount', message: 'Over the limit', severity: 'warning' },
  ],
  needs_evaluator: true,
};

describe('rules with expressions (A11-T3)', () => {
  it('lists each expression once, from the rules that need the evaluator', () => {
    const plain: BusinessRuleClient = { ...big, name: 'plain', needs_evaluator: false };
    expect(ruleExpressions([big, big, plain])).toEqual(['amount > 1000']);
  });

  it('answers an expression leaf from the evaluator results', () => {
    const tree = { any: [{ expression: 'amount > 1000' }] };
    expect(evaluateBusinessRuleCondition(tree, {}, kindOf)).toBeNull();
    expect(evaluateBusinessRuleCondition(tree, {}, kindOf, new Map([['amount > 1000', true]]))).toBe(true);
    expect(evaluateBusinessRuleCondition(tree, {}, kindOf, new Map([['amount > 1000', false]]))).toBe(false);
  });

  it('a rule waiting for the evaluator does not fire', () => {
    const outcome = computeFieldPolicies([big], { amount: 5000 }, kindOf);
    expect(outcome.required.size).toBe(0);
    expect(outcome.errors.size).toBe(0);
  });

  it('fires required and error policies once the expression holds', () => {
    const holds = computeFieldPolicies([big], { amount: 5000 }, kindOf, new Map([['amount > 1000', true]]));
    expect(holds.required.get('reason')).toBe('Big amounts need a reason');
    expect(holds.errors.get('amount')?.[0].message).toBe('Over the limit');
    const not = computeFieldPolicies([big], { amount: 5 }, kindOf, new Map([['amount > 1000', false]]));
    expect(not.required.size).toBe(0);
  });

  it('a plain condition the client cannot decide still fails closed', () => {
    const unknown: BusinessRuleClient = {
      name: 'unknown', display_name: null,
      condition: { field: 'missing', op: 'eq', value: 'x' },
      policies: [{ type: 'error', field: 'amount', message: 'Check', severity: 'error' }],
    };
    expect(computeFieldPolicies([unknown], {}, kindOf).errors.get('amount')?.length).toBe(1);
  });
});

describe('rule language types (A11-T3)', () => {
  it('declares each field by its condition kind', () => {
    expect(rulesTypesOf([
      { name: 'amount', field_type: 'number', options: null },
      { name: 'tags', field_type: 'choice', options: { choices: ['a', 'b'], multi: true } },
    ]).fields).toEqual({ amount: 'number', tags: 'list<choice>' });
  });
});
