import { describe, expect, it } from 'vitest';

import type { BusinessRuleClient } from '@attome/xrm/core/admin/data';
import { fieldKindResolver } from './business-rule-condition';
import { computeFieldPolicies, reconcileAllowed } from './field-policy';

const kindOf = fieldKindResolver([
  { name: 'region', field_type: 'choice', options: { choices: ['central', 'western'], multi: false } },
  { name: 'city', field_type: 'choice', options: { choices: ['riyadh', 'kharj', 'jeddah'], multi: false } },
]);

function rule(name: string, region: string, cities: string[]): BusinessRuleClient {
  return {
    name,
    display_name: null,
    condition: { field: 'region', op: 'eq', value: region },
    policies: [{ type: 'allowed_values', field: 'city', value: cities }],
  };
}

describe('allowed values (A6-T2)', () => {
  const rules = [rule('central', 'central', ['riyadh', 'kharj']), rule('western', 'western', ['jeddah'])];

  it('limits a field to what the firing rules allow', () => {
    const { allowed } = computeFieldPolicies(rules, { region: 'central' }, kindOf);
    expect(allowed.get('city')).toEqual(['riyadh', 'kharj']);
    expect(computeFieldPolicies(rules, { region: null }, kindOf).allowed.has('city')).toBe(false);
  });

  it('intersects two rules on the same field', () => {
    const narrower = rule('both', 'central', ['kharj', 'jeddah']);
    const { allowed } = computeFieldPolicies([...rules, narrower], { region: 'central' }, kindOf);
    expect(allowed.get('city')).toEqual(['kharj']);
  });

  it('fills a single allowed value, clears one that no longer fits, keeps one that does', () => {
    expect(reconcileAllowed(null, ['jeddah'])).toEqual({ kind: 'fill', value: 'jeddah' });
    expect(reconcileAllowed('', ['riyadh', 'kharj'])).toEqual({ kind: 'keep' });
    expect(reconcileAllowed('jeddah', ['riyadh', 'kharj'])).toEqual({ kind: 'clear' });
    expect(reconcileAllowed('riyadh', ['riyadh', 'kharj'])).toEqual({ kind: 'keep' });
    expect(reconcileAllowed(['riyadh', 'jeddah'], ['riyadh'])).toEqual({ kind: 'clear' });
  });
});
