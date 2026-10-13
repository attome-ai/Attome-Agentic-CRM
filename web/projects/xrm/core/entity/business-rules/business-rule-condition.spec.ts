import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { FieldType } from '@attome/xrm';
import {
  conditionFieldKind, evaluateBusinessRuleCondition, fieldKindResolver, parseDate,
} from './business-rule-condition';
import type { ConditionTree } from '@attome/xrm/core/admin/data';

/**
 * D-789 rule 2 — the shared conformance fixture. The same file runs through
 * `attome_core::business_rules::compile_condition` + `attome-rules` in the
 * Rust unit test `conformance_fixture_matches_compile_and_base_rules`
 * (`include_str!`). Read off disk (like `field-types.lockstep.spec.ts`) so
 * the spec needs no JSON-module compiler setting.
 */
interface FixtureField {
  name: string;
  type: FieldType;
  choices?: string[];
  multi?: boolean;
  result_type?: 'text' | 'number' | 'currency' | 'date' | 'bool';
}
interface FixtureCase {
  name: string;
  condition: ConditionTree;
  record: Record<string, unknown>;
  expected: boolean;
}
interface Fixture { version: number; fields: FixtureField[]; cases: FixtureCase[] }

// process.cwd() is the angular/ workspace root when `ng test xrm` runs.
const FIXTURE = resolve(process.cwd(), 'projects/xrm/core/entity/business-rules/conformance.json');
const fixture = JSON.parse(readFileSync(FIXTURE, 'utf-8')) as Fixture;

const kindOf = fieldKindResolver(fixture.fields.map(f => ({
  name: f.name,
  field_type: f.type,
  options: f.type === 'choice'
    ? { choices: f.choices ?? [], multi: f.multi === true }
    : f.type === 'formula'
      ? { expression: '', result_type: f.result_type ?? 'text' }
      : null,
})));

describe('evaluateBusinessRuleCondition — conformance fixture (D-789)', () => {
  it('loads the fixture', () => {
    expect(fixture.version).toBe(1);
    expect(fixture.cases.length).toBeGreaterThanOrEqual(57);
  });

  for (const c of fixture.cases) {
    it(c.name, () => {
      expect(evaluateBusinessRuleCondition(c.condition, c.record, kindOf)).toBe(c.expected);
    });
  }
});

describe('evaluateBusinessRuleCondition — unknown outcomes', () => {
  it('an advanced expression leaf is unknown on the client', () => {
    expect(evaluateBusinessRuleCondition({ expression: 'amount > 1' }, {}, kindOf)).toBeNull();
  });

  it('unknown propagates through all/any unless decided', () => {
    const unknown: ConditionTree = { expression: 'true' };
    const yes: ConditionTree = { field: 'amount', op: 'gt', value: 1 };
    const record = { amount: 5 };
    expect(evaluateBusinessRuleCondition({ all: [yes, unknown] }, record, kindOf)).toBeNull();
    expect(evaluateBusinessRuleCondition({ any: [yes, unknown] }, record, kindOf)).toBe(true);
    expect(evaluateBusinessRuleCondition({ all: [{ field: 'amount', op: 'lt', value: 1 }, unknown] }, record, kindOf))
      .toBe(false);
  });

  it('a field the entity does not have is unknown', () => {
    expect(evaluateBusinessRuleCondition({ field: 'nope', op: 'is_empty' }, {}, kindOf)).toBeNull();
  });

  it('an operator the field kind does not allow is unknown', () => {
    expect(evaluateBusinessRuleCondition({ field: 'is_vip', op: 'gt', value: true }, {}, kindOf)).toBeNull();
  });

  it('a malformed value is unknown', () => {
    expect(evaluateBusinessRuleCondition({ field: 'amount', op: 'in', value: [] }, { amount: 1 }, kindOf)).toBeNull();
    expect(evaluateBusinessRuleCondition({ field: 'due', op: 'eq', value: 'yesterday' }, {}, kindOf)).toBeNull();
  });
});

describe('conditionFieldKind', () => {
  it('maps every field type the operator table knows', () => {
    expect(conditionFieldKind({ field_type: 'text', options: null })).toBe('text');
    expect(conditionFieldKind({ field_type: 'currency', options: null })).toBe('number');
    expect(conditionFieldKind({ field_type: 'choice', options: { choices: [], multi: true } })).toBe('multi_choice');
    expect(conditionFieldKind({ field_type: 'formula', options: { expression: '', result_type: 'date' } })).toBe('date');
    expect(conditionFieldKind({ field_type: 'rich_text', options: null })).toBeUndefined();
    expect(conditionFieldKind({ field_type: 'file', options: null })).toBeUndefined();
  });
});

describe('parseDate', () => {
  it('accepts RFC 3339 and date-only values, rejects the rest', () => {
    expect(parseDate('2026-03-01')).toBe(Date.UTC(2026, 2, 1));
    expect(parseDate('2026-03-01T03:00:00+03:00')).toBe(Date.UTC(2026, 2, 1));
    expect(parseDate('2026-02-30')).toBeNull();
    expect(parseDate('03/01/2026')).toBeNull();
  });
});
