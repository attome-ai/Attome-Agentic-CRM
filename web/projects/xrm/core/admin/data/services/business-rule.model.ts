/**
 * Business-rule condition and policy wire types (D-789, design
 * `document/general/BUSINESS-RULES-DESIGN.md` sections 2, 5 and 10), shared
 * by the record form (`@attome/xrm/core/entity`, the client evaluator) and the
 * business-rule editor (`@attome/xrm/core/admin`). Here, in a `/data` entry
 * point, so neither pulls the other's components (D-314).
 *
 * Mirrors `crates/engine/attome-core/src/business_rules.rs`
 * (`ConditionTree`, `ConditionLeaf`, `BusinessRuleOp`, `PolicyDef`,
 * `PolicyType`, `Severity`, `SetMode`) and the `/schema` delivery
 * `crates/engine/attome-api/src/schema.rs::BusinessRuleClient`.
 *
 * The type declarations live in the root `@attome/xrm` (`src/lib/types.ts`),
 * beside `EntitySchema.business_rules`, and are re-exported here; this file
 * adds the runtime helpers (operator table, guards, `conditionFieldKind`).
 */

import type {
  BusinessRuleOp, ConditionAll, ConditionAny, ConditionExpression, ConditionFieldKind,
  ConditionLeaf, ConditionTree,
} from '@attome/xrm';

export type {
  BusinessRuleOp, ConditionAll, ConditionAny, ConditionExpression, ConditionLeaf, ConditionTree,
  PolicyType, RuleSeverity, SetMode, PolicyDef, BusinessRuleClient, ConditionFieldKind,
} from '@attome/xrm';

export const BUSINESS_RULE_OPS: readonly BusinessRuleOp[] = [
  'eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'not_in', 'contains', 'starts_with',
  'is_empty', 'is_not_empty',
];

/** `CONDITION_SYSTEM_FIELDS`: system columns a condition may read, as lookups. */
export const CONDITION_SYSTEM_FIELDS: readonly string[] = ['owner_ref', 'organization_ref'];

/** The operator table of design §2 (`ConditionFieldKind::allows`). */
export const OPS_BY_KIND: Readonly<Record<ConditionFieldKind, readonly BusinessRuleOp[]>> = {
  text:         ['eq', 'ne', 'in', 'not_in', 'contains', 'starts_with', 'is_empty', 'is_not_empty'],
  number:       ['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'not_in', 'is_empty', 'is_not_empty'],
  date:         ['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'is_empty', 'is_not_empty'],
  bool:         ['eq', 'is_empty', 'is_not_empty'],
  choice:       ['eq', 'ne', 'in', 'not_in', 'is_empty', 'is_not_empty'],
  multi_choice: ['contains', 'in', 'is_empty', 'is_not_empty'],
  lookup:       ['eq', 'ne', 'in', 'not_in', 'is_empty', 'is_not_empty'],
};

/** `true` for the operators that take no value. */
export function opTakesNoValue(op: BusinessRuleOp): boolean {
  return op === 'is_empty' || op === 'is_not_empty';
}

/** `true` for the operators whose value is a list. */
export function opTakesList(op: BusinessRuleOp): boolean {
  return op === 'in' || op === 'not_in';
}

export function isConditionAll(n: ConditionTree): n is ConditionAll {
  return typeof n === 'object' && n !== null && Array.isArray((n as ConditionAll).all);
}

export function isConditionAny(n: ConditionTree): n is ConditionAny {
  return typeof n === 'object' && n !== null && Array.isArray((n as ConditionAny).any);
}

export function isConditionExpression(n: ConditionTree): n is ConditionExpression {
  return typeof n === 'object' && n !== null && typeof (n as ConditionExpression).expression === 'string';
}

export function isConditionLeaf(n: ConditionTree): n is ConditionLeaf {
  return typeof n === 'object' && n !== null
    && typeof (n as ConditionLeaf).field === 'string' && typeof (n as ConditionLeaf).op === 'string';
}

/** `true` when the tree holds an advanced (`expression`) leaf anywhere. */
export function conditionHasExpression(n: ConditionTree): boolean {
  if (isConditionAll(n)) return n.all.some(conditionHasExpression);
  if (isConditionAny(n)) return n.any.some(conditionHasExpression);
  return isConditionExpression(n);
}

/** The condition kind of one schema field (`ConditionFieldKind::of_attr`). */
export function conditionFieldKind(
  field: { field_type: string; options?: unknown },
): ConditionFieldKind | undefined {
  switch (field.field_type) {
    case 'text': case 'icon': case 'color':
      return 'text';
    case 'number': case 'currency':
      return 'number';
    case 'date':
      return 'date';
    case 'bool':
      return 'bool';
    case 'choice':
      return (field.options as { multi?: boolean } | null)?.multi ? 'multi_choice' : 'choice';
    case 'lookup':
      return 'lookup';
    case 'formula':
      // D-604: a formula reads as its result type.
      switch ((field.options as { result_type?: string } | null)?.result_type) {
        case 'number': case 'currency': return 'number';
        case 'date': return 'date';
        case 'bool': return 'bool';
        default: return 'text';
      }
    default:
      // rich_text, file, image: never a leaf.
      return undefined;
  }
}
