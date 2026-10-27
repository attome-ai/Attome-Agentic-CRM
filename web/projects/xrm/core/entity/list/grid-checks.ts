/**
 * B6-T2: the checks the editable grid runs on each changed or added row
 * before it saves, pure: a field's own checks as the form runs them (A3-T7:
 * required, pattern, format, range) and the entity's business rules that
 * reach the browser (A11: a rule's error on a field, and a field a rule
 * locks). Untouched cells of a stored row are not checked: only what this
 * person changed, and every cell of a row they added. A row with an issue
 * is not saved; the others are.
 */
import { FormControl, Validators } from '@angular/forms';
import type { BusinessRuleClient } from '@attome/xrm/core/admin/data';
import type { FieldSchema } from '@attome/xrm';

import { fieldKindResolver } from '../business-rules/business-rule-condition';
import { computeFieldPolicies, isEmptyFieldValue } from '../business-rules/field-policy';
import { checkFailure, fieldValidators } from '../field/field-checks';

/** One cell's issue: a catalogue key with its parameters, or a rule's own message. */
export interface CellIssue {
  key: string;
  params: Record<string, unknown>;
  /** A business rule's message, shown as the rule's author wrote it. */
  text?: string;
}

/** Issues by field. */
export type RowIssues = Record<string, CellIssue>;

/** The issue of one field's value, or `null`. Required is only checked when `checkRequired`. */
export function fieldIssue(field: FieldSchema, value: unknown, checkRequired: boolean): CellIssue | null {
  if (isEmptyFieldValue(value)) {
    return checkRequired && field.is_required ? { key: 'editableGrid.required', params: {} } : null;
  }
  const check = Validators.compose(fieldValidators(field).filter(v => v !== Validators.required));
  const failure = check ? checkFailure(check(new FormControl(value))) : null;
  return failure ? { key: failure.key, params: failure.params } : null;
}

/**
 * The issues of one row as it will be saved (`stored` overlaid with
 * `changes`). `isNew`: an added row, whose every field is checked.
 */
export function rowIssues(
  fields: readonly FieldSchema[],
  rules: readonly BusinessRuleClient[],
  stored: Readonly<Record<string, unknown>>,
  changes: Readonly<Record<string, unknown>>,
  isNew: boolean,
): RowIssues {
  const out: RowIssues = {};
  const record = { ...stored, ...changes };
  for (const field of fields) {
    const touched = field.name in changes;
    if (!isNew && !touched) continue;
    const issue = fieldIssue(field, record[field.name], true);
    if (issue) out[field.name] = issue;
  }
  if (rules.length) {
    const outcome = computeFieldPolicies(rules, record, fieldKindResolver(fields));
    for (const [name, messages] of outcome.errors) {
      const blocking = messages.find(m => m.severity === 'error');
      if (blocking && !out[name] && (isNew || name in changes)) {
        out[name] = { key: 'editableGrid.ruleError', params: { rule: blocking.ruleName }, text: blocking.message };
      }
    }
    for (const [name, lock] of outcome.locks) {
      if (name in changes && !out[name]) {
        out[name] = { key: 'editableGrid.locked', params: { rule: lock.ruleName } };
      }
    }
  }
  return out;
}
