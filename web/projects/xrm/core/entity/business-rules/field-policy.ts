import { InjectionToken } from '@angular/core';
import type { ApiComponents, ApiError } from '@attome/base';
import { evaluateBusinessRuleCondition, type FieldKindResolver } from './business-rule-condition';
import type { BusinessRuleClient, RuleSeverity } from '@attome/xrm/core/admin/data';

/**
 * D-789 §3.3/§5 — what the business rules delivered with `/schema` mean for
 * one form's fields, and the token through which `<xrm-base-form>` hands
 * that to `attome-field-input` and `*xrmFieldVisible`.
 *
 * `disabled` = shown read-only, not editable; `hidden` = not shown and not
 * editable. Across every rule whose condition holds, per field the most
 * restrictive wins (`hidden` > `disabled` > none); among equal effects the
 * first rule in delivery (display) order names the lock — exactly
 * `attome_core::business_rules::combine_locks`. Hidden is **not** read
 * security, and none of this is enforcement: the server refuses a write that
 * changes a locked field (422 `field_locked`).
 */
export type FieldLockEffect = 'hidden' | 'disabled';

export interface FieldLockState {
  effect: FieldLockEffect;
  /** The rule's display name, else its name — what the lock icon names. */
  ruleName: string;
}

/** A field-attached `error` policy that fires live (shown, never blocking). */
export interface FieldRuleMessage {
  message: string;
  severity: RuleSeverity;
  ruleName: string;
}

export interface FieldPolicyOutcome {
  locks: ReadonlyMap<string, FieldLockState>;
  errors: ReadonlyMap<string, readonly FieldRuleMessage[]>;
}

const RANK: Record<FieldLockEffect, number> = { disabled: 1, hidden: 2 };

/** The rule's label: its display name when it has one. */
export function ruleLabel(rule: Pick<BusinessRuleClient, 'name' | 'display_name'>): string {
  const d = rule.display_name?.trim();
  return d ? d : rule.name;
}

/**
 * Evaluates every delivered rule against `record` and combines the result.
 * A condition the client cannot decide (`null`) counts as true — fail
 * closed, as on the server (design §3.2).
 */
export function computeFieldPolicies(
  rules: readonly BusinessRuleClient[],
  record: Readonly<Record<string, unknown>>,
  kindOf: FieldKindResolver,
): FieldPolicyOutcome {
  const locks = new Map<string, FieldLockState>();
  const errors = new Map<string, FieldRuleMessage[]>();
  for (const rule of rules) {
    if (evaluateBusinessRuleCondition(rule.condition, record, kindOf) === false) continue;
    const label = ruleLabel(rule);
    for (const p of rule.policies) {
      if (!p.field) continue;
      if (p.type === 'hidden' || p.type === 'disabled') {
        const existing = locks.get(p.field);
        if (!existing || RANK[p.type] > RANK[existing.effect]) {
          locks.set(p.field, { effect: p.type, ruleName: label });
        }
      } else if (p.type === 'error') {
        const list = errors.get(p.field) ?? [];
        list.push({ message: p.message ?? '', severity: p.severity ?? 'error', ruleName: label });
        errors.set(p.field, list);
      }
    }
  }
  return { locks, errors };
}

/**
 * What `<xrm-base-form>` provides to its content. Every member reads the
 * host form's signals, so a template or `computed` calling it re-renders
 * when the record or the rules change.
 */
export interface XrmFieldPolicy {
  /** The lock on `field` for this user and record, or `null`. */
  lock(field: string): FieldLockState | null;
  /** Field-attached `error` policies firing on the current values. */
  ruleErrors(field: string): readonly FieldRuleMessage[];
  /** The last save's refusal naming this field (`field_locked`, `rule_violation`), or `null`. */
  serverError(field: string): string | null;
  /** A required field that a rule locks and that is empty: the save will fail (§3.4). */
  requiredLocked(field: string): boolean;
  /** The field's current value (stored overlaid with the form's), for a read-only display. */
  value(field: string): unknown;
}

export const XRM_FIELD_POLICY = new InjectionToken<XrmFieldPolicy>('XRM_FIELD_POLICY');

/**
 * A `warning`-severity `error` policy that fired on a successful generic
 * write (D-791 rule 6): the additive `warnings` list of the create, update
 * and upsert responses: the generated `RuleWarning` (the editor's warning is
 * `RuleEditorWarning`).
 */
export type RuleWriteWarning = ApiComponents['schemas']['RuleWarning'];

/** The write response's `warnings` (absent when there are none). */
export function writeWarnings(response: unknown): RuleWriteWarning[] {
  const list = (response as { warnings?: unknown } | null)?.warnings;
  if (!Array.isArray(list)) return [];
  return list.filter((w): w is RuleWriteWarning =>
    typeof w === 'object' && w !== null
    && typeof (w as RuleWriteWarning).message === 'string'
    && typeof (w as RuleWriteWarning).rule_name === 'string');
}

/** The error codes whose body names a locked field (`AppError::FieldLocked`). */
export const FIELD_LOCKED_CODES: readonly string[] = ['field_locked', 'field_locked_required'];

/**
 * The fields a failed save names, keyed by field logical name, valued with
 * the message to show under it:
 *
 * - `field_locked` / `field_locked_required` (422): `ApiService` keeps the
 *   body's structured members — `details.fields[]` (`LockedField {field,
 *   rule_id, rule_name, effect}`, every locked field) and the top-level
 *   `field` (the first). Only when neither is present (an older server or a
 *   proxy-rewritten body) is the first field read from the message, whose
 *   fixed shape is `'<field>' is locked by the rule '<rule>'…` /
 *   `'<field>' is required but the rule '<rule>' locks it…`
 *   (`attome-types::error::field_locked_message`).
 * - `rule_violation`: `details.field` when the body carries it.
 */
export function fieldErrorsFromApiError(err: ApiError | null | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!err) return out;
  const details = (typeof err.details === 'object' && err.details !== null)
    ? err.details as { fields?: unknown; field?: unknown }
    : null;
  if (err.code && FIELD_LOCKED_CODES.includes(err.code)) {
    const structured = Array.isArray(details?.fields) ? details.fields : [];
    for (const f of structured) {
      const name = (f as { field?: unknown } | null)?.field;
      if (typeof name === 'string' && !out.has(name)) out.set(name, err.message);
    }
    if (out.size === 0 && err.field) out.set(err.field, err.message);
    if (out.size === 0) {
      // Fallback only: the structured members were absent.
      const name = /^'([^']+)'/.exec(err.message)?.[1];
      if (name) out.set(name, err.message);
    }
  } else if (err.kind === 'rule_violation' && typeof details?.field === 'string') {
    out.set(details.field, err.message);
  }
  return out;
}

/** `null`, `undefined`, a blank string or an empty list. */
export function isEmptyFieldValue(v: unknown): boolean {
  if (v === null || v === undefined) return true;
  if (typeof v === 'string') return v.trim() === '';
  if (Array.isArray(v)) return v.length === 0;
  return false;
}
