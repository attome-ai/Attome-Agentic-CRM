import type { FieldSchema } from '@attome/xrm';
import type {
  BusinessRuleOp, ConditionFieldKind, ConditionLeaf, ConditionTree,
} from '@attome/xrm/core/admin/data';
import {
  CONDITION_SYSTEM_FIELDS, OPS_BY_KIND, conditionFieldKind, isConditionAll, isConditionAny,
  isConditionExpression, isConditionLeaf,
} from '@attome/xrm/core/admin/data';

/**
 * D-789 rule 2 / design §2 — the client interpreter of a business-rule
 * condition. **UX only**: the server evaluates the same tree through
 * `attome_core::business_rules::compile_condition` + `attome-rules` (one
 * evaluator, D-399) and enforces every write. The shared fixture
 * `conformance.json` (beside this file) runs through both — this file in
 * `business-rule-condition.spec.ts`, the server in `attome-core`'s
 * `conformance_fixture_matches_compile_and_base_rules` — so the two cannot
 * drift.
 *
 * Semantics (mirrors `Compiler::leaf` and `condition_value` in
 * `business_rules.rs`):
 * - text compares case-insensitively after trimming (`lower(trim(f))`);
 *   choice keys and lookups compare exactly (a lookup as a UUID);
 * - a leaf on an empty field is `false`, except `is_empty`, `ne` and
 *   `not_in`, which are `true`;
 * - empty means null/absent, a value of the wrong JSON type, and — for
 *   `is_empty`/`is_not_empty` only — a blank text, a blank choice key or an
 *   empty multi-choice list;
 * - a date is RFC 3339 or `YYYY-MM-DD` (midnight UTC), compared as an instant.
 *
 * Returns `true`, `false`, or `null` for **unknown** (an advanced
 * `expression` leaf, an unknown field, an operator the field's kind does not
 * allow, or a malformed value). The caller treats unknown as true for
 * `hidden`/`disabled`/`error` (fail closed, design §3.2) — the same posture
 * as the server; a condition the form cannot decide never loosens a lock.
 */
export type ConditionResult = boolean | null;

/** Resolves a field name to its condition kind; `undefined` = not a condition field. */
export type FieldKindResolver = (field: string) => ConditionFieldKind | undefined;

export { conditionFieldKind };

/**
 * A resolver over an entity's schema fields, plus the condition system
 * fields (`owner_ref`, `organization_ref`) as lookups.
 */
export function fieldKindResolver(
  fields: readonly Pick<FieldSchema, 'name' | 'field_type' | 'options'>[],
): FieldKindResolver {
  const kinds = new Map<string, ConditionFieldKind>();
  for (const f of fields) {
    const kind = conditionFieldKind(f);
    if (kind) kinds.set(f.name, kind);
  }
  return name => kinds.get(name) ?? (CONDITION_SYSTEM_FIELDS.includes(name) ? 'lookup' : undefined);
}

/**
 * Evaluates `tree` against `record` (the record as it will be saved: stored
 * values overlaid with the form's current values).
 */
export function evaluateBusinessRuleCondition(
  tree: ConditionTree,
  record: Readonly<Record<string, unknown>>,
  kindOf: FieldKindResolver,
): ConditionResult {
  if (isConditionAll(tree)) {
    let unknown = false;
    for (const child of tree.all) {
      const r = evaluateBusinessRuleCondition(child, record, kindOf);
      if (r === false) return false;
      if (r === null) unknown = true;
    }
    return unknown ? null : true;
  }
  if (isConditionAny(tree)) {
    if (tree.any.length === 0) return null; // refused by the server's validation
    let unknown = false;
    for (const child of tree.any) {
      const r = evaluateBusinessRuleCondition(child, record, kindOf);
      if (r === true) return true;
      if (r === null) unknown = true;
    }
    return unknown ? null : false;
  }
  if (isConditionExpression(tree)) return null; // server-only (attome-rules)
  if (isConditionLeaf(tree)) return evaluateLeaf(tree, record, kindOf);
  return null;
}

// ── Leaves ──────────────────────────────────────────────────────────────────

function evaluateLeaf(
  leaf: ConditionLeaf,
  record: Readonly<Record<string, unknown>>,
  kindOf: FieldKindResolver,
): ConditionResult {
  const kind = kindOf(leaf.field);
  if (!kind || !OPS_BY_KIND[kind].includes(leaf.op)) return null;
  const raw = Object.prototype.hasOwnProperty.call(record, leaf.field) ? record[leaf.field] : undefined;
  const value = fieldValue(kind, raw);
  const op = leaf.op;

  if (op === 'is_empty') return isBlank(kind, value);
  if (op === 'is_not_empty') return !isBlank(kind, value);

  if (kind === 'multi_choice') {
    const held = value as string[] | null;
    if (op === 'contains') {
      const p = choiceParam(leaf.value);
      if (p === null) return null;
      return held !== null && held.includes(p);
    }
    if (op === 'in') {
      const ps = listParam(leaf.value, choiceParam);
      if (ps === null) return null;
      return held !== null && ps.some(p => held.includes(p));
    }
    return null;
  }

  if (op === 'in' || op === 'not_in') {
    const ps = listParam(leaf.value, v => scalarParam(kind, v));
    if (ps === null) return null;
    const lhs = normalized(kind, value);
    const hit = lhs !== null && ps.some(p => lhs === p);
    return op === 'in' ? hit : (lhs === null || !hit);
  }

  const p = scalarParam(kind, leaf.value);
  if (p === null) return null;
  const lhs = normalized(kind, value);
  switch (op as BusinessRuleOp) {
    case 'eq':  return lhs !== null && lhs === p;
    case 'ne':  return lhs === null || !lhs === p;
    case 'gt':  return lhs !== null && compare(lhs, p) > 0;
    case 'gte': return lhs !== null && compare(lhs, p) >= 0;
    case 'lt':  return lhs !== null && compare(lhs, p) < 0;
    case 'lte': return lhs !== null && compare(lhs, p) <= 0;
    case 'contains':
      return lhs !== null && typeof lhs === 'string' && typeof p === 'string' && lhs.includes(p);
    case 'starts_with':
      return lhs !== null && typeof lhs === 'string' && typeof p === 'string' && lhs.startsWith(p);
    default:
      return null;
  }
}

type Scalar = string | number | boolean;

/**
 * The field's value inside a condition (`condition_value`): `null` for
 * absent, JSON `null`, and a value of the wrong JSON type. Text stays raw
 * here (blank-ness matters to `is_empty`); a multi-choice value is its list
 * of string keys; a date is epoch milliseconds; a lookup is its UUID.
 */
function fieldValue(kind: ConditionFieldKind, v: unknown): Scalar | string[] | null {
  if (v === null || v === undefined) return null;
  switch (kind) {
    case 'text':
    case 'choice':
      return typeof v === 'string' ? v : null;
    case 'number':
      return typeof v === 'number' && Number.isFinite(v) ? v : null;
    case 'date':
      return typeof v === 'string' ? parseDate(v) : null;
    case 'bool':
      return typeof v === 'boolean' ? v : null;
    case 'multi_choice':
      return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : null;
    case 'lookup':
      return typeof v === 'string' ? parseUuid(v) : null;
  }
}

/** "Empty" as `is_empty` defines it: null, a blank text, a blank choice key, an empty list. */
function isBlank(kind: ConditionFieldKind, value: Scalar | string[] | null): boolean {
  if (value === null) return true;
  if (kind === 'text') return (value as string).trim() === '';
  if (kind === 'choice') return value === '';
  if (kind === 'multi_choice') return (value as string[]).length === 0;
  return false;
}

/** The left-hand side as the program compares it: text is `lower(trim(f))`. */
function normalized(kind: ConditionFieldKind, value: Scalar | string[] | null): Scalar | null {
  if (value === null || Array.isArray(value)) return null;
  if (kind === 'text') return (value as string).trim().toLowerCase();
  return value;
}

/** One leaf value of `kind` (`Compiler::scalar`); `null` when malformed. */
function scalarParam(kind: ConditionFieldKind, v: unknown): Scalar | null {
  switch (kind) {
    case 'text': {
      if (typeof v !== 'string') return null;
      const s = v.trim().toLowerCase();
      return s === '' ? null : s;
    }
    case 'number':
      return typeof v === 'number' && Number.isFinite(v) ? v : null;
    case 'date':
      return typeof v === 'string' ? parseDate(v) : null;
    case 'bool':
      return typeof v === 'boolean' ? v : null;
    case 'choice':
    case 'multi_choice':
      return choiceParam(v);
    case 'lookup':
      return typeof v === 'string' ? parseUuid(v) : null;
  }
}

function choiceParam(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}

function listParam<T>(v: unknown, item: (x: unknown) => T | null): T[] | null {
  if (!Array.isArray(v) || v.length === 0) return null;
  const out: T[] = [];
  for (const x of v) {
    const p = item(x);
    if (p === null) return null;
    out.push(p);
  }
  return out;
}

function compare(a: Scalar, b: Scalar): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  // Ordering is defined for numbers and dates (both numbers here) only;
  // the operator table never routes another kind to gt/gte/lt/lte.
  return Number.NaN;
}

const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

/** RFC 3339 or `YYYY-MM-DD` (midnight UTC) → epoch ms (`parse_date`). */
export function parseDate(s: string): number | null {
  const d = DATE_ONLY.exec(s);
  if (d) {
    const year = Number(d[1]);
    const month = Number(d[2]);
    const day = Number(d[3]);
    const ms = Date.UTC(year, month - 1, day);
    const back = new Date(ms);
    // Reject calendar overflow (2026-02-30) the way chrono does.
    if (back.getUTCFullYear() !== year || back.getUTCMonth() !== month - 1 || back.getUTCDate() !== day) {
      return null;
    }
    return ms;
  }
  if (!RFC3339.test(s)) return null;
  const ms = Date.parse(s.replace(' ', 'T'));
  return Number.isFinite(ms) ? ms : null;
}

const UUID_HYPHENATED = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const UUID_SIMPLE = /^[0-9a-f]{32}$/i;

/** A UUID in its canonical lowercase, hyphen-free form, or `null`. */
function parseUuid(s: string): string | null {
  if (UUID_HYPHENATED.test(s) || UUID_SIMPLE.test(s)) return s.replace(/-/g, '').toLowerCase();
  return null;
}
