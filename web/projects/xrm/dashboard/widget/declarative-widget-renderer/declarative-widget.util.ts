// Pure helpers for `declarative_widget` rendering — deliberately free of
// Angular DI so they are trivial to unit test directly (no TestBed). None of
// these ever build or interpret HTML: `evaluateCondition`/
// `resolveConditionalColor` only ever return a `#hex` string (validated) or
// `null`, and `substitutePlaceholders` only ever produces a plain string that
// the component binds through `{{ }}` interpolation or a sanitized property
// binding — never `[innerHTML]`. See this directory's
// `declarative-widget-renderer.component.spec.ts` for the end-to-end
// injection proof.

import type { Condition, ConditionalColorRule, ConditionOperator } from './declarative-widget.types';

/** `#RGB` / `#RRGGBB` / `#RRGGBBAA` only — the same allow-list the backend's
 * `validate_hex_color` enforces at write time (`declarative_widget.rs`).
 * Re-checked here so a config written before this check existed, or written
 * by any path that bypassed the validate-config endpoint, still cannot put
 * an arbitrary string into a `style` binding. */
export function isSafeHexColor(value: string | null | undefined): value is string {
  if (!value) return false;
  const match = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.exec(value);
  return match !== null;
}

/** `http://`/`https://` absolute, or a site-relative path starting with a
 * single `/` — mirrors the backend's `validate_link_target`
 * (`declarative_widget.rs`) exactly, including the `//host` (protocol-
 * relative) rejection. Re-checked client-side as an independent layer: even
 * a config that somehow bypassed write-time validation must not become a
 * clickable `javascript:`/`data:` link here. */
export function isSafeLinkTarget(value: string | null | undefined): value is string {
  if (!value) return false;
  if (value.length > 2000) return false;
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f]/.test(value)) return false;
  const lower = value.toLowerCase();
  if (lower.startsWith('http://') || lower.startsWith('https://')) return true;
  return value.startsWith('/') && !value.startsWith('//');
}

/** Replaces every `{field}` placeholder in `template` with the row's plain
 * string value for that field (missing/undefined -> empty string). Pure
 * string substitution — the result is only ever used as plain text or as an
 * `href`/`[style]` value, never parsed as markup. */
export function substitutePlaceholders(template: string, row: Record<string, unknown>): string {
  return template.replace(/\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g, (_match, field: string) => {
    const value = row[field];
    return value === null || value === undefined ? '' : String(value);
  });
}

function coerceComparable(value: unknown): number | string | null {
  if (typeof value === 'number' || typeof value === 'string') return value;
  if (value === null || value === undefined) return null;
  return String(value);
}

/** Structured predicate evaluation — never `eval`/`Function`, matching the
 * backend's own "declarative JSON, not a mini-language" boundary
 * (`declarative_widget.rs`'s `ConditionalColor` doc comment). */
export function evaluateCondition(row: Record<string, unknown>, condition: Condition): boolean {
  const actual = row[condition.field];
  const op: ConditionOperator = condition.operator;

  if (op === 'is_empty') return actual === null || actual === undefined || actual === '';
  if (op === 'is_not_empty') return !(actual === null || actual === undefined || actual === '');

  const a = coerceComparable(actual);
  const b = coerceComparable(condition.value);

  switch (op) {
    case 'eq':
      return a === b;
    case 'ne':
      return a !== b;
    case 'contains':
      return typeof a === 'string' && typeof b === 'string' && a.includes(b);
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const an = typeof a === 'number' ? a : Number(a);
      const bn = typeof b === 'number' ? b : Number(b);
      if (Number.isNaN(an) || Number.isNaN(bn)) return false;
      if (op === 'gt') return an > bn;
      if (op === 'gte') return an >= bn;
      if (op === 'lt') return an < bn;
      return an <= bn;
    }
    default:
      return false;
  }
}

/** First matching rule wins, top to bottom — same order the config declares
 * them in. Returns `null` (render with no color override) when nothing
 * matches or the matching rule's color fails [`isSafeHexColor`]. */
export function resolveConditionalColor(
  row: Record<string, unknown>,
  rules: ConditionalColorRule[] | undefined,
): string | null {
  if (!rules) return null;
  for (const rule of rules) {
    if (evaluateCondition(row, rule.when) && isSafeHexColor(rule.color)) {
      return rule.color;
    }
  }
  return null;
}
