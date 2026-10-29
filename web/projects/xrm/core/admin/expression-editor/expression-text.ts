import type { EntitySchema } from '@attome/xrm';
import type { RulesSchema } from '@attome/base';

/**
 * The string index of a UTF-8 byte offset into `text`. The evaluator reports
 * spans in bytes; an Arabic literal before the error takes two bytes a letter.
 */
export function indexOfByte(text: string, byte: number): number {
  let bytes = 0;
  let index = 0;
  for (const ch of text) {
    if (bytes >= byte) break;
    const cp = ch.codePointAt(0) ?? 0;
    bytes += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    index += ch.length;
  }
  return index;
}

/** The identifier being typed at `caret`: where it starts and what it is so far. */
export function wordAt(text: string, caret: number): { start: number; word: string } {
  let start = caret;
  while (start > 0 && /[A-Za-z0-9_]/.test(text[start - 1])) start--;
  return { start, word: text.slice(start, caret) };
}

/** `text` with `word` (starting at `start`, up to `caret`) replaced by `insert`. */
export function replaceWord(
  text: string,
  start: number,
  caret: number,
  insert: string,
): { text: string; caret: number } {
  return { text: text.slice(0, start) + insert + text.slice(caret), caret: start + insert.length };
}

const RULES_TYPE: Partial<Record<string, string>> = {
  number: 'number',
  currency: 'number',
  date: 'date',
  date_time: 'date',
  bool: 'bool',
  choice: 'choice',
  lookup: 'lookup',
  text: 'text',
  icon: 'text',
  color: 'text',
  rich_text: 'text',
};

/**
 * The language types of an entity's fields, as the server declares them for
 * an expression: a formula field as its result type; a file or image field
 * not at all.
 */
export function rulesSchemaOf(schema: EntitySchema): RulesSchema {
  const fields: Record<string, string> = {};
  for (const f of schema.fields ?? []) {
    const ty = f.field_type === 'formula'
      ? (f.options as { result_type?: string } | null)?.result_type
      : RULES_TYPE[f.field_type];
    if (ty) fields[f.name] = ty;
  }
  return { fields };
}

/**
 * A9-T4: the identifier being typed at `caret` and the lookups before it:
 * in `parent_ref.owner_ref.na|`, `segments` is `['parent_ref', 'owner_ref']`
 * and `word` is `na`.
 */
export function pathAt(text: string, caret: number): { start: number; segments: string[]; word: string } {
  const { start, word } = wordAt(text, caret);
  let from = start;
  while (from > 0 && /[A-Za-z0-9_.]/.test(text[from - 1])) from--;
  const before = text.slice(from, start);
  const segments = before.endsWith('.') ? before.slice(0, -1).split('.') : [];
  return { start, segments: segments.every(s => /^[A-Za-z_][A-Za-z0-9_]*$/.test(s)) ? segments : [], word };
}

/**
 * A9-T4: the dotted field chains an expression reads (`parent_ref.title`),
 * outside string literals and not followed by `(` (a method call). Pure.
 */
export function dottedPaths(text: string): string[][] {
  const code = text.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, m => ' '.repeat(m.length));
  const out = new Map<string, string[]>();
  for (const m of code.matchAll(/(?<![A-Za-z0-9_.])[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+(?![A-Za-z0-9_]|\s*\()/g)) {
    out.set(m[0], m[0].split('.'));
  }
  return [...out.values()];
}

/** A9-T4: the entity a lookup field of `schema` points at, or `null`. */
export function lookupTarget(schema: EntitySchema, field: string): string | null {
  const f = schema.fields?.find(x => x.name === field);
  if (!f || f.field_type !== 'lookup') return null;
  return (f.options as { target_entity_name?: string | null } | null)?.target_entity_name ?? null;
}

/**
 * A9-T4: `base` with the resolved paths declared as the server declares them
 * for a formula: one lookup as that lookup's related fields, more as paths.
 */
export function withPaths(base: RulesSchema, paths: { segments: string[]; type: string }[]): RulesSchema {
  const related: Record<string, Record<string, string>> = { ...(base.related ?? {}) };
  const declared: Record<string, string> = { ...(base.paths ?? {}) };
  for (const { segments, type } of paths) {
    if (segments.length === 2) {
      related[segments[0]] = { ...(related[segments[0]] ?? {}), [segments[1]]: type };
    } else {
      declared[segments.join('.')] = type;
    }
  }
  return {
    ...base,
    ...(Object.keys(related).length ? { related } : {}),
    ...(Object.keys(declared).length ? { paths: declared } : {}),
  };
}

/** The catalog key for an evaluator error code (`rules.field.unknown`). */
export function errorKey(code: string): string {
  return `expressions.errors.${code.replace(/\./g, '_')}`;
}
