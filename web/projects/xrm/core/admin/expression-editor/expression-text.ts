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

/** The catalog key for an evaluator error code (`rules.field.unknown`). */
export function errorKey(code: string): string {
  return `expressions.errors.${code.replace(/\./g, '_')}`;
}
