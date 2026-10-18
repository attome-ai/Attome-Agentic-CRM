import type { ApiComponents } from '@attome/base';

type Schemas = ApiComponents['schemas'];

/** `attome_records::customer_tests::CustomerTest`. */
export type CustomerTest = Schemas['CustomerTest'];
/** `attome_api::customer_test_admin::CustomerTestRunResult`. */
export type CustomerTestRunResult = Schemas['CustomerTestRunResult'];
/** `attome_api::customer_test_admin::CustomerTestRunAll`. */
export type CustomerTestRunAll = Schemas['CustomerTestRunAll'];

export type StepOp = 'create' | 'update' | 'delete';
export const STEP_OPS: readonly StepOp[] = ['create', 'update', 'delete'];

export type ErrorKind = 'validation' | 'forbidden' | 'conflict' | 'not_found' | 'other';
export const ERROR_KINDS: readonly ErrorKind[] = ['validation', 'forbidden', 'conflict', 'not_found', 'other'];

/** One attribute value a row sets; `value` is typed text (JSON, or a plain string). */
export interface ValueRow {
  attribute: string;
  value: string;
}

/** A record the test starts from. */
export interface GivenRow {
  entity: string;
  ref: string;
  values: ValueRow[];
}

/** One write under test. */
export interface WhenRow {
  op: StepOp;
  entity: string;
  ref: string;
  values: ValueRow[];
}

/** What must hold afterwards: an attribute's value, or an error a step met. */
export interface ExpectRow {
  kind: 'value' | 'error';
  entity: string;
  ref: string;
  attribute: string;
  equals: string;
  error: ErrorKind;
}

/** The editor's form of a test. */
export interface TestDraft {
  name: string;
  description: string;
  blocking: boolean;
  asRole: string;
  given: GivenRow[];
  when: WhenRow[];
  expect: ExpectRow[];
}

/** Typed text as a value: JSON when it reads as JSON (`12`, `true`, `null`), else the text. */
export function parseValue(text: string): unknown {
  const trimmed = text.trim();
  if (trimmed === '') return '';
  try {
    return JSON.parse(trimmed);
  } catch {
    return text;
  }
}

/** A value as editable text: a string as is, anything else as JSON. */
export function showValue(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function toRecord(rows: ValueRow[]): Record<string, unknown> {
  const record: Record<string, unknown> = {};
  for (const row of rows) {
    if (row.attribute) record[row.attribute] = parseValue(row.value);
  }
  return record;
}

function fromRecord(record: unknown): ValueRow[] {
  if (!record || typeof record !== 'object') return [];
  return Object.entries(record as Record<string, unknown>).map(([attribute, value]) => ({
    attribute,
    value: showValue(value),
  }));
}

/** The definition the API stores (`attome_records::customer_tests::TestDefinition`). */
export function toDefinition(draft: TestDraft): Record<string, unknown> {
  const definition: Record<string, unknown> = {
    given: draft.given.map(g => ({ entity: g.entity, ...(g.ref ? { ref: g.ref } : {}), record: toRecord(g.values) })),
    when: draft.when.map(w => ({ op: w.op, entity: w.entity, ...(w.ref ? { ref: w.ref } : {}), values: toRecord(w.values) })),
    expect: draft.expect.map(e =>
      e.kind === 'error'
        ? { error: e.error }
        : { entity: e.entity, ref: e.ref, attribute: e.attribute, equals: parseValue(e.equals) },
    ),
  };
  if (draft.asRole.trim()) definition['as_role'] = draft.asRole.trim();
  return definition;
}

/** A stored test (or none, for a new one) as a draft. */
export function fromTest(test: CustomerTest | null): TestDraft {
  const definition = (test?.definition ?? {}) as Record<string, unknown>;
  const list = (key: string): Record<string, unknown>[] =>
    Array.isArray(definition[key]) ? (definition[key] as Record<string, unknown>[]) : [];
  const text = (v: unknown): string => (typeof v === 'string' ? v : '');
  return {
    name: test?.name ?? '',
    description: test?.description ?? '',
    blocking: test?.blocking ?? false,
    asRole: text(definition['as_role']),
    given: list('given').map(g => ({ entity: text(g['entity']), ref: text(g['ref']), values: fromRecord(g['record']) })),
    when: list('when').map(w => ({
      op: (STEP_OPS as readonly string[]).includes(text(w['op'])) ? (w['op'] as StepOp) : 'create',
      entity: text(w['entity']),
      ref: text(w['ref']),
      values: fromRecord(w['values']),
    })),
    expect: list('expect').map(e =>
      'error' in e
        ? { kind: 'error' as const, entity: '', ref: '', attribute: '', equals: '', error: e['error'] as ErrorKind }
        : {
            kind: 'value' as const,
            entity: text(e['entity']),
            ref: text(e['ref']),
            attribute: text(e['attribute']),
            equals: showValue(e['equals']),
            error: 'validation' as const,
          },
    ),
  };
}
