import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, RulesEvaluatorService } from '@attome/base';
import type { RulesAnswer } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ExpressionEditorComponent } from './expression-editor.component';
import { errorKey, indexOfByte, rulesSchemaOf, wordAt } from './expression-text';

const SCHEMA = {
  id: 'e', name: 'Deal', plural_name: 'Deals', relationships: [],
  fields: [
    { id: '1', entity_id: 'e', name: 'amount', display_name: 'Amount', field_type: 'number', options: null, sort_order: 0, is_required: false },
    { id: '2', entity_id: 'e', name: 'title', display_name: 'Title', field_type: 'text', options: null, sort_order: 1, is_required: false },
  ],
};

/** The evaluator's answer for `amount + missing`: `missing` is unknown. */
const UNKNOWN_FIELD: RulesAnswer = {
  ok: false,
  diagnostics: [{ code: 'rules.field.unknown', message: 'unknown field missing', start: 9, end: 16 }],
};

const ARABIC: Record<string, string> = {
  [errorKey('rules.field.unknown')]: 'لا يوجد حقل بهذا الاسم في السجل.',
};

async function typed(text: string, lang: 'en' | 'ar') {
  const validate = vi.fn(async () => UNKNOWN_FIELD);
  TestBed.configureTestingModule({
    providers: [
      { provide: ApiService, useValue: {
        get: (url: string) => of(url.startsWith('/api/v1/schema/') ? SCHEMA : { functions: [] }),
        post: vi.fn(),
      } },
      { provide: RulesEvaluatorService, useValue: { validate } },
      { provide: LangService, useValue: {
        current: signal(lang),
        translate: (k: string) => (lang === 'ar' ? ARABIC[k] : undefined) ?? k,
      } },
    ],
  });
  const fixture = TestBed.createComponent(ExpressionEditorComponent);
  fixture.componentRef.setInput('entity', 'deal');
  fixture.detectChanges();
  const textarea = fixture.nativeElement.querySelector('textarea') as HTMLTextAreaElement;
  textarea.value = text;
  textarea.dispatchEvent(new Event('input'));
  await new Promise(resolve => setTimeout(resolve, 200));
  await fixture.whenStable();
  fixture.detectChanges();
  return { fixture, validate, root: fixture.nativeElement as HTMLElement };
}

describe('ExpressionEditorComponent', () => {
  it('shows error underline at span', async () => {
    const { root, validate } = await typed('amount + missing', 'en');
    expect(validate).toHaveBeenCalledWith('amount + missing', { fields: { amount: 'number', title: 'text' } }, 'v2');
    const mark = root.querySelector('[data-testid="expression-error-span"]');
    expect(mark?.textContent).toBe('missing');
    expect(root.querySelector('textarea')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('textarea')?.getAttribute('dir')).toBe('ltr');
  });

  it('renders Arabic error text when locale is ar', async () => {
    const { root } = await typed('amount + missing', 'ar');
    expect(root.querySelector('[data-testid="expression-error"]')?.textContent?.trim())
      .toBe('لا يوجد حقل بهذا الاسم في السجل.');
  });

  it('falls back to the evaluator message when the catalog has no text', async () => {
    const { root } = await typed('amount + missing', 'en');
    expect(root.querySelector('[data-testid="expression-error"]')?.textContent?.trim())
      .toBe('unknown field missing');
  });
});

describe('expression text helpers', () => {
  it('maps a UTF-8 byte offset to a string index past Arabic text', () => {
    // 'عر' is four bytes and two characters.
    expect(indexOfByte("'عر' + x", 7)).toBe(5);
    expect(indexOfByte('amount', 3)).toBe(3);
  });

  it('finds the identifier being typed', () => {
    expect(wordAt('amount + mis', 12)).toEqual({ start: 9, word: 'mis' });
  });

  it('declares a formula field as its result type and skips files', () => {
    const schema = rulesSchemaOf({
      ...SCHEMA,
      fields: [
        { ...SCHEMA.fields[0], name: 'score', field_type: 'formula', options: { expression: 'x', result_type: 'number' } },
        { ...SCHEMA.fields[1], name: 'photo', field_type: 'image' },
      ],
    } as never);
    expect(schema).toEqual({ fields: { score: 'number' } });
  });
});
