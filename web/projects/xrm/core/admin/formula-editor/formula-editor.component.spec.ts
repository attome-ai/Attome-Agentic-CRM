import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, RulesEvaluatorService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { dottedPaths, pathAt, withPaths } from '@attome/xrm/core/admin/expression-editor';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { FormulaEditorComponent, formulaOptions } from './formula-editor.component';

const field = (name: string, field_type: string, options: unknown = null) =>
  ({ id: name, entity_id: 'e', name, display_name: name, field_type, options, sort_order: 0, is_required: false });

/** `order` looks up `account`, which looks up `region`. */
const SCHEMAS: Record<string, unknown> = {
  order: { id: 'o', name: 'order', plural_name: 'orders', relationships: [], fields: [
    field('amount', 'number'),
    field('account_ref', 'lookup', { target_entity_id: 'a', target_entity_name: 'account', display_field: null }),
  ] },
  account: { id: 'a', name: 'account', plural_name: 'accounts', relationships: [], fields: [
    field('name', 'text'),
    field('region_ref', 'lookup', { target_entity_id: 'r', target_entity_name: 'region', display_field: null }),
  ] },
  region: { id: 'r', name: 'region', plural_name: 'regions', relationships: [], fields: [field('code', 'text')] },
};

const tick = () => new Promise(resolve => setTimeout(resolve, 200));

function setup(options: unknown, update = vi.fn(() => of({}))) {
  const validate = vi.fn(async () => ({ ok: true, result_type: 'text', diagnostics: [] }));
  const post = vi.fn(() => of({ ok: true, result_type: 'text', diagnostics: [], sql_translatable: false,
    sql_reason: 'reads through a lookup', value: 'EMEA', trace: [{ expr: 'account_ref.region_ref.code', value: 'EMEA' }] }));
  const get = vi.fn((url: string) => {
    const name = url.startsWith('/api/v1/schema/') ? decodeURIComponent(url.slice('/api/v1/schema/'.length)) : null;
    return name ? of(SCHEMAS[name]) : of({ functions: [] });
  });
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    imports: [FormulaEditorComponent],
    providers: [
      { provide: ApiService, useValue: { get, post } },
      { provide: RulesEvaluatorService, useValue: { validate } },
      { provide: AdminService, useValue: { updateAttribute: update } },
      { provide: LangService, useValue: {
        current: signal('en'),
        translate: (k: string, p?: Record<string, unknown>) => (p ? `${k}:${JSON.stringify(p)}` : k),
        errorText: (e: { message?: string }) => e.message ?? 'failed',
      } },
    ],
  });
  const fixture = TestBed.createComponent(FormulaEditorComponent);
  fixture.componentRef.setInput('entityId', 'o');
  fixture.componentRef.setInput('entity', 'order');
  fixture.componentRef.setInput('fieldId', 'f1');
  fixture.componentRef.setInput('fieldName', 'region_code');
  fixture.componentRef.setInput('options', options);
  fixture.detectChanges();
  return { fixture, validate, post, get, update, root: fixture.nativeElement as HTMLElement };
}

async function type(fixture: ReturnType<typeof setup>['fixture'], text: string) {
  const textarea = fixture.nativeElement.querySelector('textarea') as HTMLTextAreaElement;
  textarea.value = text;
  textarea.setSelectionRange(text.length, text.length);
  textarea.dispatchEvent(new Event('input'));
  await tick();
  await fixture.whenStable();
  fixture.detectChanges();
  return textarea;
}

describe('formula path helpers (A9-T4)', () => {
  it('finds the lookups before the word being typed', () => {
    expect(pathAt('amount + account_ref.region_ref.co', 34)).toEqual({ start: 32, segments: ['account_ref', 'region_ref'], word: 'co' });
    expect(pathAt('amount + am', 11)).toEqual({ start: 9, segments: [], word: 'am' });
  });

  it('lists the dotted paths outside strings and method calls', () => {
    expect(dottedPaths('account_ref.name + "a.b" + account_ref.region_ref.code + x.y(1)'))
      .toEqual([['account_ref', 'name'], ['account_ref', 'region_ref', 'code']]);
  });

  it('declares one lookup as related fields and more as paths', () => {
    expect(withPaths({ fields: { amount: 'number' } }, [
      { segments: ['account_ref', 'name'], type: 'text' },
      { segments: ['account_ref', 'region_ref', 'code'], type: 'text' },
    ])).toEqual({
      fields: { amount: 'number' },
      related: { account_ref: { name: 'text' } },
      paths: { 'account_ref.region_ref.code': 'text' },
    });
  });

  it('keeps the result type and replaces the expression and mode', () => {
    expect(formulaOptions({ expression: 'x', result_type: 'text' }, 'y', 'read_time'))
      .toEqual({ expression: 'y', result_type: 'text', mode: 'read_time' });
  });
});

describe('FormulaEditorComponent (A9-T4)', () => {
  it('completes fields through lookups when computed when read', async () => {
    const { fixture, root } = setup({ expression: '', result_type: 'text', mode: 'read_time' });
    await type(fixture, 'account_ref.region_ref.co');
    const options = [...root.querySelectorAll('[role="option"] code')].map(o => o.textContent);
    expect(options).toEqual(['code']);
  });

  it('offers no path completion for a stored formula', async () => {
    const { fixture, root } = setup({ expression: '', result_type: 'text', mode: 'stored' });
    await type(fixture, 'account_ref.region_ref.co');
    expect(root.querySelectorAll('[role="option"]').length).toBe(0);
  });

  it('checks a path in the browser with it declared', async () => {
    const { fixture, validate } = setup({ expression: '', result_type: 'text', mode: 'read_time' });
    await type(fixture, 'account_ref.region_ref.code');
    expect(validate).toHaveBeenLastCalledWith(
      'account_ref.region_ref.code',
      { fields: { amount: 'number', account_ref: 'lookup' }, paths: { 'account_ref.region_ref.code': 'text' } },
      'v2',
    );
  });

  it('previews on a sample record through the validate route', async () => {
    const { fixture, post, root } = setup({ expression: 'account_ref.region_ref.code', result_type: 'text', mode: 'read_time' });
    await tick();
    fixture.detectChanges();
    const sample = root.querySelector('.xee-sample input') as HTMLInputElement;
    sample.value = 'rec-1';
    sample.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    (root.querySelector('.xee-preview button') as HTMLButtonElement).click();
    await tick();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/admin/expressions/validate', {
      expression: 'account_ref.region_ref.code', entity: 'order', language_version: 'v2', sample_record_id: 'rec-1',
    });
    expect(root.textContent).toContain('"EMEA"');
  });

  it('saves the expression and mode, keeping the result type', async () => {
    const { fixture, update, root } = setup({ expression: 'amount', result_type: 'text', mode: 'stored' });
    const saved = vi.fn();
    fixture.componentInstance.saved.subscribe(saved);
    (root.querySelector('[data-testid="formula-mode-read-time"]') as HTMLInputElement).dispatchEvent(new Event('change'));
    await type(fixture, 'account_ref.name');
    (root.querySelector('[data-testid="formula-save"]') as HTMLButtonElement).click();
    expect(update).toHaveBeenCalledWith('o', 'f1', {
      options: { expression: 'account_ref.name', result_type: 'text', mode: 'read_time' },
    });
    expect(saved).toHaveBeenCalledWith({ fieldId: 'f1', options: { expression: 'account_ref.name', result_type: 'text', mode: 'read_time' } });
  });

  it('shows the server refusal', async () => {
    const update = vi.fn(() => throwError(() => ({ message: 'formula expression does not compile' })));
    const { fixture, root } = setup({ expression: 'amount', result_type: 'text', mode: 'stored' }, update);
    await type(fixture, 'amount + 1');
    (root.querySelector('[data-testid="formula-save"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="formula-error"]')?.textContent).toContain('does not compile');
  });
});
