import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { QueryService } from '@attome/xrm/core/query/data';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { RollupEditorComponent, backfillRuns, exactAllowed, fits, resultType } from './rollup-editor.component';

const field = (name: string, field_type: string, options: unknown = null) =>
  ({ id: name, entity_id: 'i', name, display_name: name, field_type, options, sort_order: 0, is_required: false });

const INVOICE = { id: 'i', name: 'invoice', plural_name: 'invoices', relationships: [], fields: [
  field('amount', 'currency'),
  field('note', 'text'),
  field('issued_on', 'date'),
  field('account_ref', 'lookup', { target_entity_id: 'a', target_entity_name: 'account', display_field: null }),
  field('owner_user', 'lookup', { target_entity_id: 'u', target_entity_name: 'user_account', display_field: null }),
] };

describe('rollup editor helpers (A10-T6)', () => {
  it('matches the server on what a function aggregates and gives', () => {
    expect(fits('sum', 'currency')).toBe(true);
    expect(fits('sum', 'text')).toBe(false);
    expect(fits('max', 'date')).toBe(true);
    expect(fits('distinct_count', 'text')).toBe(true);
    expect(resultType('count', null)).toBe('number');
    expect(resultType('sum', 'currency')).toBe('currency');
    expect(resultType('max', 'date')).toBe('date');
  });

  it('allows exact mode only for a count or sum with no filter or window', () => {
    expect(exactAllowed('sum', '', null)).toBe(true);
    expect(exactAllowed('sum', 'amount > 0', null)).toBe(false);
    expect(exactAllowed('count', '', 30)).toBe(false);
    expect(exactAllowed('max', '', null)).toBe(false);
  });

  it('estimates the backfill runs', () => {
    expect(backfillRuns(0)).toBe(1);
    expect(backfillRuns(2500)).toBe(3);
  });
});

describe('RollupEditorComponent (A10-T6)', () => {
  let createAttribute: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    createAttribute = vi.fn(() => of({ id: 'f1' }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [RollupEditorComponent],
      providers: [
        { provide: AdminService, useValue: {
          listEntities: () => of([{ id: 'i', logicalname: 'invoice', name: 'Invoice' }]),
          createAttribute,
        } },
        { provide: ApiService, useValue: { get: vi.fn(() => of(INVOICE)) } },
        { provide: QueryService, useValue: { execute: vi.fn(() => of({ data: { total: 2500, records: [] } })) } },
        { provide: LangService, useValue: {
          translate: (k: string, p?: Record<string, unknown>) => (p ? `${k}:${JSON.stringify(p)}` : k),
          errorText: (e: { message?: string }) => e.message ?? 'failed',
        } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(RollupEditorComponent);
    fixture.componentRef.setInput('entityId', 'a');
    fixture.componentRef.setInput('entity', 'account');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  function choose(root: HTMLElement, testid: string, value: string) {
    const el = root.querySelector(`[data-testid="${testid}"]`) as HTMLSelectElement | HTMLInputElement;
    el.value = value;
    el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? 'change' : 'input'));
  }

  it('previews the parents to fill and offers only lookups back to the entity', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="rollup-impact"]')?.textContent).toContain('"parents":2500');
    expect(root.querySelector('[data-testid="rollup-impact"]')?.textContent).toContain('"runs":3');
    choose(root, 'rollup-child', 'invoice');
    fixture.detectChanges();
    const vias = [...root.querySelectorAll('[data-testid="rollup-via"] option')].map(o => o.textContent?.trim());
    expect(vias).toEqual(['account_ref']);
    const fieldsOffered = [...root.querySelectorAll('[data-testid="rollup-field"] option')].map(o => (o as HTMLOptionElement).value);
    expect(fieldsOffered).toEqual(['', 'amount']);
  });

  it('saves a sum with its result type, and keeps exact mode off when a filter is set', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    const saved = vi.fn();
    fixture.componentInstance.saved.subscribe(saved);
    choose(root, 'rollup-name', 'invoiced_total');
    choose(root, 'rollup-child', 'invoice');
    fixture.detectChanges();
    choose(root, 'rollup-field', 'amount');
    choose(root, 'rollup-filter', 'amount > 0');
    fixture.detectChanges();
    expect((root.querySelector('[data-testid="rollup-mode"] option[value="exact"]') as HTMLOptionElement).disabled).toBe(true);
    (root.querySelector('[data-testid="rollup-save"]') as HTMLButtonElement).click();
    expect(createAttribute).toHaveBeenCalledWith('a', {
      logicalname: 'invoiced_total', name: 'invoiced_total', field_type: 'rollup',
      options: {
        function: 'sum', path: [{ entity: 'invoice', via: 'account_ref' }], mode: 'fast',
        result_type: 'currency', attribute: 'amount', filter: 'amount > 0',
      },
    });
    expect(saved).toHaveBeenCalledWith('invoiced_total');
  });

  it('shows the server refusal', () => {
    createAttribute.mockReturnValue(throwError(() => ({ message: 'this rollup gives a number value' })));
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    choose(root, 'rollup-name', 'n');
    choose(root, 'rollup-function', 'count');
    choose(root, 'rollup-child', 'invoice');
    fixture.detectChanges();
    (root.querySelector('[data-testid="rollup-save"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="rollup-error"]')?.textContent).toContain('gives a number');
  });
});
