import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ConfiguratorComponent, CpqProblem, listTotal } from './configurator.component';

const BUNDLE = 'b0';
const LAPTOPS = 'g1';
const EXTRAS = 'g2';

function record(id: string, data: Record<string, unknown>) {
  return { id, entity_id: '', created_at: '', updated_at: '', row_version: 1, data };
}

function mount(problems: CpqProblem[] = []) {
  const list = vi.fn((entity: string, params: { filters?: { value?: string }[] }) => {
    if (entity === 'product_option_group') {
      return of({
        data: [
          record(LAPTOPS, { name: 'Laptop', name_ar: 'الحاسوب', min_choices: 1, max_choices: 1 }),
          record(EXTRAS, { name: 'Extras', min_choices: 0, max_choices: 2 }),
        ],
        meta: { total: 2, limit: 50, offset: 0 },
      });
    }
    const group = params.filters?.[0]?.value;
    const options = group === LAPTOPS
      ? [record('o1', { product_ref: 'p14', is_default: true }), record('o2', { product_ref: 'p16' })]
      : [record('o3', { product_ref: 'dock' })];
    return of({ data: options, meta: { total: options.length, limit: 100, offset: 0 } });
  });
  const get = vi.fn(() => of({
    items: [
      { product_id: BUNDLE, name: 'Office kit', name_ar: null, list_price: '100' },
      { product_id: 'p14', name: 'Laptop 14', name_ar: null, list_price: '1000' },
      { product_id: 'p16', name: 'Laptop 16', name_ar: null, list_price: '1400' },
      { product_id: 'dock', name: 'Dock', name_ar: null, list_price: '250' },
    ],
  }));
  const post = vi.fn(() => of({ valid: problems.length === 0, problems }));
  TestBed.configureTestingModule({
    imports: [ConfiguratorComponent],
    providers: [
      { provide: ApiService, useValue: { get, post } },
      { provide: EntityService, useValue: { list } },
      {
        provide: LangService,
        useValue: {
          translate: (key: string, params?: Record<string, unknown>) =>
            params ? `${key}:${JSON.stringify(params)}` : key,
          current: signal('en'),
          intlLocale: signal('en'),
        },
      },
    ],
  });
  const fixture = TestBed.createComponent(ConfiguratorComponent);
  fixture.componentRef.setInput('bundleId', BUNDLE);
  fixture.componentRef.setInput('priceListId', 'pl');
  fixture.detectChanges();
  return { fixture, post };
}

describe('ConfiguratorComponent (F1-T3)', () => {
  it('asks each option group as a question with its defaults chosen', () => {
    const { fixture, post } = mount();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('[data-question]').length).toBe(2);
    expect((el.querySelector('[data-option="p14"]') as HTMLInputElement).checked).toBe(true);
    expect((el.querySelector('[data-option="p14"]') as HTMLInputElement).type).toBe('radio');
    expect(post).toHaveBeenCalledWith('/api/v1/sales/cpq/validate', { bundle_product_id: BUNDLE, chosen: ['p14'] });
  });

  it('updates the live price as choices change', () => {
    const { fixture } = mount();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-total]')?.textContent?.trim()).toContain('1,100');
    (el.querySelector('[data-option="dock"]') as HTMLInputElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[data-total]')?.textContent?.trim()).toContain('1,350');
  });

  it('explains each problem the server finds', () => {
    const { fixture } = mount([
      { code: 'missing_required', group_id: null, option_id: 'dock', other_option_id: 'p16', rule_id: null,
        min: null, max: null, chosen: null, message: null },
      { code: 'rule_failed', group_id: null, option_id: null, other_option_id: null, rule_id: 'r1',
        min: null, max: null, chosen: null, message: 'The dock fits only the 16-inch laptop.' },
    ]);
    const problems = [...(fixture.nativeElement as HTMLElement).querySelectorAll('[data-problem]')]
      .map(p => p.textContent?.trim());
    expect(problems[0]).toContain('configurator.problem.missing_required');
    expect(problems[0]).toContain('Laptop 16');
    expect(problems[1]).toBe('The dock fits only the 16-inch laptop.');
  });

  it('totals the bundle and the chosen options', () => {
    const options = [
      { productId: 'a', name: 'A', nameAr: null, listPrice: 10 },
      { productId: 'b', name: 'B', nameAr: null, listPrice: null },
    ];
    expect(listTotal(5, options, new Set(['a', 'b']))).toBe(15);
    expect(listTotal(null, options, new Set())).toBe(0);
  });
});
