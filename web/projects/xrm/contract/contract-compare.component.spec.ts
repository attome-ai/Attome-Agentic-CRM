import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ContractCompareComponent, parseComparison } from './contract-compare.component';

const diff = [
  {
    section: '1. Payment', status: 'changed', changes: [
      { op: 'equal', text: 'Pay within' }, { op: 'delete', text: '30' }, { op: 'insert', text: '60' }, { op: 'equal', text: 'days.' },
    ],
  },
  { section: 'المادة 2', status: 'added', text: 'يلتزم الطرفان بالسرية.' },
  { section: '3. Old clause', status: 'removed', text: 'Gone now.' },
];
const deviations = [{ section: '1. Payment', clause_id: 'c1', clause_key: 'payment_terms', similarity: 0.42 }];

describe('parseComparison (W1-T15)', () => {
  it('splits a word diff into its two sides', () => {
    const [changed, added, removed] = parseComparison(JSON.stringify(diff), JSON.stringify(deviations));
    expect(changed.before.map(w => w.text)).toEqual(['Pay within', '30', 'days.']);
    expect(changed.after.map(w => w.text)).toEqual(['Pay within', '60', 'days.']);
    expect(changed.deviation?.clause_key).toBe('payment_terms');
    expect(added.before).toEqual([]);
    expect(removed.after).toEqual([]);
    expect(parseComparison('not json', null)).toEqual([]);
  });
});

describe('ContractCompareComponent (W1-T15)', () => {
  const current = signal('en');
  let get: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    current.set('en');
    get = vi.fn(() => of({ id: 'cmp', data: { status: 'done', diff_json: JSON.stringify(diff), deviations_json: JSON.stringify(deviations) } }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [ContractCompareComponent],
      providers: [
        { provide: EntityService, useValue: { get } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current, errorText: () => 'failed', isRtl: () => current() === 'ar' },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(ContractCompareComponent);
    fixture.componentRef.setInput('id', 'cmp');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture.nativeElement as HTMLElement;
  }

  it('renders removed and added words', () => {
    const root = render();
    expect(get).toHaveBeenCalledWith('contract_comparison', 'cmp');
    const removed = [...root.querySelectorAll('[data-testid="cc-removed"]')].map(e => e.textContent);
    const added = [...root.querySelectorAll('[data-testid="cc-added"]')].map(e => e.textContent);
    expect(removed).toEqual(['30', 'Gone now.']);
    expect(added).toEqual(['60', 'يلتزم الطرفان بالسرية.']);
    expect(root.querySelectorAll('[data-testid="cc-section"]').length).toBe(3);
  });

  it('mirrors in Arabic', () => {
    current.set('ar');
    const root = render();
    expect(root.querySelector('[data-testid="cc"]')?.getAttribute('dir')).toBe('rtl');
    // Each side is its own bidi island.
    expect(root.querySelector('.cc-text')?.getAttribute('dir')).toBe('auto');
  });

  it('shows deviation badge', () => {
    const root = render();
    const badges = root.querySelectorAll('[data-testid="cc-deviation"]');
    expect(badges.length).toBe(1);
    expect(badges[0].textContent).toContain('42%');
    expect(root.querySelector('[data-testid="cc-deviation-count"]')).not.toBeNull();
  });

  it('says when the comparison is still running', () => {
    get.mockReturnValue(of({ id: 'cmp', data: { status: 'queued' } }));
    const root = render();
    expect(root.querySelector('[data-testid="cc-pending"]')).not.toBeNull();
  });
});
