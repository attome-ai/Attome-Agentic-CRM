import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { WhitespaceGridComponent, cellKey, pivot, type WhitespaceCell } from './whitespace-grid.component';

const cell = (id: string, product: string, department: string, status: string, value: number | null = null): WhitespaceCell => ({
  id, product_ref: product, department, status, estimated_value: value, row_version: 1,
});

describe('account plan whitespace (D27-T2)', () => {
  it('pivots products by departments and sums the open opportunity value', () => {
    const grid = pivot(
      [
        cell('1', 'p2', 'Finance', 'owned'),
        cell('2', 'p1', 'HR', 'opportunity', 1000),
        cell('3', 'p1', ' Finance ', 'opportunity', 500),
        cell('4', 'p2', 'HR', 'competitor'),
      ],
      new Map([['p1', 'Payroll'], ['p2', 'Analytics']]),
    );
    expect(grid.products.map(p => p.name)).toEqual(['Analytics', 'Payroll']);
    expect(grid.departments).toEqual(['Finance', 'HR']);
    expect(grid.cells.get(cellKey('p1', 'Finance'))?.status).toBe('opportunity');
    expect(grid.open_value).toBe(1500);
  });

  it('shows the grid and fills an empty cell by creating it', () => {
    const post = vi.fn((path: string, body: { entity?: string }) => of(path === '/api/v1/query/execute'
      ? { data: { records: body.entity === 'account_whitespace'
        ? [{ id: 'w1', product_ref: 'p1', department: 'HR', status: 'owned', row_version: 2 }]
        : [{ id: 'p1', name: 'Payroll' }] } }
      : {}));
    const patch = vi.fn(() => of({}));
    TestBed.configureTestingModule({
      imports: [WhitespaceGridComponent],
      providers: [
        { provide: ApiService, useValue: { post, patch } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('ar'), errorText: () => 'error', intlLocale: () => 'ar-SA' },
        },
      ],
    });
    const fixture = TestBed.createComponent(WhitespaceGridComponent);
    fixture.componentRef.setInput('recordId', 'plan-1');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-product="p1"] [data-status="owned"]')).not.toBeNull();
    const cmp = fixture.componentInstance;
    cmp.setStatus('p1', 'Finance', { target: { value: 'opportunity' } } as unknown as Event);
    expect(post).toHaveBeenCalledWith('/api/v1/account_whitespace', {
      account_plan_ref: 'plan-1', product_ref: 'p1', department: 'Finance', status: 'opportunity',
    });
    cmp.setStatus('p1', 'HR', { target: { value: 'competitor' } } as unknown as Event);
    expect(patch).toHaveBeenCalledWith('/api/v1/account_whitespace/w1', { status: 'competitor' }, 2);
  });
});
