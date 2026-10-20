import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ForecastGridComponent, ForecastRow, commitTotal } from './forecast-grid.component';

function record(id: string, data: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return { id, entity_id: '', created_at: '', updated_at: '', row_version: 3, data, ...extra };
}

function mount() {
  const list = vi.fn((entity: string) => {
    const page = (data: unknown[]) => of({ data, meta: { total: data.length, limit: 100, offset: 0 } });
    switch (entity) {
      case 'forecast_period':
        return page([record('q1', { name: 'Q1 2027', status: 'open' })]);
      case 'forecast_category':
        return page([
          record('commit', { name: 'Commit', counts_in_commit: true }),
          record('best', { name: 'Best case', counts_in_commit: false }),
        ]);
      default:
        return page([
          record('c1', { node_key: 'user:sara', category_ref: 'commit', pipeline_amount: 900, adjusted_amount: 800, quota: 1000 },
            { lookups: { owner_ref: { exists: true, is_active: true, name: 'Sara' } } }),
          record('c2', { node_key: 'user:sara', category_ref: 'best', pipeline_amount: 500, adjusted_amount: 500, quota: 1000 },
            { lookups: { owner_ref: { exists: true, is_active: true, name: 'Sara' } } }),
        ]);
    }
  });
  const create = vi.fn(() => of({}));
  const update = vi.fn(() => of({}));
  TestBed.configureTestingModule({
    imports: [ForecastGridComponent],
    providers: [
      { provide: EntityService, useValue: { list, create, update } },
      {
        provide: LangService,
        useValue: { translate: (key: string) => key, current: signal('en'), intlLocale: signal('en') },
      },
    ],
  });
  const fixture = TestBed.createComponent(ForecastGridComponent);
  fixture.detectChanges();
  return { fixture, create, update };
}

describe('ForecastGridComponent (D11-T3)', () => {
  it('shows a row per person with a cell per category and the commit against quota', () => {
    const { fixture } = mount();
    const el = fixture.nativeElement as HTMLElement;
    const row = el.querySelector('[data-node="user:sara"]');
    expect(row?.textContent).toContain('Sara');
    expect(row?.querySelectorAll('[data-cell]').length).toBe(2);
    expect(row?.querySelector('[data-commit]')?.textContent?.trim()).toBe('800');
    expect(row?.querySelector('[data-attainment]')?.textContent?.trim()).toBe('80%');
  });

  it('keeps an adjustment and moves the cell at its version', () => {
    const { fixture, create, update } = mount();
    const el = fixture.nativeElement as HTMLElement;
    (el.querySelector('[data-cell="c1"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const amount = el.querySelector('form input[type=number]') as HTMLInputElement;
    const reason = el.querySelector('form input[type=text]') as HTMLInputElement;
    amount.value = '950';
    reason.value = 'Signed PO expected';
    (el.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'));
    fixture.detectChanges();
    expect(create).toHaveBeenCalledWith('forecast_adjustment', expect.objectContaining({
      cell_ref: 'c1', amount: 950, previous_amount: 800, reason: 'Signed PO expected',
    }));
    expect(update).toHaveBeenCalledWith('forecast_cell', 'c1', { adjusted_amount: 950 }, 3);
    expect(el.querySelector('[data-node="user:sara"] [data-commit]')?.textContent?.trim()).toBe('950');
  });

  it('commits only the categories that count', () => {
    const row: ForecastRow = {
      nodeKey: 'n', label: 'n', quota: null,
      cells: {
        a: { id: '1', rowVersion: 1, nodeKey: 'n', owner: null, categoryId: 'a', pipeline: 0, adjusted: 10, quota: null },
        b: { id: '2', rowVersion: 1, nodeKey: 'n', owner: null, categoryId: 'b', pipeline: 0, adjusted: 5, quota: null },
      },
    };
    expect(commitTotal(row, new Set(['a']))).toBe(10);
  });
});
