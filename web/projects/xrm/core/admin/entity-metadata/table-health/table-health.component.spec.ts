import { TestBed } from '@angular/core/testing';
import { LangService, SdkService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { TableHealthComponent, canKey, canPartition, copiedPercent } from './table-health.component';

const HEALTH = {
  entity: 'deal', total_bytes: 2 * 1024 * 1024, live_rows: 1200, dead_rows: 30, dead_ratio: 0.024,
  last_autovacuum: null, unused_indexes: [], lookups_without_index: ['account_ref'], growth_rows_7d: 40,
};

describe('TableHealthComponent (Y2-T15)', () => {
  let sdk: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn>; patch: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    sdk = {
      get: vi.fn((path: string) => {
        if (path.endsWith('/health')) return of(HEALTH);
        if (path.endsWith('/orphans')) {
          return of({ items: [{ attribute: 'account_ref', target_entity: 'account', orphans: 3, scanned_at: '2026-11-03T10:00:00Z', run_id: null }], total: 1, page: 1, page_size: 100 });
        }
        if (path.endsWith('/index-proposals')) {
          return of({ available: true, reason: null, proposals: [{ attribute: 'stage', field_id: 'f-stage', statements: 2, calls: 120, worst_mean_ms: 340 }] });
        }
        if (path.endsWith('/foreign-key')) return of({ state: 'none', keyed: true, target_entity: 'account', queued: false });
        if (path.endsWith('/partition')) return of({ entity: 'deal', storage_mode: 'standard', old_table_kept: false, run: null });
        return of(null);
      }),
      post: vi.fn(() => of({})),
      patch: vi.fn(() => of({})),
    };
    TestBed.configureTestingModule({
      imports: [TableHealthComponent],
      providers: [
        { provide: SdkService, useValue: sdk },
        { provide: LangService, useValue: { translate: (k: string) => k, isRtl: () => false, errorText: () => 'error' } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(TableHealthComponent);
    fixture.componentRef.setInput('entityId', 'e1');
    fixture.componentRef.setInput('lookups', [{ id: 'f-account', logicalname: 'account_ref' }]);
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('shows orphan count', () => {
    const { el } = render();
    expect(sdk.get).toHaveBeenCalledWith('/api/v1/admin/entities/e1/orphans', { query: { page: 1, page_size: 100 } });
    expect(el.querySelector('[data-orphan-count]')?.textContent?.trim()).toBe('3');
    expect(el.querySelector('[data-orphans]')?.textContent).toContain('account_ref');
  });

  it('apply index calls POST', () => {
    const { el } = render();
    el.querySelector<HTMLButtonElement>('[data-apply-index]')?.click();
    // An index proposal is applied by making its field filterable.
    expect(sdk.patch).toHaveBeenCalledWith('/api/v1/admin/entities/e1/fields/f-stage', { body: { is_filterable: true } });
    el.querySelector<HTMLButtonElement>('[data-add-key]')?.click();
    expect(sdk.post).toHaveBeenCalledWith('/api/v1/admin/entities/e1/fields/f-account/foreign-key', { body: {} });
    el.querySelector<HTMLButtonElement>('[data-start-partition]')?.click();
    expect(sdk.post).toHaveBeenCalledWith('/api/v1/admin/entities/e1/partition', { body: {} });
  });

  it('offers a key, a partitioning and progress only when they apply', () => {
    expect(canKey(null)).toBe(false);
    expect(canKey({ state: 'valid', keyed: true, target_entity: 'a', queued: false })).toBe(false);
    expect(canKey({ state: 'none', keyed: false, target_entity: 'a', queued: false })).toBe(false);
    expect(canKey({ state: 'not_valid', keyed: true, target_entity: 'a', queued: false })).toBe(true);
    const running = { entity: 'deal', storage_mode: 'standard', old_table_kept: false, run: { id: 'r', status: 'running', rows_estimate: 200, rows_scanned: 50, rows_written: 50 } };
    expect(canPartition(running)).toBe(false);
    expect(copiedPercent(running)).toBe(25);
    expect(canPartition({ ...running, storage_mode: 'high_volume', run: null })).toBe(false);
  });
});
