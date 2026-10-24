import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { ScanService } from '@attome/base/scan';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ContinuousScanDialogComponent, SCAN_BATCH } from './continuous-scan-dialog.component';
import { EntityService } from '../services/entity.service';

describe('ContinuousScanDialogComponent (B16-T10)', () => {
  let bulkCreate: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-24T10:00:00Z'));
    bulkCreate = vi.fn(() => of({ id: 'bulk-1' }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [ContinuousScanDialogComponent],
      providers: [
        { provide: EntityService, useValue: { bulkCreate } },
        { provide: ScanService, useValue: { startCamera: vi.fn(() => of()), stop: vi.fn() } },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: () => 'failed' } },
      ],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render() {
    const fixture = TestBed.createComponent(ContinuousScanDialogComponent);
    fixture.componentRef.setInput('entityName', 'order_line');
    fixture.componentRef.setInput('valueField', 'sku');
    fixture.componentRef.setInput('links', [{ field: 'order_ref', value: 'o1' }]);
    fixture.detectChanges();
    return fixture;
  }

  it('debounces same value', () => {
    const c = render().componentInstance;
    c.onScan('6281000000017');
    vi.advanceTimersByTime(500);
    c.onScan('6281000000017');
    expect(c.accepted()).toBe(1);
    expect(c.duplicate()).toBeNull();
    // Past the window the same code is a deliberate second scan.
    vi.advanceTimersByTime(2000);
    c.onScan('6281000000017');
    expect(c.duplicate()).toBe('6281000000017');
  });

  it('warns on duplicate', () => {
    const fixture = render();
    const c = fixture.componentInstance;
    c.onScan('A');
    c.onScan('B');
    c.onScan('A');
    fixture.detectChanges();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="scan-duplicate"]')?.textContent).toContain('relatedGrid.scan.duplicate');
    expect(c.accepted()).toBe(2);
    (root.querySelector('[data-testid="scan-add-again"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(c.accepted()).toBe(3);
    expect(c.lines()).toEqual([{ value: 'A', count: 2 }, { value: 'B', count: 1 }]);
    expect(root.querySelector('[data-testid="scan-duplicate"]')).toBeNull();
  });

  it('flushes every 20', () => {
    const c = render().componentInstance;
    for (let i = 0; i < SCAN_BATCH + 3; i++) c.onScan(`code-${i}`);
    expect(bulkCreate).toHaveBeenCalledTimes(1);
    const [entity, records] = bulkCreate.mock.calls[0];
    expect(entity).toBe('order_line');
    expect(records.length).toBe(SCAN_BATCH);
    expect(records[0]).toEqual({ data: { sku: 'code-0', order_ref: 'o1' } });
    expect(c.written()).toBe(SCAN_BATCH);
    expect(c.pendingCount()).toBe(3);
    // Close writes the rest.
    const closed = vi.fn();
    c.closed.subscribe(closed);
    c.close();
    expect(bulkCreate).toHaveBeenCalledTimes(2);
    expect(bulkCreate.mock.calls[1][1].length).toBe(3);
    expect(closed).toHaveBeenCalledWith(SCAN_BATCH + 3);
  });
});
