import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  OperationSummary, OperationsComponent, controlsFor, progressPercent,
} from './operations.component';

function op(id: string, status: string, extra: Partial<OperationSummary> = {}): OperationSummary {
  return {
    id, kind: 'mass', action: 'delete', entity: 'account', status,
    rows_done: 250, estimated_rows: 1000, started_by: 'u-1', reason: 'clean-up',
    created_at: '2026-10-28T10:00:00Z', finished_at: null, row_version: 3, seconds_left: 750,
    ...extra,
  };
}

describe('OperationsComponent (AA10-T8)', () => {
  afterEach(() => vi.useRealTimers());

  function create(items: OperationSummary[]) {
    const get = vi.fn((_url: string, _params?: Record<string, string>) => of({ items, next_cursor: null }));
    const post = vi.fn((_url: string, _body: unknown, _opts?: unknown) => of({}));
    TestBed.configureTestingModule({
      imports: [OperationsComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(OperationsComponent);
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('undo button only on done operations', () => {
    const { fixture } = create([
      op('a', 'running'), op('b', 'paused'), op('c', 'done', { seconds_left: null }), op('d', 'queued'),
    ]);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-op="c"] [data-control="undo"]')).not.toBeNull();
    for (const id of ['a', 'b', 'd']) {
      expect(el.querySelector(`[data-op="${id}"] [data-control="undo"]`)).toBeNull();
    }
    expect(el.querySelector('[data-op="a"] [data-control="pause"]')).not.toBeNull();
    expect(el.querySelector('[data-op="b"] [data-control="resume"]')).not.toBeNull();
    // Cancelling undoes nothing by itself; the part that ran can be undone after.
    expect(controlsFor(op('e', 'cancelled'))).toEqual(['undo']);
    // Other kinds have their own screens and no controls here.
    expect(controlsFor(op('f', 'running', { kind: 'bulk', row_version: null }))).toEqual([]);
  });

  it('shows progress and time left, and sends the row version it saw', () => {
    const { fixture, post } = create([op('a', 'running')]);
    const row: HTMLElement = fixture.nativeElement.querySelector('[data-op="a"]');
    expect(row.querySelector('progress')?.getAttribute('value')).toBe('25');
    expect(row.textContent).toContain('250 / 1000');
    expect(row.textContent).toContain('12 min');
    (row.querySelector('[data-control="pause"]') as HTMLButtonElement).click();
    expect(post).toHaveBeenCalledWith('/api/v1/mass/a/pause', {}, { ifMatch: 3 });
  });

  it('refreshes every 5 s only while something is working', () => {
    vi.useFakeTimers();
    const working = create([op('a', 'running')]);
    expect(working.get).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(5000);
    expect(working.get).toHaveBeenCalledTimes(2);
    TestBed.resetTestingModule();

    const idle = create([op('b', 'done')]);
    vi.advanceTimersByTime(15000);
    expect(idle.get).toHaveBeenCalledTimes(1);
  });

  it('computes progress only with a known total', () => {
    expect(progressPercent(op('a', 'running', { estimated_rows: null }))).toBeNull();
    expect(progressPercent(op('a', 'running', { rows_done: 0 }))).toBe(0);
    expect(progressPercent(op('a', 'running', { rows_done: 2000 }))).toBe(100);
  });
});
