import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import {
  MassConfirmDialogComponent, MassEstimate, durationLabel, filtersToCondition,
} from './mass-confirm-dialog.component';

describe('MassConfirmDialogComponent (AA10-T8)', () => {
  function create(estimate: MassEstimate) {
    const post = vi.fn((url: string, _body: unknown) => of(
      url.endsWith('/estimate')
        ? estimate
        : { operation: { id: 'op-1', status: 'queued', estimated_rows: estimate.estimated_rows, rows_done: 0 } },
    ));
    TestBed.configureTestingModule({
      imports: [MassConfirmDialogComponent],
      providers: [
        { provide: ApiService, useValue: { post } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(MassConfirmDialogComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.componentRef.setInput('filter', { kind: 'compare', field: 'city', op: 'eq', value: 'Riyadh' });
    fixture.detectChanges();
    fixture.componentInstance.show();
    fixture.detectChanges();
    return { fixture, post };
  }

  it('shows background note for large estimate', () => {
    const { fixture } = create({
      exact_upto: 5001, exceeds: true, estimated_rows: 120000, estimated_seconds: 240, path: 'background',
    });
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-background-note]')).not.toBeNull();
    expect(el.querySelector('[data-estimate-time]')?.textContent).toContain('massConfirm.time');
    expect(fixture.componentInstance.duration(240)).toBe('4 min');
  });

  it('shows no background note for a small estimate', () => {
    const { fixture } = create({
      exact_upto: 12, exceeds: false, estimated_rows: 12, estimated_seconds: 1, path: 'inline',
    });
    expect(fixture.nativeElement.querySelector('[data-background-note]')).toBeNull();
  });

  it('starts only after the estimate, sending the rows it showed', () => {
    const { fixture, post } = create({
      exact_upto: 5001, exceeds: true, estimated_rows: 120000, estimated_seconds: 240, path: 'background',
    });
    const started = vi.fn();
    fixture.componentInstance.started.subscribe(started);
    expect(post).toHaveBeenCalledWith('/api/v1/account/mass/estimate', {
      kind: 'delete', filter: { kind: 'compare', field: 'city', op: 'eq', value: 'Riyadh' }, payload: {},
    });
    (fixture.nativeElement.querySelector('[data-confirm]') as HTMLButtonElement).click();
    expect(post).toHaveBeenLastCalledWith('/api/v1/account/mass', expect.objectContaining({
      kind: 'delete', confirm_estimate_rows: 120000,
    }));
    expect(started).toHaveBeenCalledOnce();
  });

  it('turns the list filters into one condition', () => {
    expect(filtersToCondition([])).toBeNull();
    expect(filtersToCondition([{ field: 'city', op: 'eq', value: 'Riyadh' }]))
      .toEqual({ kind: 'compare', field: 'city', op: 'eq', value: 'Riyadh' });
    expect(filtersToCondition([
      { field: 'city', op: 'eq', value: 'Riyadh' }, { field: 'phone', op: 'is_null' },
    ])).toEqual({ kind: 'and', all: [
      { kind: 'compare', field: 'city', op: 'eq', value: 'Riyadh' },
      { kind: 'compare', field: 'phone', op: 'is_null' },
    ] });
    // A tag filter has no condition form: the list must not offer the action.
    expect(filtersToCondition([{ field: 'id', op: 'tagged', value: 't' }])).toBeUndefined();
    expect(durationLabel(30)).toBe('30 s');
    expect(durationLabel(7201)).toBe('3 h');
  });
});
