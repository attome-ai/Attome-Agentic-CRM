import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { RecycleBinComponent } from './recycle-bin.component';

describe('RecycleBinComponent (A18-T9)', () => {
  function create() {
    const get = vi.fn().mockReturnValue(of({ items: [
      { id: 'r1', label: 'Acme', deleted_at: '2026-10-14T10:00:00Z', deleted_by: null, reason: 'duplicate', operation_id: 'op-1', operation_kind: 'request' },
      { id: 'r2', label: null, deleted_at: '2026-10-14T10:00:00Z', deleted_by: null, reason: null, operation_id: 'op-1', operation_kind: 'request' },
    ] }));
    const post = vi.fn().mockReturnValue(of({ restored: 2, failed: [] }));
    TestBed.configureTestingModule({
      imports: [RecycleBinComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(RecycleBinComponent);
    fixture.componentRef.setInput('entity', 'account');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('lists deleted records with their reason and restores a selection', () => {
    const { fixture, get, post } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/account/deleted', { page: '1', page_size: '100' });
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.querySelector('[data-record="r1"]')?.textContent).toContain('duplicate');
    fixture.componentInstance.toggle('r1');
    fixture.componentInstance.restoreSelected();
    expect(post).toHaveBeenCalledWith('/api/v1/bin/restore', { items: [{ entity: 'account', id: 'r1' }] });
    expect(fixture.componentInstance.result()?.restored).toBe(2);
  });

  it('restores a whole operation', () => {
    const { fixture, post } = create();
    expect(fixture.componentInstance.operationSize('op-1')).toBe(2);
    fixture.componentInstance.restoreOperation('op-1');
    expect(post).toHaveBeenCalledWith('/api/v1/bin/operations/op-1/restore', {});
  });
});
