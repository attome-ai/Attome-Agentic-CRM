import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';
import { firstValueFrom, of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EntityService } from '../../services/entity.service';
import { PolymorphicLookupComponent, entityIcon, recordLabel } from './polymorphic-lookup.component';

const rec = (id: string, data: Record<string, unknown>) => ({ id, row_version: 1, data } as unknown as EntityRecord);

describe('polymorphic lookup picker (A8-T5)', () => {
  it('names a record by its display field and falls back to name, then the id', () => {
    expect(recordLabel(rec('1', { company: 'Acme' }), 'company')).toBe('Acme');
    expect(recordLabel(rec('2', { name: 'شركة النور' }), 'company')).toBe('شركة النور');
    expect(recordLabel(rec('3', {}), 'name')).toBe('3');
    expect(entityIcon('account', { account: 'las la-building' })).toBe('las la-building');
    expect(entityIcon('case', {})).toBe('las la-file-alt');
  });

  function setUp() {
    const lookupSearch = vi.fn((entity: string) => {
      if (entity === 'account') return of({ data: [rec('a1', { name: 'شركة النور' })], meta: { total: 1 } });
      if (entity === 'contact') return of({ data: [], meta: { total: 0 } });
      return throwError(() => new Error('forbidden'));
    });
    TestBed.configureTestingModule({
      imports: [PolymorphicLookupComponent],
      providers: [
        { provide: EntityService, useValue: { lookupSearch } },
        { provide: LangService, useValue: { translate: (k: string) => k, isRtl: signal(false) } },
      ],
    });
    const fixture = TestBed.createComponent(PolymorphicLookupComponent);
    fixture.componentRef.setInput('targets', ['account', 'contact', 'secret']);
    fixture.componentRef.setInput('icons', { account: 'las la-building' });
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, lookupSearch };
  }

  it('searches every allowed entity at once and keeps only the ones with hits', async () => {
    const { cmp, lookupSearch } = setUp();
    const groups = await firstValueFrom(cmp.search('النور'));
    expect(lookupSearch).toHaveBeenCalledTimes(3);
    expect(lookupSearch).toHaveBeenCalledWith('account', 'النور', 'name');
    expect(groups).toEqual([{ entity: 'account', icon: 'las la-building', hits: [{ id: 'a1', label: 'شركة النور' }] }]);
    expect(await firstValueFrom(cmp.search('a'))).toEqual([]);
  });

  it('emits the picked pair and shows the current value', () => {
    const { cmp, fixture, el } = setUp();
    const picked = vi.fn();
    cmp.picked.subscribe(picked);
    cmp.pick('account', { id: 'a1', label: 'شركة النور' });
    expect(picked).toHaveBeenCalledWith({ entity: 'account', id: 'a1', label: 'شركة النور' });
    fixture.componentRef.setInput('value', { entity: 'account', id: 'a1', label: 'شركة النور' });
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="poly-value"]')?.textContent).toContain('شركة النور');
    cmp.clear();
    expect(picked).toHaveBeenLastCalledWith(null);
  });
});
