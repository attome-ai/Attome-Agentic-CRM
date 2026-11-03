import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';
import { firstValueFrom, of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { EntityService } from '../../services/entity.service';
import { MultiLookupComponent, chipsChanged } from './multi-lookup.component';

const rec = (id: string, data: Record<string, unknown>) => ({ id, row_version: 1, data } as unknown as EntityRecord);

describe('multi-lookup chips (A2-T5)', () => {
  it('a different set of chips is a change, the same set in another order is not', () => {
    const a = { id: 'a', label: 'A' };
    const b = { id: 'b', label: 'B' };
    expect(chipsChanged([a, b], [b, a])).toBe(false);
    expect(chipsChanged([a], [a, b])).toBe(true);
    expect(chipsChanged([a, b], [a, { id: 'c', label: 'C' }])).toBe(true);
  });

  function setUp() {
    const entities = {
      listRelated: vi.fn().mockReturnValue(of({
        items: [rec('t1', { name: 'وسم أول First tag' }), rec('t2', { name: 'Second' })], total: 2, page: 1, page_size: 200,
      })),
      lookupSearch: vi.fn().mockReturnValue(of({ data: [rec('t2', { name: 'Second' }), rec('t3', { name: 'Third' })], meta: { total: 2 } })),
      replaceRelated: vi.fn().mockReturnValue(of(undefined)),
    };
    TestBed.configureTestingModule({
      imports: [MultiLookupComponent],
      providers: [
        { provide: EntityService, useValue: entities },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: () => 'error', isRtl: signal(false) } },
      ],
    });
    const fixture = TestBed.createComponent(MultiLookupComponent);
    fixture.componentRef.setInput('entity', 'deal');
    fixture.componentRef.setInput('recordId', 'd1');
    fixture.componentRef.setInput('relationship', 'deal_tags');
    fixture.componentRef.setInput('otherEntity', 'tag');
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, entities };
  }

  it('shows the linked records as chips', () => {
    const { el, entities } = setUp();
    expect(entities.listRelated).toHaveBeenCalledWith('deal', 'd1', 'deal_tags', 1, 200);
    const chips = el.querySelectorAll('.ml-chip');
    expect(chips.length).toBe(2);
    expect(chips[0].textContent).toContain('First tag');
  });

  it('searches the other side, leaving out what is already linked', async () => {
    const { cmp } = setUp();
    const hits = await firstValueFrom(cmp.search('th'));
    expect(hits.map(h => h.id)).toEqual(['t3']);
    expect(await firstValueFrom(cmp.search('t'))).toEqual([]);
  });

  it('adds and removes chips, then saves the set in one call', () => {
    const { cmp, fixture, entities } = setUp();
    expect(cmp.dirty()).toBe(false);
    cmp.add({ id: 't3', label: 'Third' });
    cmp.remove('t1');
    fixture.detectChanges();
    expect(cmp.dirty()).toBe(true);
    cmp.save();
    expect(entities.replaceRelated).toHaveBeenCalledWith('deal', 'd1', 'deal_tags', ['t2', 't3']);
    expect(cmp.dirty()).toBe(false);
  });
});
