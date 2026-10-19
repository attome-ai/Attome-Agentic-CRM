import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';

import { OFFLINE_STORE } from './offline-queue.service';
import { MemoryBackend, OfflineStore } from './offline-store';
import { OfflineSearch, normaliseArabic, recordText } from './offline-search';

function search(records: { entity: string; id: string; data: Record<string, unknown> }[]): OfflineSearch {
  TestBed.configureTestingModule({
    providers: [{ provide: OFFLINE_STORE, useValue: new OfflineStore(new MemoryBackend()) }],
  });
  const s = TestBed.inject(OfflineSearch);
  s.load(records);
  return s;
}

describe('OfflineSearch (B18-T11)', () => {
  it('finds arabic name without diacritics', () => {
    const s = search([{ entity: 'contact', id: 'c1', data: { name: 'مُحَمَّد العَلِي' } }]);
    expect(s.search('محمد').map(h => h.id)).toEqual(['c1']);
  });

  it('finds by alef variant', () => {
    const s = search([
      { entity: 'contact', id: 'c1', data: { name: 'أحمد سالم' } },
      { entity: 'contact', id: 'c2', data: { name: 'إبراهيم' } },
    ]);
    expect(s.search('احمد').map(h => h.id)).toEqual(['c1']);
    expect(s.search('ابراهيم').map(h => h.id)).toEqual(['c2']);
  });

  it('matches ta marbuta and alef maqsura either way, and English by prefix', () => {
    const s = search([
      { entity: 'account', id: 'a1', data: { name: 'مدرسة النور' } },
      { entity: 'account', id: 'a2', data: { name: 'مستشفى الشفاء' } },
      { entity: 'account', id: 'a3', data: { name: 'Riyadh Trading Co' } },
    ]);
    expect(s.search('مدرسه').map(h => h.id)).toEqual(['a1']);
    expect(s.search('مستشفي').map(h => h.id)).toEqual(['a2']);
    expect(s.search('riya').map(h => h.id)).toEqual(['a3']);
  });

  it('rebuilds from the records the device holds', async () => {
    const store = new OfflineStore(new MemoryBackend());
    await store.putRecord('contact', 'c9', { name: 'سارة' });
    const s = search([]);
    await s.rebuild(store);
    expect(s.size).toBe(1);
    expect(s.search('ساره')[0]).toMatchObject({ entity: 'contact', id: 'c9', name: 'سارة' });
  });

  it('normalises and skips ids', () => {
    expect(normaliseArabic('آمِنَة')).toBe('امنه');
    expect(recordText({ id: '0192f0c4-7d1e-7c3a-9b1e-5d6f8a9b0c1d', title: 'Deal', owner_ref: 'x' }))
      .toEqual({ name: 'Deal', text: 'Deal' });
  });
});
