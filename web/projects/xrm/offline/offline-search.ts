import { Injectable, inject } from '@angular/core';
import MiniSearch from 'minisearch';

import { OFFLINE_STORE } from './offline-queue.service';
import { OfflineStore } from './offline-store';

/**
 * B18-T11 — search over the records held on this device, with no network.
 *
 * Each record's text values (its primary name and other text attributes)
 * are indexed in memory with MiniSearch; prefix and light fuzzy matching
 * find a name as it is being typed. Arabic is normalised the same way when
 * indexing and when searching, so the way a name was typed does not decide
 * whether it is found: diacritics (tashkeel) and the tatweel are dropped,
 * every alef form (أ إ آ ٱ) becomes ا, ة becomes ه and ى becomes ي. So
 * "احمد" finds "أحمد" and "مدرسه" finds "مدرسة".
 *
 * The index lives only in memory: `rebuild` reads the device store again,
 * which the sync loop calls after each pull.
 */

/** Arabic diacritics, the superscript alef and the tatweel. */
const TASHKEEL = /[ً-ٰٟـ]/g;
const ALEF_FORMS = /[آأإٱ]/g;

/** One normalised search form of `text`. */
export function normaliseArabic(text: string): string {
  return text
    .normalize('NFC')
    .replace(TASHKEEL, '')
    .replace(ALEF_FORMS, 'ا')
    .replace(/ة/g, 'ه')
    .replace(/ى/g, 'ي')
    .toLowerCase();
}

/** One record as the search answers it. */
export interface OfflineHit {
  entity: string;
  id: string;
  /** The record's name: its first text value, for showing the hit. */
  name: string;
  score: number;
}

interface Doc {
  key: string;
  entity: string;
  id: string;
  name: string;
  text: string;
}

/** Attributes that are never searched: ids, versions and system stamps. */
const SKIPPED = new Set(['id', 'row_version', 'created_by', 'modified_by', 'owner_id', 'created_at', 'modified_at']);

/** The searchable text of a record: its string values, skipping ids. */
export function recordText(data: Record<string, unknown>): { name: string; text: string } {
  const values: string[] = [];
  for (const [key, value] of Object.entries(data)) {
    if (SKIPPED.has(key) || key.startsWith('_') || key.endsWith('_ref')) continue;
    if (typeof value === 'string' && value.trim() && !/^[0-9a-f-]{36}$/i.test(value)) values.push(value.trim());
  }
  const named = data['name'] ?? data['title'] ?? data['full_name'];
  const name = typeof named === 'string' && named.trim() ? named.trim() : (values[0] ?? '');
  return { name, text: values.join(' ') };
}

function newIndex(): MiniSearch<Doc> {
  return new MiniSearch<Doc>({
    idField: 'key',
    fields: ['name', 'text'],
    storeFields: ['entity', 'id', 'name'],
    processTerm: term => normaliseArabic(term),
    searchOptions: {
      prefix: true,
      fuzzy: 0.15,
      boost: { name: 2 },
      processTerm: term => normaliseArabic(term),
    },
  });
}

@Injectable({ providedIn: 'root' })
export class OfflineSearch {
  private readonly store = inject(OFFLINE_STORE);
  private index = newIndex();

  /** Records indexed now. */
  get size(): number {
    return this.index.documentCount;
  }

  /** Indexes these records in place of whatever was indexed. */
  load(records: { entity: string; id: string; data: Record<string, unknown> }[]): void {
    const index = newIndex();
    index.addAll(records.map(r => ({ key: `${r.entity}:${r.id}`, entity: r.entity, id: r.id, ...recordText(r.data) })));
    this.index = index;
  }

  /** Reads every record the device holds and indexes them again. */
  async rebuild(store: OfflineStore = this.store): Promise<void> {
    const records: { entity: string; id: string; data: Record<string, unknown> }[] = [];
    for (const key of await store.keys('records')) {
      const [entity, id] = key.split('\u0000');
      if (!entity || !id) continue;
      const data = await store.getRecord<Record<string, unknown>>(entity, id);
      if (data && typeof data === 'object') records.push({ entity, id, data });
    }
    this.load(records);
  }

  /** The best matches for `query`, at most `limit`. */
  search(query: string, limit = 20): OfflineHit[] {
    if (!query.trim()) return [];
    return this.index
      .search(query)
      .slice(0, limit)
      .map(hit => ({ entity: hit['entity'] as string, id: hit['id'] as string, name: hit['name'] as string, score: hit.score }));
  }
}
