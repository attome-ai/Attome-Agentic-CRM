import { Injectable } from '@angular/core';

/**
 * Render plans kept across page loads (roadmap Y14-T2), in IndexedDB.
 * Best effort: any failure (no IndexedDB, private mode, a quota error) reads
 * as "nothing stored" and the plan is simply fetched again.
 */

export interface StoredPlan<T> {
  etag: string;
  plan: T;
}

const DB_NAME = 'attome-render-plans';
const STORE = 'plans';

@Injectable({ providedIn: 'root' })
export class PlanStore {
  private open(): Promise<IDBDatabase | null> {
    return new Promise(resolve => {
      try {
        if (typeof indexedDB === 'undefined') {
          resolve(null);
          return;
        }
        const request = indexedDB.open(DB_NAME, 1);
        request.onupgradeneeded = () => request.result.createObjectStore(STORE);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    });
  }

  async read<T>(key: string): Promise<StoredPlan<T> | null> {
    const db = await this.open();
    if (!db) return null;
    return new Promise(resolve => {
      try {
        const request = db.transaction(STORE, 'readonly').objectStore(STORE).get(key);
        request.onsuccess = () => resolve((request.result as StoredPlan<T> | undefined) ?? null);
        request.onerror = () => resolve(null);
      } catch {
        resolve(null);
      }
    });
  }

  async write<T>(key: string, value: StoredPlan<T>): Promise<void> {
    const db = await this.open();
    if (!db) return;
    try {
      db.transaction(STORE, 'readwrite').objectStore(STORE).put(value, key);
    } catch {
      // Best effort: the next load fetches the plan again.
    }
  }
}
