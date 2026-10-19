import { Injectable } from '@angular/core';

/** AA7-T11: one remembered answer — the ETag it came with and its body. */
export interface ConditionalEntry {
  etag: string;
  body: unknown;
}

/**
 * AA7-T11 — the bodies `ApiService` revalidates with `If-None-Match`: an
 * entity schema and a `query/execute` page. Returning to a list whose rows
 * did not change then costs one `304` and no body.
 *
 * In memory only (never `localStorage`), at most `MAX_ENTRIES` entries with
 * the least recently used dropped first, and cleared when the session ends
 * or the language changes, so no entry outlives the user or the language it
 * was fetched for. It has no dependencies, which lets `AuthService` and
 * `LangService` clear it without depending on `ApiService`.
 *
 * Bodies are copied in and out, so a caller that edits what it got back
 * cannot change what the next `304` returns.
 */
@Injectable({ providedIn: 'root' })
export class ConditionalCache {
  static readonly MAX_ENTRIES = 200;

  private readonly entries = new Map<string, ConditionalEntry>();

  get size(): number {
    return this.entries.size;
  }

  /** The entry for `key`, marking it the most recently used. */
  get(key: string): ConditionalEntry | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    this.entries.delete(key);
    this.entries.set(key, entry);
    return { etag: entry.etag, body: structuredClone(entry.body) };
  }

  set(key: string, etag: string, body: unknown): void {
    this.entries.delete(key);
    this.entries.set(key, { etag, body: structuredClone(body) });
    while (this.entries.size > ConditionalCache.MAX_ENTRIES) {
      const oldest = this.entries.keys().next();
      if (oldest.done) break;
      this.entries.delete(oldest.value);
    }
  }

  delete(key: string): void {
    this.entries.delete(key);
  }

  clear(): void {
    this.entries.clear();
  }
}
