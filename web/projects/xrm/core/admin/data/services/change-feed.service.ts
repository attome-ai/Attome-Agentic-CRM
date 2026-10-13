import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';

/**
 * M89 Change Intelligence item 1 — `GET /api/v1/admin/changes`
 * (`crates/engine/attome-api/src/changes_admin.rs`, `Authorized<Admin>`).
 *
 * Keyset paged: the route merges every source in one total order
 * (`occurred_at` newest first, then kind, then source row id) and hands back
 * an opaque `next_cursor` for the page after the last row — absent when
 * there is none. Nothing is capped, so paging reaches every change in the
 * window. `total` is exact and present only on a request without a cursor.
 * The route has no offset `page` mode (deleted, D-790). The envelope is the
 * shared `CursorPage<ChangeFeedEntry>` (D-793).
 */
export type ChangeFeedEntry = ApiComponents['schemas']['ChangeFeedEntry'];
export type ChangeKind      = ApiComponents['schemas']['ChangeKind'];
export type ChangeFeedPage  = ApiComponents['schemas']['CursorPage_ChangeFeedEntry'];

/** Every `ChangeKind` wire value, in the order `changes_admin.rs` lists them. */
export const CHANGE_KINDS: readonly ChangeKind[] = [
  'metadata', 'bundle', 'query', 'workflow', 'dashboard',
  'content', 'license', 'security', 'ai', 'settings',
];

export interface ChangeFeedFilter {
  kind?: ChangeKind;
  /** ISO-8601 instant; the server defaults to `to - 30 days`. */
  from?: string;
  /** ISO-8601 instant; the server defaults to now. */
  to?:   string;
}

@Injectable({ providedIn: 'root' })
export class ChangeFeedService {
  private readonly api = inject(ApiService);

  /** `cursor` is a previous page's `next_cursor`, verbatim; omit it for the first page. */
  listChanges(filter: ChangeFeedFilter, cursor?: string, pageSize = 50): Observable<ChangeFeedPage> {
    const params: Record<string, string> = { page_size: String(pageSize) };
    if (cursor)      params['cursor'] = cursor;
    if (filter.kind) params['kind'] = filter.kind;
    if (filter.from) params['from'] = filter.from;
    if (filter.to)   params['to'] = filter.to;
    return this.api.get<ChangeFeedPage>('/api/v1/admin/changes', params);
  }
}
