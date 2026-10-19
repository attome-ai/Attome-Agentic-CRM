import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents, Page } from '@attome/base';

/**
 * Z3-T10 — the cache admin routes (`attome_api::profiler_admin`, Z3-T9,
 * administrators only): each declared cache's numbers on the node that
 * answers, and an audited purge of one key or the whole cache on every node.
 * Neither route ever returns a cached value.
 */
export type CacheStatsRow = ApiComponents['schemas']['CacheStatsRow'];

@Injectable({ providedIn: 'root' })
export class CacheAdminService {
  private readonly api = inject(ApiService);

  /** `GET /api/v1/admin/caches` (one-based pages). */
  list(page = 1, pageSize = 200): Observable<Page<CacheStatsRow>> {
    return this.api.get<Page<CacheStatsRow>>('/api/v1/admin/caches', {
      page: String(page), page_size: String(pageSize),
    });
  }

  /** `POST /api/v1/admin/caches/{name}/purge`: one key, or everything when `key` is null. */
  purge(name: string, key: string | null): Observable<void> {
    return this.api.post<void>(
      `/api/v1/admin/caches/${encodeURIComponent(name)}/purge`,
      key ? { key } : {},
    );
  }
}
