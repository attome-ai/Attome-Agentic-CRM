import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents, Page } from '@attome/base';

/**
 * Z1-T14 — the configuration admin reads (`attome_compliance::config_admin`,
 * administrators only): the secret inventory (Z1-T8; names, users, key ids
 * and ages, never a value) and the record of node starts with a comparison
 * of two (Z1-T7).
 */
export type SecretInventoryRow = ApiComponents['schemas']['SecretInventoryRow'];
export type ConfigStartRow = ApiComponents['schemas']['ConfigStartRow'];
export type ConfigChange = ApiComponents['schemas']['ConfigChange'];

@Injectable({ providedIn: 'root' })
export class SecretsAdminService {
  private readonly api = inject(ApiService);

  /** `GET /api/v1/admin/secrets` (one-based pages). */
  secrets(page = 1, pageSize = 200): Observable<Page<SecretInventoryRow>> {
    return this.api.get<Page<SecretInventoryRow>>('/api/v1/admin/secrets', {
      page: String(page), page_size: String(pageSize),
    });
  }

  /** `GET /api/v1/admin/config/starts`, newest first (one-based pages). */
  starts(page = 1, pageSize = 50): Observable<Page<ConfigStartRow>> {
    return this.api.get<Page<ConfigStartRow>>('/api/v1/admin/config/starts', {
      page: String(page), page_size: String(pageSize),
    });
  }

  /** `GET /api/v1/admin/config/starts/diff?a=&b=`: the keys that differ. */
  diff(a: string, b: string): Observable<Page<ConfigChange>> {
    return this.api.get<Page<ConfigChange>>('/api/v1/admin/config/starts/diff', { a, b });
  }
}
