import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService, Page } from '@attome/base';

/**
 * M61 / S10-T1 — API usage over `crates/engine/attome-api/src/api_usage_admin.rs`
 * (`system.admin`): the per-route rollup, every key with its requests and
 * its own quota, and setting that quota. Lists are one-based (D-347, D-793).
 */
export interface ApiUsageSummaryRow {
  method: string;
  route_template: string;
  identity_kind: string;
  identity_label: string;
  total_requests: number;
}

/** One API key as an admin sees it (never its secret). */
export interface ApiKeyUsageRow {
  id: string;
  name: string;
  public_key: string;
  owner_id: string;
  owner_name?: string | null;
  is_active: boolean;
  expires_at?: string | null;
  last_used_at?: string | null;
  /** The key's own budget per minute; `null` leaves the deployment's limits only. */
  requests_per_minute?: number | null;
  total_requests: number;
}

export interface ApiKeyQuotaSet {
  id: string;
  requests_per_minute?: number | null;
}

/** The largest quota the API accepts (`MAX_KEY_QUOTA`). */
export const MAX_KEY_QUOTA = 100_000;

/** The windows the usage screen offers, in days (the API clamps to 1–90). */
export const USAGE_WINDOWS = [1, 7, 30, 90] as const;

@Injectable({ providedIn: 'root' })
export class ApiUsageService {
  private readonly api = inject(ApiService);

  summary(days: number, page = 1, pageSize = 50): Observable<Page<ApiUsageSummaryRow>> {
    return this.api.get<Page<ApiUsageSummaryRow>>('/api/v1/admin/api-usage/summary', {
      days: String(days), page: String(page), page_size: String(pageSize),
    });
  }

  keys(days: number, page = 1, pageSize = 50): Observable<Page<ApiKeyUsageRow>> {
    return this.api.get<Page<ApiKeyUsageRow>>('/api/v1/admin/api-keys', {
      days: String(days), page: String(page), page_size: String(pageSize),
    });
  }

  /** Sets the key's quota; `null` clears it. */
  setQuota(id: string, requestsPerMinute: number | null): Observable<ApiKeyQuotaSet> {
    return this.api.put<ApiKeyQuotaSet>(
      `/api/v1/admin/api-keys/${encodeURIComponent(id)}/quota`,
      { requests_per_minute: requestsPerMinute },
    );
  }
}
