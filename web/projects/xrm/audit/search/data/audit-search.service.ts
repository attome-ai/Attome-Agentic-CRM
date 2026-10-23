import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService, ATTOME_CONFIG } from '@attome/base';

/**
 * M19 (Audit) gap list — `GET /api/v1/admin/audit/search` and `GET
 * /api/v1/admin/audit/export` (`crates/engine/attome-audit/src/admin.rs`).
 * Types are pulled from the generated OpenAPI document
 * (`npm run generate:api`), same convention `EntityService`'s typed calls
 * use — `AuditSearchRow`/`PaginatedResponse_AuditSearchRow` are this file's
 * Rust struct name and its `PaginatedResponse<T>` wrapper respectively.
 */
export type AuditSearchRow = ApiComponents['schemas']['AuditSearchRow'];
/** Q17-T1: what an evidence pack covers — a time range or one record. */
export type EvidencePackRequest = ApiComponents['schemas']['EvidencePackRequest'];
export type EvidencePack = ApiComponents['schemas']['EvidencePack'];
export type AuditSearchResponse =
  ApiComponents['schemas']['PaginatedResponse_AuditSearchRow'];

export interface AuditSearchFilters {
  entity_name?: string;
  record_id?: string;
  user_id?: string;
  user_email?: string;
  /** `attome_audit::model::AuditOperation`'s integer discriminant. */
  operation?: number;
  field_name?: string;
  date_from?: string;
  date_to?: string;
  organization_ref?: string;
}

export type AuditExportFormat = 'jsonl' | 'cef' | 'csv';

@Injectable({ providedIn: 'root' })
export class AuditSearchService {
  private readonly api = inject(ApiService);
  private readonly config = inject(ATTOME_CONFIG);

  search(
    filters: AuditSearchFilters,
    page: number,
    pageSize: number,
  ): Observable<AuditSearchResponse> {
    const params = toParams(filters);
    params['page'] = String(page);
    params['page_size'] = String(pageSize);
    return this.api.get<AuditSearchResponse>('/api/v1/admin/audit/search', params);
  }

  /**
   * Q17-T1 / Q16: the sealed events of a range or record with their
   * inclusion proofs and the public keys to verify them offline
   * (`POST /api/v1/admin/audit/evidence-packs`, at most 2,000 events).
   */
  evidencePack(body: EvidencePackRequest): Observable<EvidencePack> {
    return this.api.post<EvidencePack>('/api/v1/admin/audit/evidence-packs', body);
  }

  /**
   * The streamed export is a direct authenticated download, not a
   * job-and-poll flow (`data_export.rs`'s route explicitly forbids audit
   * entities — see `attome_audit::admin`'s module doc for why "reuse M12"
   * meant reusing its streaming primitive, not its route). Returns the URL
   * a template binds to `<a href download>` / opens directly — the
   * session cookie rides along on a same-site navigation the same way
   * `MigrationWizardComponent.errorsUrl()` already relies on.
   */
  exportUrl(filters: AuditSearchFilters, format: AuditExportFormat): string {
    // `admin.rs::ExportQuery` names the date-range params `from`/`to` (the
    // conventional SIEM export shape), not `date_from`/`date_to` —
    // translated explicitly here rather than relying on key-for-key
    // passthrough, which would silently drop the filter instead of erroring.
    const { date_from, date_to, ...rest } = filters;
    const params = toParams(rest);
    if (date_from) params['from'] = date_from;
    if (date_to) params['to'] = date_to;
    params['format'] = format;
    const query = new URLSearchParams(params).toString();
    return `${this.config.apiUrl}/api/v1/admin/audit/export?${query}`;
  }
}

function toParams(filters: AuditSearchFilters): Record<string, string> {
  const params: Record<string, string> = {};
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === null || value === '') continue;
    params[key] = String(value);
  }
  return params;
}
