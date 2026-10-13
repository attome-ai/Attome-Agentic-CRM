import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService, Page } from '@attome/base';

// P-api-contract (C-26): codegen-derived where a generated schema exists —
// these types now mirror `attome-compliance/src/{dsr_admin,legal_hold_admin,
// governance_admin}.rs` (moved there from `attome-api` since this file's old
// header comment was written; the doc comment was stale on that point) via
// `ApiComponents['schemas']`, checked one at a time against the owning Rust
// struct. Several exported names here differ from their generated schema key
// — kept so the consuming components below don't need to change — see each
// type's comment for the actual schema name and why.

/** Wire schema is `DsrRequestSummary` (`dsr_admin.rs`). */
export type DsrRequestItem = ApiComponents['schemas']['DsrRequestSummary'];

export type CreateDsrRequestBody = ApiComponents['schemas']['CreateDsrRequestBody'];
export type DsrScope = ApiComponents['schemas']['DsrScope'];
export type FulfillExportBody = ApiComponents['schemas']['FulfillExportBody'];
export type ScopeExportResult = ApiComponents['schemas']['ScopeExportResult'];
export type FulfillExportResult = ApiComponents['schemas']['FulfillExportResult'];
export type FulfillErasureBody = ApiComponents['schemas']['FulfillErasureBody'];

// `ErasedRecord`/`FulfillErasureResult`/`FulfillErasurePending` stay
// hand-written: their Rust structs (`dsr_admin.rs`) derive only `Serialize`,
// not `ToSchema`, so none reaches `openapi.json` — backend annotation gap
// (guidelines §12), out of scope for this Angular-only pass. `FulfillErasureResult`
// was itself missing two fields the Rust struct has carried for a while
// (`consents_withdrawn`/`memories_deleted`, M24/D-428 and M35/D-451) — added
// here by hand since codegen can't do it; verified directly against
// `dsr_admin.rs`'s `FulfillErasureResult` struct.
export interface ErasedRecord {
  entity_logicalname: string;
  record_id:           string;
  key_destroyed:        boolean;
}

export interface FulfillErasureResult {
  id:                  string;
  status:              string;
  block_reason:        string | null;
  erased:              ErasedRecord[];
  /** M24/D-428: `audit_consent` withdrawal rows appended for this subject. */
  consents_withdrawn:  number;
  /** M35/D-451: `memory` rows deleted for this subject. */
  memories_deleted:    number;
}

/** Returned instead of `FulfillErasureResult` when `dsr.fulfill_erasure` is
 *  in `approval.required_actions` (D-269) — distinguish via `approval_pending`.
 *  Same backend annotation gap as `FulfillErasureResult` above. */
export interface FulfillErasurePending {
  approval_pending:     true;
  approval_request_id:  string;
}

/** Wire schema is `PlaceLegalHoldResult` (`legal_hold_admin.rs`) — a
 *  superset of `list`/`release`'s `LegalHoldSummary` (adds optional
 *  `resolved_steward_ref`, M15/D-413), so it types all three call sites:
 *  `listLegalHolds`'s items simply never populate that one optional field. */
export type LegalHoldItem = ApiComponents['schemas']['PlaceLegalHoldResult'];

// ── M15 Data Governance (D-413): data domains / accountability register
// (`crates/engine/attome-compliance/src/governance_admin.rs`) ──

/** Wire schema is `DataDomainSummary`. */
export type DataDomainItem = ApiComponents['schemas']['DataDomainSummary'];

/** Wire schema is `CreateDomainBody`. */
export type CreateDataDomainBody = ApiComponents['schemas']['CreateDomainBody'];

/**
 * Wire schema is `UpdateDomainBody`. `row_version` really is a required body
 * field here, not an `If-Match` header — verified against
 * `governance_admin.rs::update_domain`, which binds `body.row_version`
 * straight into its `UPDATE ... WHERE row_version = $6` and has no `If-Match`
 * handling at all. This is a real, deployed divergence from the generic
 * entity engine's `If-Match` convention (guidelines §2 describes that as the
 * default, not as universal) on this one bespoke admin surface — changing it
 * would be a backend wire-contract change, out of scope for this Angular-only
 * pass, and not something to do silently either way (guidelines §15).
 */
export type UpdateDataDomainBody = ApiComponents['schemas']['UpdateDomainBody'];

/** Wire schema is `DomainEntitySummary`. */
export type DomainEntityItem = ApiComponents['schemas']['DomainEntitySummary'];

export type ClassificationBreakdown = ApiComponents['schemas']['ClassificationBreakdown'];
export type DomainLegalHold = ApiComponents['schemas']['DomainLegalHold'];
export type DomainDsrRequest = ApiComponents['schemas']['DomainDsrRequest'];
export type DomainReport = ApiComponents['schemas']['DomainReport'];
export type PlaceLegalHoldBody = ApiComponents['schemas']['PlaceLegalHoldBody'];

@Injectable({ providedIn: 'root' })
export class DataProtectionAdminService {
  private readonly api = inject(ApiService);

  // ── DSR requests ───────────────────────────────────────────────────────

  /** `page` is 1-based, like every offset list (D-793). */
  listDsrRequests(status?: string, requestType?: string, page = 1, pageSize = 50): Observable<Page<DsrRequestItem>> {
    const params: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (status) params['status'] = status;
    if (requestType) params['request_type'] = requestType;
    return this.api.get<Page<DsrRequestItem>>('/api/v1/admin/dsr/requests', params);
  }

  createDsrRequest(body: CreateDsrRequestBody): Observable<DsrRequestItem> {
    return this.api.post<DsrRequestItem>('/api/v1/admin/dsr/requests', body);
  }

  fulfillAccess(id: string, body: FulfillExportBody): Observable<FulfillExportResult> {
    return this.api.post<FulfillExportResult>(`/api/v1/admin/dsr/requests/${id}/fulfill-access`, body);
  }

  fulfillPortability(id: string, body: FulfillExportBody): Observable<FulfillExportResult> {
    return this.api.post<FulfillExportResult>(`/api/v1/admin/dsr/requests/${id}/fulfill-portability`, body);
  }

  /** D-269: may resolve to a `FulfillErasureResult` (executed immediately)
   *  OR a `FulfillErasurePending` (submitted for four-eyes approval instead)
   *  depending on whether `dsr.fulfill_erasure` is gated on this deployment —
   *  callers must check `'approval_pending' in result`. */
  fulfillErasure(id: string, body: FulfillErasureBody): Observable<FulfillErasureResult | FulfillErasurePending> {
    return this.api.post<FulfillErasureResult | FulfillErasurePending>(
      `/api/v1/admin/dsr/requests/${id}/fulfill-erasure`, body,
    );
  }

  // ── Legal holds ────────────────────────────────────────────────────────

  listLegalHolds(status: 'active' | 'released' = 'active', entityLogicalname?: string, page = 1, pageSize = 50): Observable<Page<LegalHoldItem>> {
    const params: Record<string, string> = { status, page: String(page), page_size: String(pageSize) };
    if (entityLogicalname) params['entity_logicalname'] = entityLogicalname;
    return this.api.get<Page<LegalHoldItem>>('/api/v1/admin/legal-holds', params);
  }

  placeLegalHold(body: PlaceLegalHoldBody): Observable<LegalHoldItem> {
    return this.api.post<LegalHoldItem>('/api/v1/admin/legal-holds', body);
  }

  releaseLegalHold(id: string): Observable<LegalHoldItem> {
    return this.api.post<LegalHoldItem>(`/api/v1/admin/legal-holds/${id}/release`, {});
  }

  // ── Data domains (M15 Data Governance, D-413) ─────────────────────────────

  /** `page` is 1-based, like every offset list (D-793). */
  listDomains(page = 1, pageSize = 50): Observable<Page<DataDomainItem>> {
    return this.api.get<Page<DataDomainItem>>('/api/v1/admin/governance/domains', {
      page: String(page), page_size: String(pageSize),
    });
  }

  createDomain(body: CreateDataDomainBody): Observable<DataDomainItem> {
    return this.api.post<DataDomainItem>('/api/v1/admin/governance/domains', body);
  }

  getDomain(id: string): Observable<DataDomainItem> {
    return this.api.get<DataDomainItem>(`/api/v1/admin/governance/domains/${id}`);
  }

  /** `row_version` inside the body, not an `If-Match` header — matches
   *  `governance_admin.rs::update_domain`'s contract. */
  updateDomain(id: string, body: UpdateDataDomainBody): Observable<DataDomainItem> {
    return this.api.patch<DataDomainItem>(`/api/v1/admin/governance/domains/${id}`, body);
  }

  assignEntities(id: string, entityLogicalnames: string[]): Observable<DomainEntityItem[]> {
    return this.api.post<DomainEntityItem[]>(
      `/api/v1/admin/governance/domains/${id}/entities`,
      { entity_logicalnames: entityLogicalnames },
    );
  }

  unassignEntity(id: string, entityLogicalname: string): Observable<void> {
    return this.api.delete(
      `/api/v1/admin/governance/domains/${id}/entities/${encodeURIComponent(entityLogicalname)}`,
    );
  }

  getDomainReport(id: string): Observable<DomainReport> {
    return this.api.get<DomainReport>(`/api/v1/admin/governance/domains/${id}/report`);
  }
}
