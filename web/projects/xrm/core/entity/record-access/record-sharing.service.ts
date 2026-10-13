import { Injectable, inject } from '@angular/core';
import type { Observable } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';

export type RecordShareItem       = ApiComponents['schemas']['RecordShareItem'];
export type CreateRecordShareBody = ApiComponents['schemas']['CreateRecordShareBody'];
export type ReassignOwnerBody     = ApiComponents['schemas']['ReassignOwnerBody'];
export type OwnerItem             = ApiComponents['schemas']['OwnerItem'];

/** The capabilities a record share grants (`shares.rs::capability_to_i16`). */
export const SHARE_CAPABILITIES = ['view', 'action', 'deny'] as const;
export type ShareCapability = typeof SHARE_CAPABILITIES[number];

/**
 * The record-level sharing routes (`attome-security/src/admin/shares.rs`) —
 * list/grant/revoke a record's shares and reassign its owner. Every route is
 * `Authorized<Admin>` today; B-R11 (U7 Phase B) is what would open them to a
 * privileged non-admin, server-side.
 *
 * Lives in `@attome/xrm/core/entity` so the record form and the list can reach
 * it; `@attome/xrm/core/security` depends on this entry point, not the other
 * way round, and its `SecurityAdminService` delegates its record-share calls
 * here so the four routes have one client wrapper.
 */
@Injectable({ providedIn: 'root' })
export class RecordSharingService {
  private readonly api = inject(ApiService);

  listRecordShares(entity: string, recordId: string): Observable<RecordShareItem[]> {
    return this.api.getAllPages<RecordShareItem>('/api/v1/admin/security/record-shares', {
      entity, record_id: recordId,
    });
  }

  createRecordShare(body: CreateRecordShareBody): Observable<RecordShareItem> {
    return this.api.post<RecordShareItem>('/api/v1/admin/security/record-shares', body);
  }

  deleteRecordShare(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/record-shares/${id}`);
  }

  /** PUT, per record — the route has no bulk form. */
  reassignOwner(body: ReassignOwnerBody): Observable<OwnerItem> {
    return this.api.put<OwnerItem>('/api/v1/admin/security/record-shares/reassign-owner', body);
  }
}
