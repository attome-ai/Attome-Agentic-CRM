import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

/** Mirrors `attome_compliance::consent_admin::WithdrawConsentBody` exactly —
 *  `crates/engine/attome-compliance/src/consent_admin.rs`. */
export interface WithdrawConsentBody {
  purpose_key: string;
  subject_reference: string;
  regarding_entity?: string;
  regarding_id?: string;
  evidence?: string;
}

export interface ConsentRow {
  id: string;
  status: string;
}

/**
 * M24 (D-428): the one bespoke consent workflow the generic entity CRUD
 * engine can't express — an explicit withdrawal, always a NEW `audit_consent`
 * row, never an update of the row that recorded the grant. Ordinary reads
 * and an authenticated "grant" (a plain `create` of a `granted` row) go
 * through `EntityService` against `audit_consent`/`audit_consent_purpose`
 * directly, same as any other registered entity — see
 * `ConsentPanelComponent`.
 */
@Injectable({ providedIn: 'root' })
export class ConsentAdminService {
  private readonly api = inject(ApiService);

  withdraw(body: WithdrawConsentBody): Observable<ConsentRow> {
    return this.api.post<ConsentRow>('/api/v1/consents/withdraw', body);
  }
}
