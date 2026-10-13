import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Wire types (mirror attome_service::offering exactly) ─────────────────────

export interface OfferingSummary {
  id:               string;
  name:             string;
  category:         string | null;
  description:      string | null;
  default_priority: string;
  /** `ticket | task | project | workflow:<def>`. */
  fulfilment:       string;
}

export interface CreateWorkRequestFromOfferingRequest {
  title:         string;
  description:   string | null;
  request_type:  string;
  requester_id:  string;
}

export interface CreateWorkRequestFromOfferingResponse {
  work_request_id: string;
  status:           string;
  /** `{public_id}.{secret}` — shown to the requester exactly once. */
  portal_token:     string;
}

/**
 * The internal "New Request" picker's client — authenticated, distinct from
 * `ServicePortalService` (which calls the anonymous, bypass
 * `/api/v1/service-portal/*` routes). This one calls the catalog +
 * create-from-offering routes (`attome_service::offering`), which stay
 * license/privilege-gated like any other admin surface.
 */
@Injectable({ providedIn: 'root' })
export class ServiceAdminService {
  private readonly api = inject(ApiService);

  listActiveOfferings(): Observable<OfferingSummary[]> {
    return this.api.get<OfferingSummary[]>('/api/v1/service-offering/active');
  }

  createWorkRequestFromOffering(
    offeringId: string,
    body: CreateWorkRequestFromOfferingRequest,
  ): Observable<CreateWorkRequestFromOfferingResponse> {
    return this.api.post<CreateWorkRequestFromOfferingResponse>(
      `/api/v1/service-offering/${offeringId}/create-work-request`,
      body,
    );
  }
}
