import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Wire types (mirror attome_service::portal exactly) ────────────────────────

export interface PublicOffering {
  id:           string;
  name:         string;
  category:     string | null;
  description:  string | null;
  fulfilment:   string;
}

export interface PortalStatus {
  title:                  string;
  status:                 string;
  resolved_entity_name:   string | null;
}

/**
 * The public, anonymous self-service portal client — deliberately separate
 * from `ServiceAdminService` (which always sends credentials and hits the
 * authenticated `/api/v1/service-offering/*` routes): this calls the bypass
 * routes (`/api/v1/service-portal/*`) that never require a session, same
 * split `ContentPublicService` already establishes for
 * `@attome/xrm/content/view`.
 */
@Injectable({ providedIn: 'root' })
export class ServicePortalService {
  private readonly api = inject(ApiService);

  listPublicOfferings(): Observable<PublicOffering[]> {
    return this.api.get<PublicOffering[]>('/api/v1/service-portal/offerings');
  }

  lookupStatus(token: string): Observable<PortalStatus> {
    return this.api.get<PortalStatus>('/api/v1/service-portal/status', { token });
  }
}
