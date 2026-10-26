import { inject, Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Response types (mirror s2s_admin.rs exactly) ──────────────────────────────

export interface ClientListItem {
  id:             string;
  client_id:      string;
  name:           string;
  status:         string;
  rate_limit_rpm: number;
  last_used_at:   string | null;
  created_at:     string;
  key_slots:      string[];
  /** S11-T4: the person answerable for the client. */
  owner_user_ref: string | null;
  owner_email:    string | null;
  purpose:        string | null;
  environment:    S2sEnvironment | null;
  expires_at:     string | null;
  /** S11-T6: how the client can authenticate. */
  methods:        S2sMethod[];
}

/** S11-T4: the environments a client may be declared for. */
export type S2sEnvironment = 'production' | 'staging' | 'development' | 'test';
export const S2S_ENVIRONMENTS: readonly S2sEnvironment[] = ['production', 'staging', 'development', 'test'];

/** S11-T6: `key` (an HMAC key, also the client secret), `public_key` (S11-T1), `identity_provider` (S11-T2). */
export type S2sMethod = 'key' | 'public_key' | 'identity_provider';

/** S11-T2: a trusted identity provider of a client. */
export interface TrustItem {
  id:         string;
  issuer:     string;
  audience:   string;
  subject:    string;
  jwks_uri:   string;
  created_at: string;
}

export interface CreateTrustBody {
  issuer:   string;
  audience: string;
  subject:  string;
  jwks_uri: string;
}

export interface KeySummary {
  slot:         string;
  public_id:    string;
  status:       string;
  secret_last4: string | null;
  created_at:   string;
  expires_at:   string | null;
  last_used_at: string | null;
}

export interface PermissionItem {
  id:          string;
  entity_name: string;
  can_read:    boolean;
  can_create:  boolean;
  can_update:  boolean;
  can_delete:  boolean;
  can_export:  boolean;
  can_bulk:    boolean;
}

export interface ClientDetail {
  id:                 string;
  client_id:          string;
  name:               string;
  description:        string | null;
  status:             string;
  service_user_ref:   string | null;
  rate_limit_rpm:     number;
  max_concurrent:     number;
  allowed_cidrs:      string[] | null;
  max_payload_bytes:  number;
  auto_disable_days:  number;
  /** S1-T10: may name a user to act as (`x-attome-act-as`). */
  can_act_as_user:    boolean;
  /** S11-T1: whether a public key for OAuth token assertions is set. */
  oauth_public_key_set: boolean;
  /** S11-T1: the scopes an OAuth access token may carry. */
  oauth_scopes:       string[];
  /** S11-T4: the service-account fields. */
  owner_user_ref:     string | null;
  purpose:            string | null;
  environment:        S2sEnvironment | null;
  expires_at:         string | null;
  last_used_at:       string | null;
  row_version:        number;
  created_at:         string;
  updated_at:         string;
  keys:               KeySummary[];
  permissions:        PermissionItem[];
}

export interface KeyCreatedResponse {
  public_id:  string;
  slot:       string;
  /** Raw HMAC secret — shown exactly once, never retrievable again. */
  secret:     string;
  expires_at: string | null;
  created_at: string;
}

export interface AccessLogItem {
  id:               string;
  method:           string;
  path:             string;
  status_code:      number | null;
  response_time_ms: number | null;
  correlation_id:   string | null;
  ip_address:       string | null;
  nonce:            string | null;
  error_code:       string | null;
  created_at:       string;
}

export interface AccessLogPage {
  items:  AccessLogItem[];
  total:  number;
  limit:  number;
  offset: number;
}

// ── Request bodies ─────────────────────────────────────────────────────────────

export interface CreateClientBody {
  client_id:          string;
  name:               string;
  description?:       string;
  service_user_ref?:  string;
  rate_limit_rpm?:    number;
  max_concurrent?:    number;
  allowed_cidrs?:     string[];
  max_payload_bytes?: number;
  auto_disable_days?: number;
  can_act_as_user?:   boolean;
  /** S11-T4: the caller when omitted. */
  owner_user_ref?:    string;
  purpose?:           string;
  environment?:       S2sEnvironment;
  expires_at?:        string;
}

export interface UpdateClientBody {
  name?:               string;
  description?:        string;
  status?:             string;
  rate_limit_rpm?:     number;
  max_concurrent?:     number;
  allowed_cidrs?:      string[];
  max_payload_bytes?:  number;
  auto_disable_days?:  number;
  can_act_as_user?:    boolean;
  /** S11-T1: a PEM public key; an empty string removes it. */
  oauth_public_key_pem?: string;
  oauth_scopes?:       string[];
  /** S11-T4: the service-account fields; omitted ones are kept. */
  purpose?:            string;
  environment?:        S2sEnvironment;
  expires_at?:         string;
  row_version:         number;
}

export interface GenerateKeyBody {
  slot:        string;
  expires_at?: string;
}

export interface SetPermissionBody {
  entity_name: string;
  can_read?:   boolean;
  can_create?: boolean;
  can_update?: boolean;
  can_delete?: boolean;
  can_export?: boolean;
  can_bulk?:   boolean;
}

@Injectable({ providedIn: 'root' })
export class S2sAdminService {
  private readonly api = inject(ApiService);

  listClients(status?: string): Observable<ClientListItem[]> {
    return this.api.getAllPages<ClientListItem>('/api/v1/admin/s2s/clients', status ? { status } : {});
  }

  createClient(body: CreateClientBody): Observable<ClientDetail> {
    return this.api.post<ClientDetail>('/api/v1/admin/s2s/clients', body);
  }

  getClient(id: string): Observable<ClientDetail> {
    return this.api.get<ClientDetail>(`/api/v1/admin/s2s/clients/${id}`);
  }

  updateClient(id: string, body: UpdateClientBody): Observable<ClientDetail> {
    return this.api.patch<ClientDetail>(`/api/v1/admin/s2s/clients/${id}`, body);
  }

  deleteClient(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/s2s/clients/${id}`);
  }

  generateKey(clientId: string, body: GenerateKeyBody): Observable<KeyCreatedResponse> {
    return this.api.post<KeyCreatedResponse>(`/api/v1/admin/s2s/clients/${clientId}/keys`, body);
  }

  revokeKey(clientId: string, slot: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/s2s/clients/${clientId}/keys/${slot}`);
  }

  listPermissions(clientId: string): Observable<PermissionItem[]> {
    return this.api.get<PermissionItem[]>(`/api/v1/admin/s2s/clients/${clientId}/permissions`);
  }

  setPermission(clientId: string, body: SetPermissionBody): Observable<PermissionItem> {
    return this.api.post<PermissionItem>(`/api/v1/admin/s2s/clients/${clientId}/permissions`, body);
  }

  deletePermission(clientId: string, entityName: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/s2s/clients/${clientId}/permissions/${entityName}`);
  }

  listTrusts(clientId: string): Observable<TrustItem[]> {
    return this.api
      .get<{ items: TrustItem[] }>(`/api/v1/admin/s2s/clients/${clientId}/trusts`)
      .pipe(map(page => page.items));
  }

  createTrust(clientId: string, body: CreateTrustBody): Observable<TrustItem> {
    return this.api.post<TrustItem>(`/api/v1/admin/s2s/clients/${clientId}/trusts`, body);
  }

  deleteTrust(clientId: string, trustId: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/s2s/clients/${clientId}/trusts/${trustId}`);
  }

  listLogs(clientId: string, limit = 50, offset = 0): Observable<AccessLogPage> {
    return this.api.get<AccessLogPage>(`/api/v1/admin/s2s/clients/${clientId}/logs`, {
      limit: String(limit), offset: String(offset),
    });
  }
}
