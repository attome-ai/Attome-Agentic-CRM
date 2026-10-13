import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
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

  listLogs(clientId: string, limit = 50, offset = 0): Observable<AccessLogPage> {
    return this.api.get<AccessLogPage>(`/api/v1/admin/s2s/clients/${clientId}/logs`, {
      limit: String(limit), offset: String(offset),
    });
  }
}
