import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService, Page } from '@attome/base';

// Wire types of the web portal admin API (`crates/engine/attome-portal/src/admin.rs`,
// `roles.rs`, `provision.rs`). Every route is `system.admin` only.

export type PortalType = 'anonymous' | 'authenticated' | 'mixed';
export type PortalUserStatus = 'invited' | 'active' | 'disabled';
/** `ConditionSpec.operator` (roles.rs). */
export type ConditionOperator = 'eq' | 'ne' | 'gt' | 'lt' | 'gte' | 'lte' | 'in';
export const CONDITION_OPERATORS: readonly ConditionOperator[] = ['eq', 'ne', 'gt', 'lt', 'gte', 'lte', 'in'];

export interface PortalDetail {
  id: string;
  name: string;
  description?: string | null;
  keyword: string;
  portal_type: PortalType;
  is_enabled: boolean;
  owning_team_ref: string | null;
  mfa_policy: 'optional' | 'required';
  row_version: number;
}

export interface NewPortal {
  name: string;
  keyword: string;
  portal_type: PortalType;
  is_enabled: boolean;
  owning_team_ref?: string | null;
}

export interface PortalUserDetail {
  id: string;
  webportal_id: string;
  name: string;
  /** D-777: null when the user signs in with a username only. */
  email: string | null;
  /** D-777: the login username, when the user has one. */
  username: string | null;
  status: PortalUserStatus;
  row_version: number;
}

export interface RoleSummary {
  id: string;
  name: string;
  user_count: number;
}

export interface ConditionSpec {
  field: string;
  operator: ConditionOperator;
  value?: unknown;
  value_ref?: string | null;
}

export interface FieldSpec {
  field: string;
  can_read: boolean;
  can_write: boolean;
  can_filter: boolean;
  allow_sensitive?: boolean;
}

export interface GrantSpec {
  can_read: boolean;
  can_create: boolean;
  can_update: boolean;
  can_delete: boolean;
  conditions: ConditionSpec[];
  fields: FieldSpec[];
}

export interface GrantView extends GrantSpec {
  entity: string;
  /** A read-only, literal-only grant (G-3). */
  public: boolean;
}

export interface RoleView {
  id: string;
  webportal_id: string;
  name: string;
  user_count: number;
  grants: GrantView[];
}

export interface EntityConfigView {
  entity: string;
  portal_user_field: string | null;
}

export interface ErasureRequest {
  id: string;
  webportal_user_id: string;
  status: 'open' | 'completed' | 'rejected';
  requested_at: string;
  handled_by: string | null;
  handled_at: string | null;
}

export interface InvitationSent {
  expires_at: string;
}

export interface ExportScope {
  entity_logicalname: string;
  object_key: string;
  checksum: string;
  exported_rows: number;
  withheld_for_legal_hold: number;
}

/** G-14: the DSR access request the export recorded and fulfilled. */
export interface ExportResult {
  id: string;
  status: string;
  scopes: ExportScope[];
}

export type MfaPolicy = 'optional' | 'required';

/**
 * `PATCH …/{id}/settings` body (`provision.rs::PortalSettingsPatch`): only the
 * keys sent change; `owning_team_ref: null` clears the team. Optimistic
 * concurrency through `row_version`.
 */
export interface PortalSettingsPatch {
  row_version: number;
  keyword?: string;
  portal_type?: PortalType;
  is_enabled?: boolean;
  owning_team_ref?: string | null;
  mfa_policy?: MfaPolicy;
}

/** `policy.rs::SignupMode`. */
export type SignupMode = 'invite_only' | 'self_service' | 'domain_allowlist';
export const SIGNUP_MODES: readonly SignupMode[] = ['invite_only', 'self_service', 'domain_allowlist'];

/** `GET`/`PUT …/{id}/auth-policy` (`policy.rs::AuthPolicy`). */
export interface AuthPolicy {
  signup_mode: SignupMode;
  signup_domains: string[];
  signup_role_ref: string | null;
  oidc_providers: string[];
  terms_version: string | null;
  privacy_version: string | null;
  /** Never a lookup, file, formula, sensitive or identity field (D-588, G-17): the server refuses them. */
  editable_profile_fields: string[];
  page_size_cap: number;
  allowed_cidrs: string[];
  records_rpm: number;
  /** D-777: username length (defaults 3 and 12). */
  username_min_len: number;
  username_max_len: number;
  /** D-777: refused anywhere in a username (case-insensitive). */
  username_blocked_words: string[];
  /** D-777: refused as a whole username (case-insensitive). */
  username_reserved: string[];
  /** D-779: the portal's own servers may sign users in and create accounts. */
  trusted_server_login: boolean;
  row_version: number;
}

/** `GET /api/v1/admin/security/teams` row (`attome-security/src/admin/teams.rs`). */
export interface TeamOption {
  id: string;
  name: string;
}

const BASE = '/api/v1/admin/webportals';
/** Page size of the users list; the screen pages past it with "Load more". */
export const USERS_PAGE_SIZE = 200;

@Injectable({ providedIn: 'root' })
export class PortalAdminService {
  private readonly api = inject(ApiService);

  listPortals(): Observable<Page<PortalDetail>> {
    return this.api.get<Page<PortalDetail>>(BASE, { page: '1', page_size: '200' });
  }

  createPortal(body: NewPortal): Observable<PortalDetail> {
    return this.api.post<PortalDetail>(BASE, body);
  }

  /** One-based page of a portal's users. */
  listUsers(portalId: string, page = 1): Observable<Page<PortalUserDetail>> {
    return this.api.get<Page<PortalUserDetail>>(
      `${BASE}/${portalId}/users`, { page: String(page), page_size: String(USERS_PAGE_SIZE) });
  }

  /**
   * Teams for the owning-team picker. The same endpoint as
   * `SecurityAdminService.listTeams`, called here because that service sits in
   * the `@attome/xrm/core/security` component barrel, which a sibling entry
   * point must not import (D-314).
   */
  listTeams(): Observable<TeamOption[]> {
    return this.api.getAllPages<TeamOption>('/api/v1/admin/security/teams');
  }

  /** D-777: at least one of `email` and `username`. */
  createUser(
    portalId: string,
    body: { name: string; email?: string; username?: string },
  ): Observable<PortalUserDetail> {
    return this.api.post<PortalUserDetail>(`${BASE}/${portalId}/users`, body);
  }

  inviteUser(portalId: string, userId: string): Observable<InvitationSent> {
    return this.api.post<InvitationSent>(`${BASE}/${portalId}/users/${userId}/invite`, {});
  }

  setUserEnabled(portalId: string, userId: string, enabled: boolean): Observable<PortalUserDetail> {
    return this.api.post<PortalUserDetail>(
      `${BASE}/${portalId}/users/${userId}/${enabled ? 'enable' : 'disable'}`, {});
  }

  assignRole(portalId: string, userId: string, roleId: string): Observable<void> {
    return this.api.put<void>(`${BASE}/${portalId}/users/${userId}/role`, { role_id: roleId });
  }

  exportUser(portalId: string, userId: string): Observable<ExportResult> {
    return this.api.post<ExportResult>(`${BASE}/${portalId}/users/${userId}/export`, {});
  }

  eraseUser(portalId: string, userId: string): Observable<{ erasure_request_id: string }> {
    return this.api.post<{ erasure_request_id: string }>(`${BASE}/${portalId}/users/${userId}/erase`, {});
  }

  listRoles(portalId: string): Observable<Page<RoleSummary>> {
    return this.api.get<Page<RoleSummary>>(`${BASE}/${portalId}/roles`);
  }

  getRole(portalId: string, roleId: string): Observable<RoleView> {
    return this.api.get<RoleView>(`${BASE}/${portalId}/roles/${roleId}`);
  }

  createRole(portalId: string, name: string): Observable<RoleSummary> {
    return this.api.post<RoleSummary>(`${BASE}/${portalId}/roles`, { name });
  }

  putGrant(portalId: string, roleId: string, entity: string, grant: GrantSpec): Observable<void> {
    return this.api.put<void>(
      `${BASE}/${portalId}/roles/${roleId}/grants/${encodeURIComponent(entity)}`, grant);
  }

  deleteGrant(portalId: string, roleId: string, entity: string): Observable<void> {
    return this.api.delete(`${BASE}/${portalId}/roles/${roleId}/grants/${encodeURIComponent(entity)}`);
  }

  listEntityConfigs(portalId: string): Observable<Page<EntityConfigView>> {
    return this.api.get<Page<EntityConfigView>>(`${BASE}/${portalId}/entities`);
  }

  putEntityConfig(portalId: string, entity: string, portalUserField: string | null): Observable<void> {
    return this.api.put<void>(
      `${BASE}/${portalId}/entities/${encodeURIComponent(entity)}`, { portal_user_field: portalUserField });
  }

  listErasureRequests(portalId: string): Observable<Page<ErasureRequest>> {
    return this.api.get<Page<ErasureRequest>>(`${BASE}/${portalId}/erasure-requests`, { page: '1', page_size: '200' });
  }

  rejectErasureRequest(portalId: string, requestId: string): Observable<void> {
    return this.api.post<void>(`${BASE}/${portalId}/erasure-requests/${requestId}/reject`, {});
  }

  updateSettings(portalId: string, patch: PortalSettingsPatch): Observable<PortalDetail> {
    return this.api.patch<PortalDetail>(`${BASE}/${portalId}/settings`, patch);
  }

  getAuthPolicy(portalId: string): Observable<AuthPolicy> {
    return this.api.get<AuthPolicy>(`${BASE}/${portalId}/auth-policy`);
  }

  putAuthPolicy(portalId: string, policy: AuthPolicy): Observable<AuthPolicy> {
    return this.api.put<AuthPolicy>(`${BASE}/${portalId}/auth-policy`, policy);
  }

  renameRole(portalId: string, roleId: string, name: string): Observable<void> {
    return this.api.patch<void>(`${BASE}/${portalId}/roles/${roleId}`, { name });
  }

  /** Refused (409) while any user holds the role or the signup policy hands it out. */
  deleteRole(portalId: string, roleId: string): Observable<void> {
    return this.api.delete(`${BASE}/${portalId}/roles/${roleId}`);
  }

  /** 404 when the user holds no role in this portal. */
  unassignRole(portalId: string, userId: string): Observable<void> {
    return this.api.delete(`${BASE}/${portalId}/users/${userId}/role`);
  }
}
