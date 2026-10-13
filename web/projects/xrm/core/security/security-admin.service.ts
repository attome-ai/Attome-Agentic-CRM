import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService, Page } from '@attome/base';
import { RecordSharingService } from '@attome/xrm/core/entity';

// P-api-contract (C-26): every interface in this file used to be hand-written
// and had drifted from `crates/engine/attome-security/src/admin/*.rs`'s actual wire
// shapes (entity.service.ts's doc comment describes the same pattern this
// migration closes). Each is now `ApiComponents['schemas']['<Name>']` — the
// generated OpenAPI schema for that Rust struct — checked one at a time
// against its owning `admin/*.rs` file so a same-named-but-different schema
// never gets aliased by accident (see `RelationshipDef`'s doc comment in
// `admin.service.ts` for a real example of that trap in a sibling file).

export type PrivilegeItem = ApiComponents['schemas']['PrivilegeItem'];

// D-111: roles replace jobs as the grant-bundling concept (supersedes
// D-011/D-012). See DECISIONS.md.
export type RoleItem = ApiComponents['schemas']['RoleItem'];
export type CreateRoleBody = ApiComponents['schemas']['CreateRoleBody'];

// `position_hierarchy_enabled` deliberately excluded — it has its own
// dedicated endpoint (`updateRolePositionHierarchy` below) because toggling
// it invalidates every current holder's cached SecurityContext.
export type UpdateRoleBody = ApiComponents['schemas']['UpdateRoleBody'];

// D-369 (Assignments tab): reverse of `listUserRoles` — every user directly
// holding a role, not just the roles a given user holds.
export type RoleUserItem = ApiComponents['schemas']['RoleUserItem'];

// D-133/D-134/D-136: per-(role, entity) record-level access-level ladder —
// None(0) < Team(1) < BusinessUnit(2) < Global(3). A role holding an
// entity's privilege but no row here defaults to Global (zero-behavior-
// change guarantee) for that entity's read/write/delete depth.
export type RoleEntityAccessItem = ApiComponents['schemas']['RoleEntityAccessItem'];
export type UpsertEntityAccessGrantBody = ApiComponents['schemas']['UpsertEntityAccessGrantBody'];

// Display labels only — the underlying `value` sent to the API is unchanged
// (0=None/1=Team/2=BusinessUnit/3=Global, D-133/D-136). Relabeled per
// explicit request: value 0 as "User" (self-scoped), value 2 as
// "Organization" (was briefly "Team", which collided with value 1 — fixed).
//
// C-29 (M01 §7): `label` used to be the literal English display text. It is
// now an i18n catalog key (`security.accessLevel.*`, en.catalog.ts/
// ar.catalog.ts) — every consumer routes it through `| translate` (a
// template pipe) or `LangService.translate()` (a method that returns
// display text, e.g. `levelLabel()`) rather than rendering it directly.
export const ACCESS_LEVELS: { value: number; label: string }[] = [
  { value: 0, label: 'security.accessLevel.user' },
  { value: 1, label: 'security.accessLevel.team' },
  { value: 2, label: 'security.accessLevel.organization' },
  { value: 3, label: 'security.accessLevel.global' },
];

// Direct user -> role assignment (2026-07-27 addition, closes the D-134 gap
// noted in the security-model skill — team-mediated assignment already
// existed via add_team_role).
export type UserRoleItem = ApiComponents['schemas']['UserRoleItem'];
export type AssignUserRoleBody = ApiComponents['schemas']['AssignUserRoleBody'];
export type UserListItem = ApiComponents['schemas']['UserListItem'];

// D-133 Phase 4: teams are pure people-groupings; roles attach to a team
// ("everyone on Finance gets Finance Role") alongside direct user->role
// assignment above, not a hierarchy.
export type TeamItem = ApiComponents['schemas']['TeamItem'];
export type CreateTeamBody = ApiComponents['schemas']['CreateTeamBody'];
export type TeamMemberItem = ApiComponents['schemas']['TeamMemberItem'];
export type AddTeamMemberBody = ApiComponents['schemas']['AddTeamMemberBody'];
export type TeamRoleItem = ApiComponents['schemas']['TeamRoleItem'];

// D-133 (3): BusinessUnit-tier membership. Organization records themselves
// are managed via the generic entity route (/xrm/core/organization/list);
// this is only the user<->org membership edge.
export type OrganizationItem = ApiComponents['schemas']['OrganizationItem'];
export type OrganizationMemberItem = ApiComponents['schemas']['OrganizationMemberItem'];
export type AddOrganizationMemberBody = ApiComponents['schemas']['AddOrganizationMemberBody'];

// D-133 (4): capability is the coarse view/action/deny axis a
// core_record_share or core_entity_default_share row grants — independent
// of the read/write/delete access-level ladder above. This one stays a
// hand-written literal union deliberately: it is a UI value list (the
// `<select>` in `record-shares.component.ts`), not a duplicate of a wire
// type — the backend's own `capability` column is an untyped `String`
// (`shares.rs`), so the generated schema for it is a bare `string` with no
// vocabulary to alias.
export type ShareCapability = 'view' | 'action' | 'deny';

export type RecordShareItem = ApiComponents['schemas']['RecordShareItem'];
export type CreateRecordShareBody = ApiComponents['schemas']['CreateRecordShareBody'];

export type ReassignOwnerBody = ApiComponents['schemas']['ReassignOwnerBody'];
export type OwnerItem = ApiComponents['schemas']['OwnerItem'];

export type EntityDefaultShareItem = ApiComponents['schemas']['EntityDefaultShareItem'];
export type CreateEntityDefaultShareBody = ApiComponents['schemas']['CreateEntityDefaultShareBody'];

// The "configured vs. effective" preview (RLS admin UI requirement): raw
// assignments (with display names attached) alongside what they actually
// resolve to, right now, uncached.
export type EffectiveAccessRoleRef = ApiComponents['schemas']['EffectiveAccessRoleRef'];
export type EffectiveAccessTeamRef = ApiComponents['schemas']['EffectiveAccessTeamRef'];
export type EffectiveAccessOrgRef = ApiComponents['schemas']['EffectiveAccessOrgRef'];
export type ConfiguredAccess = ApiComponents['schemas']['ConfiguredAccess'];
export type EffectiveAccess = ApiComponents['schemas']['EffectiveAccess'];
export type EffectiveAccessPreview = ApiComponents['schemas']['EffectiveAccessPreview'];

export type RoleGrantItem = ApiComponents['schemas']['RoleGrantItem'];
export type CreateRoleGrantBody = ApiComponents['schemas']['CreateRoleGrantBody'];

// D-369: bounded per-grant record conditions. `value` is a JSON scalar
// (string/number/boolean) for every operator except `in`, which takes a JSON
// array of scalars.
//
// C-29 (M01 §7): `label` is an i18n catalog key (`security.conditionOperator.*`)
// — see `ACCESS_LEVELS`'s comment above for the convention.
export const CONDITION_OPERATORS: { value: number; label: string }[] = [
  { value: 0, label: 'security.conditionOperator.equals' },
  { value: 1, label: 'security.conditionOperator.notEquals' },
  { value: 2, label: 'security.conditionOperator.greaterThan' },
  { value: 3, label: 'security.conditionOperator.lessThan' },
  { value: 4, label: 'security.conditionOperator.greaterThanOrEqual' },
  { value: 5, label: 'security.conditionOperator.lessThanOrEqual' },
  { value: 6, label: 'security.conditionOperator.in' },
];

export type RoleGrantConditionItem = ApiComponents['schemas']['RoleGrantConditionItem'];
export type CreateConditionBody = ApiComponents['schemas']['CreateConditionBody'];

// F013/F135 (D-111): field-security profiles — a named bundle of per-field
// read grants, assigned to roles.
export type FieldSecurityProfileItem = ApiComponents['schemas']['FieldSecurityProfileItem'];
export type CreateFieldSecurityProfileBody = ApiComponents['schemas']['CreateFieldSecurityProfileBody'];

// P-field-write-security (D-141): `can_update` is independent of `can_read`
// — a caller can hold either grant for a given (entity, field) pair without
// the other.
export type FieldSecurityProfileFieldItem = ApiComponents['schemas']['FieldSecurityProfileFieldItem'];
export type SetFieldProfileFieldBody = ApiComponents['schemas']['SetFieldProfileFieldBody'];

@Injectable({ providedIn: 'root' })
export class SecurityAdminService {
  private readonly api = inject(ApiService);
  // U7 Phase A: the record-share routes' one client wrapper now lives beside
  // the record form and list that also call them (`@attome/xrm/core/entity`).
  private readonly sharing = inject(RecordSharingService);

  listPrivileges(): Observable<PrivilegeItem[]> {
    return this.api.getAllPages<PrivilegeItem>('/api/v1/admin/security/privileges');
  }

  listRoles(): Observable<RoleItem[]> {
    return this.api.getAllPages<RoleItem>('/api/v1/admin/security/roles');
  }

  createRole(body: CreateRoleBody): Observable<RoleItem> {
    return this.api.post<RoleItem>('/api/v1/admin/security/roles', body);
  }

  updateRole(id: string, body: UpdateRoleBody): Observable<RoleItem> {
    return this.api.patch<RoleItem>(`/api/v1/admin/security/roles/${id}`, body);
  }

  /** The dedicated endpoint `updateRole` deliberately excludes — see `UpdateRoleBody`. */
  updateRolePositionHierarchy(id: string, enabled: boolean): Observable<void> {
    return this.api.put<void>(`/api/v1/admin/security/roles/${id}/position-hierarchy`, {
      position_hierarchy_enabled: enabled,
    });
  }

  listRoleUsers(roleId: string): Observable<RoleUserItem[]> {
    return this.api.getAllPages<RoleUserItem>(`/api/v1/admin/security/roles/${roleId}/users`);
  }

  listRoleGrants(): Observable<RoleGrantItem[]> {
    return this.api.getAllPages<RoleGrantItem>('/api/v1/admin/security/role-grants');
  }

  createRoleGrant(body: CreateRoleGrantBody): Observable<RoleGrantItem> {
    return this.api.post<RoleGrantItem>('/api/v1/admin/security/role-grants', body);
  }

  deleteRoleGrant(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/role-grants/${id}`);
  }

  // ── D-369: bounded per-grant record conditions ─────────────────────────

  listGrantConditions(grantId: string): Observable<RoleGrantConditionItem[]> {
    return this.api.get<RoleGrantConditionItem[]>(
      `/api/v1/admin/security/role-grants/${grantId}/conditions`,
    );
  }

  createGrantCondition(grantId: string, body: CreateConditionBody): Observable<RoleGrantConditionItem> {
    return this.api.post<RoleGrantConditionItem>(
      `/api/v1/admin/security/role-grants/${grantId}/conditions`,
      body,
    );
  }

  deleteGrantCondition(grantId: string, conditionId: string): Observable<void> {
    return this.api.delete(
      `/api/v1/admin/security/role-grants/${grantId}/conditions/${conditionId}`,
    );
  }

  listFieldProfiles(): Observable<FieldSecurityProfileItem[]> {
    return this.api.getAllPages<FieldSecurityProfileItem>('/api/v1/admin/security/field-profiles');
  }

  createFieldProfile(body: CreateFieldSecurityProfileBody): Observable<FieldSecurityProfileItem> {
    return this.api.post<FieldSecurityProfileItem>('/api/v1/admin/security/field-profiles', body);
  }

  listFieldProfileFields(profileId: string): Observable<FieldSecurityProfileFieldItem[]> {
    return this.api.getAllPages<FieldSecurityProfileFieldItem>(
      `/api/v1/admin/security/field-profiles/${profileId}/fields`,
    );
  }

  setFieldProfileField(
    profileId: string,
    body: SetFieldProfileFieldBody,
  ): Observable<FieldSecurityProfileFieldItem> {
    return this.api.post<FieldSecurityProfileFieldItem>(
      `/api/v1/admin/security/field-profiles/${profileId}/fields`,
      body,
    );
  }

  assignFieldProfile(profileId: string, roleId: string): Observable<void> {
    return this.api.post<void>(
      `/api/v1/admin/security/field-profiles/${profileId}/assignments`,
      { role_id: roleId },
    );
  }

  unassignFieldProfile(profileId: string, roleId: string): Observable<void> {
    return this.api.delete(
      `/api/v1/admin/security/field-profiles/${profileId}/assignments/${roleId}`,
    );
  }

  // ── Role x entity access-level grants ──────────────────────────────────

  listEntityAccessGrants(): Observable<RoleEntityAccessItem[]> {
    return this.api.getAllPages<RoleEntityAccessItem>('/api/v1/admin/security/role-entity-access');
  }

  upsertEntityAccessGrant(body: UpsertEntityAccessGrantBody): Observable<RoleEntityAccessItem> {
    return this.api.post<RoleEntityAccessItem>('/api/v1/admin/security/role-entity-access', body);
  }

  deleteEntityAccessGrant(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/role-entity-access/${id}`);
  }

  // ── Direct user -> role assignment ─────────────────────────────────────

  listUserRoles(userId: string): Observable<UserRoleItem[]> {
    return this.api.getAllPages<UserRoleItem>(`/api/v1/admin/security/users/${userId}/roles`);
  }

  assignUserRole(userId: string, body: AssignUserRoleBody): Observable<UserRoleItem> {
    return this.api.post<UserRoleItem>(`/api/v1/admin/security/users/${userId}/roles`, body);
  }

  removeUserRole(userId: string, roleId: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/users/${userId}/roles/${roleId}`);
  }

  // ── Teams: membership + team-role assignment ───────────────────────────

  listTeams(): Observable<TeamItem[]> {
    return this.api.getAllPages<TeamItem>('/api/v1/admin/security/teams');
  }

  createTeam(body: CreateTeamBody): Observable<TeamItem> {
    return this.api.post<TeamItem>('/api/v1/admin/security/teams', body);
  }

  deleteTeam(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/teams/${id}`);
  }

  listTeamMembers(teamId: string): Observable<TeamMemberItem[]> {
    return this.api.getAllPages<TeamMemberItem>(`/api/v1/admin/security/teams/${teamId}/members`);
  }

  addTeamMember(teamId: string, body: AddTeamMemberBody): Observable<TeamMemberItem> {
    return this.api.post<TeamMemberItem>(`/api/v1/admin/security/teams/${teamId}/members`, body);
  }

  removeTeamMember(teamId: string, userId: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/teams/${teamId}/members/${userId}`);
  }

  listTeamRoles(teamId: string): Observable<TeamRoleItem[]> {
    return this.api.getAllPages<TeamRoleItem>(`/api/v1/admin/security/teams/${teamId}/roles`);
  }

  addTeamRole(teamId: string, roleId: string): Observable<TeamRoleItem> {
    return this.api.post<TeamRoleItem>(`/api/v1/admin/security/teams/${teamId}/roles`, { role_id: roleId });
  }

  removeTeamRole(teamId: string, roleId: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/teams/${teamId}/roles/${roleId}`);
  }

  // ── Business units (organization membership) ───────────────────────────

  listOrganizations(): Observable<OrganizationItem[]> {
    return this.api.getAllPages<OrganizationItem>('/api/v1/admin/security/organizations');
  }

  listOrganizationMembers(orgId: string): Observable<OrganizationMemberItem[]> {
    return this.api.getAllPages<OrganizationMemberItem>(`/api/v1/admin/security/organizations/${orgId}/members`);
  }

  addOrganizationMember(orgId: string, body: AddOrganizationMemberBody): Observable<OrganizationMemberItem> {
    return this.api.post<OrganizationMemberItem>(`/api/v1/admin/security/organizations/${orgId}/members`, body);
  }

  removeOrganizationMember(orgId: string, userId: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/organizations/${orgId}/members/${userId}`);
  }

  // ── Record shares + entity-default shares (D-133 (4)) ──────────────────

  listRecordShares(entity: string, recordId: string): Observable<RecordShareItem[]> {
    return this.sharing.listRecordShares(entity, recordId);
  }

  createRecordShare(body: CreateRecordShareBody): Observable<RecordShareItem> {
    return this.sharing.createRecordShare(body);
  }

  deleteRecordShare(id: string): Observable<void> {
    return this.sharing.deleteRecordShare(id);
  }

  reassignOwner(body: ReassignOwnerBody): Observable<OwnerItem> {
    return this.sharing.reassignOwner(body);
  }

  listEntityDefaultShares(entity: string): Observable<EntityDefaultShareItem[]> {
    return this.api.getAllPages<EntityDefaultShareItem>('/api/v1/admin/security/entity-default-shares', { entity });
  }

  createEntityDefaultShare(body: CreateEntityDefaultShareBody): Observable<EntityDefaultShareItem> {
    return this.api.post<EntityDefaultShareItem>('/api/v1/admin/security/entity-default-shares', body);
  }

  deleteEntityDefaultShare(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/security/entity-default-shares/${id}`);
  }

  // ── Effective-access preview ────────────────────────────────────────────

  effectiveAccessPreview(userId: string): Observable<EffectiveAccessPreview> {
    return this.api.get<EffectiveAccessPreview>(`/api/v1/admin/security/users/${userId}/effective-access`);
  }

  // ── User lookup by email (shared by the pages below) ────────────────────

  /**
   * `page` is 1-indexed (D-793). Backend caps `page_size` at 200 (attome_types::MAX_PAGE_SIZE).
   * Returns the shared `Page<T>` envelope (`@attome/base`) instead of a
   * service-local `UserListPage` — C-26 (guidelines §12).
   */
  listUsers(page = 1, pageSize = 200): Observable<Page<UserListItem>> {
    return this.api.get<Page<UserListItem>>('/api/v1/admin/security/users', {
      page: String(page), page_size: String(pageSize),
    });
  }

  findUserByEmail(email: string): Observable<ApiComponents['schemas']['UserLookupItem'][]> {
    return this.api.get<ApiComponents['schemas']['UserLookupItem'][]>(
      '/api/v1/admin/security/users/lookup', { email },
    );
  }
}
