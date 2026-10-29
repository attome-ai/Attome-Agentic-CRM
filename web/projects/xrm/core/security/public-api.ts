// Admin-only grant/role/team/record-share administration. MyAccessComponent and
// MfaSettingsComponent deliberately live in @attome/xrm/access instead, not here
// — see that entry's comment (P-frontend-hardening step 5).

// ── Security model (privilege grants, roles, field security — D-111) ───────
// The direct-user-grants page (privilege-grants.component.ts, `/xrm/admin/
// security/grants`) was removed 2026-08-19: it was a flat cross-user list of
// the same `user_account_mm_privilege` junction the User form's own
// "Privileges" tab now edits scoped to one user. That tab was first a bespoke
// `UserPrivilegesPanelComponent` talking to `ApiService` directly; it was
// itself replaced by an ordinary `xrm-related-grid` m2m subgrid once the
// junction was registered as an entity (same pattern the Teams tab already
// used), so `listGrants`/`createGrant`/`deleteGrant`/`GrantItem`/
// `CreateGrantBody` went with it — the generic entity API covers reads and
// writes, and `attome-api::entity_crud::access::invalidate_privilege_grant_target`
// keeps the immediate-cache-invalidation guarantee `/api/v1/admin/security/
// grants` (still live, `attome-security/src/admin/grants.rs`) provides.
export { SecurityAdminService }         from './security-admin.service';
export { FieldSecurityProfilesComponent } from './field-security-profiles.component';
export type {
  PrivilegeItem,
  RoleItem, CreateRoleBody, UpdateRoleBody, RoleUserItem,
  RoleGrantItem, CreateRoleGrantBody,
  RoleGrantConditionItem, CreateConditionBody,
  FieldSecurityProfileItem, CreateFieldSecurityProfileBody,
  FieldSecurityProfileFieldItem, SetFieldProfileFieldBody,
} from './security-admin.service';
export { CONDITION_OPERATORS } from './security-admin.service';

// D-369/D-371/D-372 (2026-08-18): the unified Role form — General/Privilege
// Grants/Record Access/Assignments/Notes — additive to the remaining flat
// pages above, not a replacement for them. (The flat role-privileges page
// was removed 2026-08-19: it was a strict subset of this form's Privilege
// Grants tab, same API, no cross-role view worth keeping.) The list itself
// is no longer a custom component: role is a registered entity (D-372), so
// EntityRouterComponent's generic list serves `/xrm/core/role/list`; this
// form stays a literal route override (`core/role/form`) ahead of that
// wildcard, same idiom as `dashboard/form`.
export { RoleFormComponent }            from './role-form.component';

// ── RLS/team/share administration UI (D-133/D-134 record-level security) ───
export { SecurityAdminOverviewComponent } from './security-admin-overview.component';
export { RoleEntityAccessComponent }      from './role-entity-access.component';
export { UserAccessComponent }            from './user-access.component';
export { UsersListComponent }             from './users-list.component';
export { OrganizationsListComponent }     from './organizations-list.component';
export { RecordSharesComponent }          from './record-shares.component';
// Q5-T10: second-factor coverage.
export { MfaCoverageComponent }           from './mfa-coverage.component';
export { MFA_FACTORS, MFA_MODES, WEAK_MFA_FACTORS } from './security-admin.service';
export type { RoleAuthPolicy, RoleAuthPolicyBody, MfaCoverageRow, MfaCoverageSummary } from './security-admin.service';
// Q8-T9: an administrator's sessions screen (Q8-T5 routes).
export { SessionsAdminComponent }         from './sessions-admin.component';
export type { AdminSessionItem, SessionsEnded } from './security-admin.service';
// Q1-T14: the sign-in provider screens.
export { OidcProvidersComponent }         from './oidc-providers.component';
export { OidcProviderFormComponent, applyPreset, bodyOf, draftOf, emptyDraft } from './oidc-provider-form.component';
export type { OidcDraft, OidcTab } from './oidc-provider-form.component';
export type {
  RoleEntityAccessItem, UpsertEntityAccessGrantBody,
  UserRoleItem, AssignUserRoleBody, UserListItem,
  TeamItem, CreateTeamBody, TeamMemberItem, AddTeamMemberBody, TeamRoleItem,
  OrganizationItem, OrganizationMemberItem, AddOrganizationMemberBody,
  ShareCapability, RecordShareItem, CreateRecordShareBody,
  ReassignOwnerBody, OwnerItem,
  EntityDefaultShareItem, CreateEntityDefaultShareBody,
  EffectiveAccessPreview, ConfiguredAccess, EffectiveAccess,
  EffectiveAccessRoleRef, EffectiveAccessTeamRef, EffectiveAccessOrgRef,
} from './security-admin.service';
export { ACCESS_LEVELS, SECURITY_FLAGS, endOfDay, operationLevelsOf } from './security-admin.service';
// Q10-T12: the types the access-admin entry point's pages use; the pages
// themselves are `@attome/xrm/core/security/access-admin`.
export type {
  PermissionSetItem, PermissionSetDetail, SetEntityAccessItem, PermissionSetAssignment,
  ConflictRule, CurrentConflict, RoleTemplateItem, InstalledRole,
} from './security-admin.service';

// The `user_account` form override (UserFormComponent) and
// registerSecurityEntityForms live in
// `@attome/xrm/core/security/registration` instead of here — a separate,
// lighter entry point so registering the override doesn't force this
// entry's heavier admin pages into the same eager chunk. See that entry's
// public-api.ts doc comment.

// Q11-T1: access review campaigns, decisions with reasons, and CSV evidence.
export { AccessReviewsComponent } from './access-reviews/access-reviews.component';
export { AccessReviewsService, evidenceCsv } from './access-reviews/access-reviews.service';
export type {
  AccessReviewCampaign, AccessReviewItem, AccessReviewDecision,
} from './access-reviews/access-reviews.service';
// Q6-T2: the person's own passkeys.
export { PasskeysComponent, PASSKEY_MANAGE, type MyPasskey } from './passkeys/passkeys.component';
