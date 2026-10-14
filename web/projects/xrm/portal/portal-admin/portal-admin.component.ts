import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Observable } from 'rxjs';
import { ApiError, ApiErrorKind, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { AdminService, AttributeMeta, EntityMeta } from '@attome/xrm/core/admin/data';

import {
  AuthPolicy,
  CONDITION_OPERATORS,
  ConditionOperator,
  EntityConfigView,
  ErasureRequest,
  FieldSpec,
  GrantSpec,
  MfaPolicy,
  PortalAdminService,
  PortalDetail,
  PortalSettingsPatch,
  PortalType,
  PortalUserDetail,
  RoleSummary,
  RoleView,
  SIGNUP_MODES,
  SignupMode,
  TeamOption,
} from '../portal-admin.service';

/** The entity a portal user field must look up onto (`roles.rs::put_entity_config`). */
const PORTAL_USER_ENTITY = 'webportal_user';

/**
 * Entities the server refuses to expose to a portal
 * (`attome-portal/src/roles.rs::DENIED_ENTITY_PREFIXES` and
 * `DENIED_CORE_ENTITIES`). Mirrored only to keep them out of the picker; the
 * server stays the authority.
 */
const DENIED_ENTITY_PREFIXES = [
  'audit_', 'ai_', 's2s_', 'notification_', 'integration_', 'webportal',
];
const DENIED_CORE_ENTITIES = new Set([
  'organization', 'team', 'user_account', 'user_account_mm_team', 'user_account_mm_privilege',
  'privilege', 'role', 'api_key', 'authentication_type', 'license', 'note', 'activity',
  'communication', 'communication_event', 'follow', 'tag_category', 'tag_item', 'glossary_term',
  'record_relationship', 'profiler_finding', 'autovalue', 'reminder', 'saved_search',
]);

/** How many conditions one grant takes (the grant API's limit, `roles.rs`). */
export const MAX_GRANT_CONDITIONS = 3;

interface ConditionDraft {
  field: string;
  operator: ConditionOperator;
  /** `value_ref` when it starts with `@portal_user.`, else a literal. */
  value: string;
}

interface GrantDraft {
  entity: string;
  can_read: boolean;
  can_create: boolean;
  can_update: boolean;
  can_delete: boolean;
  /** ANDed; a row with no field is ignored. */
  conditions: ConditionDraft[];
  fields: FieldSpec[];
}

function emptyCondition(): ConditionDraft {
  return { field: '', operator: 'eq', value: '@portal_user.id' };
}

function emptyGrant(): GrantDraft {
  return {
    entity: '', can_read: true, can_create: false, can_update: false, can_delete: false,
    conditions: [emptyCondition()],
    fields: [{ field: '', can_read: true, can_write: false, can_filter: false }],
  };
}

/** The editable portal settings (`PortalSettingsPatch` without the version). */
interface SettingsDraft {
  keyword: string;
  portal_type: PortalType;
  is_enabled: boolean;
  owning_team_ref: string;
  mfa_policy: MfaPolicy;
}

/** The auth policy with its lists as editable text (one item per line). */
interface PolicyDraft {
  signup_mode: SignupMode;
  signup_domains: string;
  signup_role_ref: string;
  oidc_providers: string;
  terms_version: string;
  privacy_version: string;
  editable_profile_fields: string;
  page_size_cap: number;
  allowed_cidrs: string;
  records_rpm: number;
  username_min_len: number;
  username_max_len: number;
  username_blocked_words: string;
  username_reserved: string;
  trusted_server_login: boolean;
}

/** A text box's lines (or comma-separated items), trimmed, blanks dropped. */
function lines(text: string): string[] {
  return text.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
}

/**
 * Web portal administration (web portal plan Phase 13 step 6, G-8/G-14): the
 * staff side of D-576 on the existing admin API — portals, users and
 * invitations, roles with their grants and field profile (the `public`
 * label shown), per-entity portal user field, erasure requests, and the
 * user data export (a DSR access request, fulfilled by attome-compliance).
 * Every route it calls is `system.admin` only and audited server-side.
 *
 * A grant takes up to three ANDed conditions. The portal's settings (type,
 * enabled, owning team, MFA policy, keyword) and its account policy (signup,
 * self-editable profile fields, page cap, address allowlist, request ceiling)
 * are edited here too, both under optimistic concurrency (`row_version`).
 * Roles can be renamed and deleted (the server refuses a role still held or
 * handed out by signup), and a user's role unassigned.
 *
 * Pickers (C9 friction): the owning team is a `<select>` over the teams list,
 * the entity a `<datalist>` over the entity metadata list (names shown,
 * logical name submitted), and the portal user field a `<select>` over that
 * entity's lookups onto `webportal_user`. The grant's condition and
 * field-profile inputs suggest the entity's fields but stay free text.
 */
@Component({
  selector: 'attome-portal-admin',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, LocalDatePipe],
  styleUrls: ['../../styles/admin-page.css', './portal-admin.component.css'],
  templateUrl: './portal-admin.component.html',
})
export class PortalAdminComponent {
  private readonly service = inject(PortalAdminService);
  private readonly lang = inject(LangService);
  private readonly dialog = inject(DialogService);
  private readonly admin = inject(AdminService);

  readonly operators = CONDITION_OPERATORS;
  readonly portalTypes: readonly PortalType[] = ['authenticated', 'mixed', 'anonymous'];
  readonly signupModes = SIGNUP_MODES;
  readonly mfaPolicies: readonly MfaPolicy[] = ['optional', 'required'];
  readonly maxConditions = MAX_GRANT_CONDITIONS;

  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  readonly portals = signal<PortalDetail[]>([]);
  readonly selected = signal<PortalDetail | null>(null);
  readonly users = signal<PortalUserDetail[]>([]);
  readonly roles = signal<RoleSummary[]>([]);
  readonly role = signal<RoleView | null>(null);
  readonly entityConfigs = signal<EntityConfigView[]>([]);
  readonly erasures = signal<ErasureRequest[]>([]);
  /** Users loaded so far vs. the API's total, for "Load more" past one page. */
  readonly usersTotal = signal(0);
  private usersPage = 1;

  readonly teams = signal<TeamOption[]>([]);
  private readonly allEntities = signal<EntityMeta[]>([]);
  /** Entities a portal may expose, by display name. */
  readonly entities = computed(() =>
    this.allEntities()
      .filter(e => e.is_active && !DENIED_CORE_ENTITIES.has(e.logicalname)
        && !DENIED_ENTITY_PREFIXES.some(p => e.logicalname.startsWith(p)))
      .sort((a, b) => a.name.localeCompare(b.name)));
  /** Lookups onto the portal user entity on the entity chosen in "Entity settings". */
  readonly portalUserFields = signal<AttributeMeta[]>([]);
  /** Field suggestions for the grant editor's entity. */
  readonly grantFields = signal<AttributeMeta[]>([]);

  newPortal = { name: '', keyword: '', portal_type: 'authenticated' as PortalType, is_enabled: true, owning_team_ref: '' };
  newUser = { name: '', email: '', username: '' };
  newRoleName = '';
  grant: GrantDraft = emptyGrant();
  entityConfig = { entity: '', portal_user_field: '' };
  /** Role picked per user row, before "Assign". */
  roleChoice: Record<string, string> = {};
  /**
   * Drafts as signals: they are filled by HTTP responses, and on this OnPush,
   * zoneless screen only a signal write schedules the render.
   */
  readonly settings = signal<SettingsDraft | null>(null);
  readonly policy = signal<AuthPolicy | null>(null);
  readonly policyDraft = signal<PolicyDraft | null>(null);
  roleName = '';

  constructor() {
    this.loadPortals();
    // Picker sources. A failure leaves the picker empty (the entity input
    // still takes a typed logical name) and shows the error like any other.
    this.service.listTeams().subscribe({ next: t => this.teams.set(t), error: e => this.fail(e) });
    this.admin.listEntities().subscribe({ next: e => this.allEntities.set(e), error: e => this.fail(e) });
  }

  // ── Portals ──────────────────────────────────────────────────────────────

  loadPortals(): void {
    this.loading.set(true);
    this.service.listPortals().subscribe({
      next: page => { this.portals.set(page.items); this.loading.set(false); },
      error: (err: ApiError) => { this.fail(err); this.loading.set(false); },
    });
  }

  createPortal(): void {
    const p = this.newPortal;
    this.run(this.service.createPortal({
      name: p.name.trim(),
      keyword: p.keyword.trim(),
      portal_type: p.portal_type,
      is_enabled: p.is_enabled,
      owning_team_ref: p.owning_team_ref.trim() || null,
    }), created => {
      this.portals.update(list => [created, ...list]);
      this.newPortal = { name: '', keyword: '', portal_type: 'authenticated', is_enabled: true, owning_team_ref: '' };
      this.select(created);
    });
  }

  select(portal: PortalDetail): void {
    this.selected.set(portal);
    this.role.set(null);
    this.grant = emptyGrant();
    this.grantFields.set([]);
    this.settings.set(settingsOf(portal));
    this.policy.set(null);
    this.policyDraft.set(null);
    // A response for a portal no longer selected is dropped: otherwise a late
    // answer for A would show (and save) A's policy under B.
    const id = portal.id;
    this.service.getAuthPolicy(id).subscribe({
      next: p => { if (this.selected()?.id === id) this.setPolicy(p); },
      error: e => this.fail(e),
    });
    this.refreshPortal();
  }

  // ── Settings and account policy ──────────────────────────────────────────

  saveSettings(): void {
    const portal = this.selected();
    const d = this.settings();
    if (!portal || !d) return;
    const patch: PortalSettingsPatch = {
      row_version: portal.row_version,
      portal_type: d.portal_type,
      is_enabled: d.is_enabled,
      owning_team_ref: d.owning_team_ref || null,
      mfa_policy: d.mfa_policy,
    };
    // The keyword is the portal's URL: sent only when it actually changes.
    if (d.keyword.trim() !== portal.keyword) patch.keyword = d.keyword.trim();
    this.run(this.service.updateSettings(portal.id, patch), updated => {
      this.portals.update(list => list.map(p => (p.id === updated.id ? updated : p)));
      if (this.selected()?.id !== updated.id) return;
      this.selected.set(updated);
      this.settings.set(settingsOf(updated));
      this.notice.set(this.lang.translate('portalAdmin.saved'));
    }, { conflict: 'portalAdmin.keywordTaken' });
  }

  savePolicy(): void {
    const current = this.policy();
    const d = this.policyDraft();
    const id = this.portalId();
    if (!current || !d) return;
    const body: AuthPolicy = {
      signup_mode: d.signup_mode,
      signup_domains: lines(d.signup_domains).map(x => x.toLowerCase()),
      signup_role_ref: d.signup_role_ref || null,
      oidc_providers: lines(d.oidc_providers),
      terms_version: d.terms_version.trim() || null,
      privacy_version: d.privacy_version.trim() || null,
      editable_profile_fields: lines(d.editable_profile_fields),
      page_size_cap: Number(d.page_size_cap),
      allowed_cidrs: lines(d.allowed_cidrs),
      records_rpm: Number(d.records_rpm),
      // D-777: the server replaces the whole policy, so every field is sent.
      username_min_len: Number(d.username_min_len),
      username_max_len: Number(d.username_max_len),
      username_blocked_words: lines(d.username_blocked_words),
      username_reserved: lines(d.username_reserved),
      trusted_server_login: d.trusted_server_login,
      row_version: current.row_version,
    };
    this.run(this.service.putAuthPolicy(id, body), saved => {
      if (this.selected()?.id !== id) return;
      this.setPolicy(saved);
      this.notice.set(this.lang.translate('portalAdmin.saved'));
    });
  }

  private setPolicy(p: AuthPolicy): void {
    this.policy.set(p);
    this.policyDraft.set({
      signup_mode: p.signup_mode,
      signup_domains: p.signup_domains.join('\n'),
      signup_role_ref: p.signup_role_ref ?? '',
      oidc_providers: p.oidc_providers.join('\n'),
      terms_version: p.terms_version ?? '',
      privacy_version: p.privacy_version ?? '',
      editable_profile_fields: p.editable_profile_fields.join('\n'),
      page_size_cap: p.page_size_cap,
      allowed_cidrs: p.allowed_cidrs.join('\n'),
      records_rpm: p.records_rpm,
      username_min_len: p.username_min_len,
      username_max_len: p.username_max_len,
      username_blocked_words: p.username_blocked_words.join('\n'),
      username_reserved: p.username_reserved.join('\n'),
      trusted_server_login: p.trusted_server_login,
    });
  }

  private refreshPortal(): void {
    const id = this.selected()?.id;
    if (!id) return;
    this.usersPage = 1;
    this.service.listUsers(id).subscribe({
      next: p => { this.users.set(p.items); this.usersTotal.set(p.total); },
      error: e => this.fail(e),
    });
    this.service.listRoles(id).subscribe({ next: p => this.roles.set(p.items), error: e => this.fail(e) });
    this.service.listEntityConfigs(id).subscribe({ next: p => this.entityConfigs.set(p.items), error: e => this.fail(e) });
    this.service.listErasureRequests(id).subscribe({ next: p => this.erasures.set(p.items), error: e => this.fail(e) });
  }

  // ── Users ────────────────────────────────────────────────────────────────

  loadMoreUsers(): void {
    const id = this.portalId();
    const next = this.usersPage + 1;
    this.run(this.service.listUsers(id, next), p => {
      this.usersPage = next;
      const seen = new Set(this.users().map(u => u.id));
      this.users.update(list => [...list, ...p.items.filter(u => !seen.has(u.id))]);
      this.usersTotal.set(p.total);
    });
  }

  createUser(): void {
    const id = this.portalId();
    const email = this.newUser.email.trim();
    const username = this.newUser.username.trim();
    const body = { name: this.newUser.name.trim(), ...(email ? { email } : {}), ...(username ? { username } : {}) };
    this.run(this.service.createUser(id, body), user => {
      this.users.update(list => [user, ...list]);
      this.usersTotal.update(n => n + 1);
      this.newUser = { name: '', email: '', username: '' };
    });
  }

  invite(user: PortalUserDetail): void {
    this.run(this.service.inviteUser(this.portalId(), user.id), sent =>
      this.notice.set(this.lang.translate('portalAdmin.invited', { when: new Date(sent.expires_at).toLocaleString() })));
  }

  setEnabled(user: PortalUserDetail, enabled: boolean): void {
    this.run(this.service.setUserEnabled(this.portalId(), user.id, enabled), updated =>
      this.users.update(list => list.map(u => (u.id === updated.id ? updated : u))));
  }

  unassignRole(user: PortalUserDetail): void {
    this.run(this.service.unassignRole(this.portalId(), user.id), () => {
      this.notice.set(this.lang.translate('portalAdmin.roleRemoved'));
      this.refreshPortal();
    }, { not_found: 'portalAdmin.noRoleToRemove' });
  }

  assignRole(user: PortalUserDetail): void {
    const roleId = this.roleChoice[user.id];
    if (!roleId) return;
    this.run(this.service.assignRole(this.portalId(), user.id, roleId), () => {
      this.notice.set(this.lang.translate('portalAdmin.saved'));
      this.refreshPortal();
    });
  }

  exportData(user: PortalUserDetail): void {
    this.run(this.service.exportUser(this.portalId(), user.id), result => {
      const rows = result.scopes.reduce((n, s) => n + s.exported_rows, 0);
      this.notice.set(this.lang.translate('portalAdmin.exported', { rows, files: result.scopes.length, id: result.id }));
    });
  }

  async erase(user: PortalUserDetail): Promise<void> {
    const ok = await this.dialog.confirm({
      message: this.lang.translate('portalAdmin.eraseConfirm', { email: user.email ?? user.username ?? user.name }),
      confirmText: this.lang.translate('portalAdmin.erase'),
      variant: 'danger',
    });
    if (!ok) return;
    this.run(this.service.eraseUser(this.portalId(), user.id), () => {
      this.notice.set(this.lang.translate('portalAdmin.erased'));
      this.refreshPortal();
    });
  }

  // ── Roles and grants ─────────────────────────────────────────────────────

  createRole(): void {
    this.run(this.service.createRole(this.portalId(), this.newRoleName.trim()), created => {
      this.newRoleName = '';
      this.refreshPortal();
      this.openRole(created.id);
    });
  }

  openRole(roleId: string): void {
    this.service.getRole(this.portalId(), roleId).subscribe({
      next: view => {
        this.role.set(view);
        this.roleName = view.name;
        this.grant = emptyGrant();
        this.grantFields.set([]);
      },
      error: (err: ApiError) => this.fail(err),
    });
  }

  renameRole(): void {
    const role = this.role();
    const name = this.roleName.trim();
    if (!role || !name || name === role.name) return;
    this.run(this.service.renameRole(this.portalId(), role.id, name), () => {
      this.notice.set(this.lang.translate('portalAdmin.saved'));
      this.refreshPortal();
      this.openRole(role.id);
    }, { conflict: 'portalAdmin.roleNameTaken' });
  }

  async deleteRole(): Promise<void> {
    const role = this.role();
    if (!role) return;
    const ok = await this.dialog.confirm({
      message: this.lang.translate('portalAdmin.deleteRoleConfirm', { name: role.name }),
      confirmText: this.lang.translate('portalAdmin.deleteRole'),
      variant: 'danger',
    });
    if (!ok) return;
    this.run(this.service.deleteRole(this.portalId(), role.id), () => {
      this.role.set(null);
      this.notice.set(this.lang.translate('portalAdmin.roleDeleted'));
      this.refreshPortal();
      // The panel holding the Delete button is gone: keep focus in the roles card.
      document.getElementById('roles-heading')?.focus();
    }, { conflict: 'portalAdmin.roleInUse' });
  }

  editGrant(entity: string): void {
    const g = this.role()?.grants.find(x => x.entity === entity);
    if (!g) return;
    const conditions = g.conditions.map(c => ({
      field: c.field,
      operator: c.operator,
      value: c.value_ref ?? JSON.stringify(c.value ?? ''),
    }));
    this.grant = {
      entity: g.entity,
      can_read: g.can_read, can_create: g.can_create, can_update: g.can_update, can_delete: g.can_delete,
      conditions: conditions.length ? conditions : [emptyCondition()],
      fields: g.fields.map(f => ({ ...f })),
    };
    this.onGrantEntityChange(g.entity);
  }

  /** Loads field suggestions once the grant's entity names a known entity. */
  onGrantEntityChange(text: string): void {
    this.loadAttributes(text, () => this.grant.entity,
      attrs => this.grantFields.set(attrs.filter(a => a.is_active)));
  }

  addCondition(): void {
    if (this.grant.conditions.length >= MAX_GRANT_CONDITIONS) return;
    this.grant.conditions = [...this.grant.conditions, emptyCondition()];
  }

  removeCondition(index: number): void {
    this.grant.conditions = this.grant.conditions.filter((_, i) => i !== index);
  }

  addField(): void {
    this.grant.fields = [...this.grant.fields, { field: '', can_read: true, can_write: false, can_filter: false }];
  }

  removeField(index: number): void {
    this.grant.fields = this.grant.fields.filter((_, i) => i !== index);
  }

  /** The API body for the draft; a value starting `@portal_user.` is a bound reference. */
  grantBody(): GrantSpec {
    const g = this.grant;
    const conditions = g.conditions
      .filter(c => c.field.trim())
      .map(c => {
        const raw = c.value.trim();
        const field = c.field.trim();
        return raw.startsWith('@portal_user.')
          ? { field, operator: c.operator, value_ref: raw }
          : { field, operator: c.operator, value: parseLiteral(raw) };
      });
    return {
      can_read: g.can_read, can_create: g.can_create, can_update: g.can_update, can_delete: g.can_delete,
      conditions,
      fields: g.fields.filter(f => f.field.trim()).map(f => ({ ...f, field: f.field.trim() })),
    };
  }

  saveGrant(): void {
    const role = this.role();
    if (!role) return;
    this.run(this.service.putGrant(this.portalId(), role.id, this.resolveEntity(this.grant.entity), this.grantBody()), () => {
      this.notice.set(this.lang.translate('portalAdmin.grantSaved'));
      this.openRole(role.id);
    });
  }

  deleteGrant(entity: string): void {
    const role = this.role();
    if (!role) return;
    this.run(this.service.deleteGrant(this.portalId(), role.id, entity), () => this.openRole(role.id));
  }

  // ── Entity settings and erasure requests ─────────────────────────────────

  /** Reloads the portal user field choices for the entity picked in "Entity settings". */
  onConfigEntityChange(text: string): void {
    this.entityConfig.portal_user_field = '';
    const target = this.allEntities().find(e => e.logicalname === PORTAL_USER_ENTITY)?.id;
    this.loadAttributes(text, () => this.entityConfig.entity, attrs => this.portalUserFields.set(attrs.filter(a =>
      a.is_active && a.field_type === 'lookup'
      && (a.lookup_entity_ref ? a.lookup_entity_ref === target : a.lookup_entity_name === PORTAL_USER_ENTITY))));
  }

  /** Display name of a logical name, for the table rows and picker hints. */
  entityName(logicalname: string): string {
    return this.allEntities().find(e => e.logicalname === logicalname)?.name ?? logicalname;
  }

  /**
   * The logical name an entity input means: the text itself, or the logical
   * name of the entity whose display name it matches (a walker who types
   * "Case" and never picks the suggestion still sends `case`).
   */
  resolveEntity(text: string): string {
    const t = text.trim();
    const all = this.allEntities();
    if (all.some(e => e.logicalname === t)) return t;
    const lower = t.toLowerCase();
    return all.find(e => e.name.toLowerCase() === lower)?.logicalname ?? t;
  }

  /**
   * The attributes of a known entity, or `[]` (and no request) for anything
   * else. `current` re-reads the input when the response lands, so a slower
   * response for an earlier choice cannot overwrite a later one.
   */
  private loadAttributes(text: string, current: () => string, done: (attrs: AttributeMeta[]) => void): void {
    const logicalname = this.resolveEntity(text);
    const meta = this.allEntities().find(e => e.logicalname === logicalname);
    if (!meta) { done([]); return; }
    this.admin.getEntity(meta.id).subscribe({
      next: d => { if (this.resolveEntity(current()) === logicalname) done(d.attributes); },
      error: (e: ApiError) => { done([]); this.fail(e); },
    });
  }

  saveEntityConfig(): void {
    const c = this.entityConfig;
    this.run(this.service.putEntityConfig(this.portalId(), this.resolveEntity(c.entity), c.portal_user_field.trim() || null), () => {
      this.notice.set(this.lang.translate('portalAdmin.saved'));
      this.entityConfig = { entity: '', portal_user_field: '' };
      this.portalUserFields.set([]);
      this.refreshPortal();
    });
  }

  rejectErasure(request: ErasureRequest): void {
    this.run(this.service.rejectErasureRequest(this.portalId(), request.id), () => this.refreshPortal());
  }

  userName(userId: string): string {
    const user = this.users().find(u => u.id === userId);
    return user?.email ?? user?.username ?? userId;
  }

  // ── Plumbing ─────────────────────────────────────────────────────────────

  private portalId(): string {
    return this.selected()?.id ?? '';
  }

  /**
   * `errors` names a clearer message for an error kind this call can hit for a
   * reason of its own (a 409 that means "name taken", not "changed by someone
   * else"); every other error uses the generic text.
   */
  private run<T>(
    call: Observable<T>,
    done: (value: T) => void,
    errors: Partial<Record<ApiErrorKind, string>> = {},
  ): void {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
    call.subscribe({
      next: value => { this.busy.set(false); done(value); },
      error: (err: ApiError) => {
        this.busy.set(false);
        const key = errors[err.kind];
        if (key) this.error.set(this.lang.translate(key));
        else this.fail(err);
      },
    });
  }

  private fail(err: ApiError): void {
    this.error.set(this.lang.errorText(err));
  }
}

function settingsOf(p: PortalDetail): SettingsDraft {
  return {
    keyword: p.keyword,
    portal_type: p.portal_type,
    is_enabled: p.is_enabled,
    owning_team_ref: p.owning_team_ref ?? '',
    mfa_policy: p.mfa_policy,
  };
}

/** A literal condition value: JSON when it parses (numbers, arrays for `in`), else the text. */
function parseLiteral(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}
