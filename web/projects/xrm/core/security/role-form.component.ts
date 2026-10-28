import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, effect, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { Observable, forkJoin } from 'rxjs';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { AdminService, EntityMeta } from '@attome/xrm/core/admin/data';

import {
  ACCESS_LEVELS,
  CONDITION_OPERATORS,
  CreateConditionBody,
  PrivilegeItem,
  RoleEntityAccessItem,
  RoleGrantConditionItem,
  RoleGrantItem,
  RoleItem,
  RoleUserItem,
  MFA_FACTORS,
  MFA_MODES,
  RoleAuthPolicy,
  SecurityAdminService,
  WEAK_MFA_FACTORS,
  UpsertEntityAccessGrantBody,
  operationLevelsOf,
} from './security-admin.service';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

/** Preferred display order for the well-known verbs; anything else (a
 * future custom privilege key such as `account.export`) sorts after them,
 * in the order the privilege catalog itself returns (already `ORDER BY key`
 * server-side). */
const VERB_ORDER = ['read', 'create', 'update', 'delete', 'bulk'];
// C-29 (M01 §7): used to be a hardcoded English `Record<string, string>` —
// the well-known verbs now resolve through `roleForm.verb.*` catalog keys
// (`RoleFormComponent.verbLabel`, a class method so it can reach
// `LangService`); a verb outside this fixed set (a future custom privilege
// key) keeps the exact same capitalize-the-raw-string fallback as before.
const KNOWN_VERBS: readonly string[] = VERB_ORDER;

type ScopeColumn = 'read_access_level' | 'write_access_level' | 'delete_access_level';
type OwnerVisibleColumn = 'read_owner_visible' | 'write_owner_visible' | 'delete_owner_visible';
const ACCESS_SCOPE_COLUMNS: ScopeColumn[] = ['read_access_level', 'write_access_level', 'delete_access_level'];

/** `(verb, scope column, owner-visible column)` — only `read`/`update`/
 * `delete` have a Record Access depth or an enforced condition at all
 * (`entity_crud.rs`'s three real enforcement points, D-133/D-136/D-369);
 * `create` has no existing row to filter against, and `bulk` isn't part of
 * the ladder either (D-133's `access_level` migration comment: "create is
 * deliberately excluded"). Both get `null` scope/owner columns and no
 * Conditions button — showing either for them would be a checkbox that
 * silently does nothing. */
const SCOPE_COLUMNS: Record<string, [ScopeColumn, OwnerVisibleColumn] | undefined> = {
  read:   ['read_access_level', 'read_owner_visible'],
  update: ['write_access_level', 'write_owner_visible'],
  delete: ['delete_access_level', 'delete_owner_visible'],
};

/** One entity's privilege list — however many privileges it actually has
 * (D-369 v1 seeds 5 per entity today; this doesn't assume that stays fixed —
 * "support many privileges under one entity" means iterating the real
 * catalog, never a hardcoded action list). */
interface PrivilegeRow {
  privilege: PrivilegeItem;
  verb: string;
  // Only set for a system (non-entity) privilege row, where it's the
  // backend-supplied `privilege.name` — real catalog data, not a
  // hardcoded string, so it stays as a plain field. An entity-privilege row
  // (`filteredGroups()`) has none: its display text is the *verb*
  // (`RoleFormComponent.verbLabel(row.verb)`, resolved live in the template
  // so a language switch after render still re-resolves it correctly — see
  // that method's doc comment).
  label?: string;
  grant?: RoleGrantItem;
  scopeColumn: ScopeColumn | null;
  ownerVisibleColumn: OwnerVisibleColumn | null;
}

interface EntityPrivilegeGroup {
  entity: EntityMeta;
  rows: PrivilegeRow[];
  grantedCount: number;
  accessGrant: RoleEntityAccessItem | null;
}

/** Draft state for one grant's condition editor, expanded on demand — see
 * `toggleConditions`. Fetched lazily (not pre-loaded for every grant in the
 * matrix) to avoid an N+1 fetch storm across a deployment with many entities. */
interface ConditionEditorState {
  loading: boolean;
  error: string | null;
  items: RoleGrantConditionItem[];
  newField: string;
  newOperator: number;
  newValue: string;
}

/** The unified Role form — General / Privilege Grants / Record Access /
 * Assignments / Notes. Replaces the "everything about one role" gap the 5
 * flat admin pages (`role-privileges`, `role-entity-access`,
 * `privilege-grants`, `field-security-profiles`, `user-access`) never
 * covered; those pages stay reachable — this is additive. Route:
 * `/xrm/core/role/form?id=<uuid>` — a literal override ahead of
 * `EntityRouterComponent`'s wildcard (role IS a registered entity,
 * D-372, but this tabbed form replaces its generic one, same idiom as
 * `dashboard/form` in xrm-shell.routes.ts). id absent for a new role (only the
 * General tab is meaningful until the role is saved — every other tab needs
 * a real `role_id`, same "save first" convention `user-form.component.ts`'s
 * Notes tab already uses). */
@Component({
  selector:   'xrm-role-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [OwnerLayerBadgeComponent, FormsModule, DatePipe, TranslatePipe],
  // Overrides admin-page.css's button classes to match the generic entity
  // list's ".btn"/".btn-primary" (entity-list.component.css) — landing here
  // from the Role list's "New Record" button (that generic style) should not
  // feel like a different app. Scoped to this component only (not a global
  // admin-page.css edit) since the other flat admin pages this file's
  // classes are shared with weren't part of this complaint.
  styleUrls:  ['../../styles/xrm-form.css', '../../styles/admin-page.css', './role-form.component.css'],
  templateUrl: './role-form.component.html',
})
// Deliberately does NOT extend EngineFormBase (@attome/xrm/core/entity), unlike
// every other per-entity form. That base is built around "one entity record,
// one FormGroup, one save()" — this component is five independent
// sub-resource editors (General/Grants/Access/Conditions/Assignments)
// against SecurityAdminService's own bespoke, security-sensitive endpoints,
// not a single generic-entity CRUD form. Its General tab alone saves through
// `updateRole`/`createRole`, not `EntityService.update('role', …)` —
// role mutations very likely carry SecurityContext cache-invalidation side
// effects the generic entity-update path doesn't perform (the same reasoning
// `user_account`'s custom delete override documents for user
// deactivation). Rerouting this component's saves through EngineFormBase to
// eliminate the small amount of duplicated tab-navigation code it still
// carries would risk silently dropping that invalidation — not a trade worth
// making for maintainability alone.
export class RoleFormComponent implements OnInit {
  private readonly svc        = inject(SecurityAdminService);
  private readonly adminSvc   = inject(AdminService);
  private readonly router     = inject(Router);
  private readonly dialogSvc  = inject(DialogService);
  private readonly lang       = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  /** Router-bound query param (`withComponentInputBinding()`, app.config.ts)
   * — reactive, unlike a one-shot `ActivatedRoute.snapshot` read: this is
   * what makes the post-create `router.navigate(['.../form'], {queryParams:
   * {id}})` below actually take effect. Angular reuses this component
   * instance across that same-route navigation (no `ngOnInit` re-run), so a
   * snapshot read taken once would stay stuck at "no id" forever — tabs
   * would look permanently disabled and Record Access/Assignments would
   * never load, even though the URL bar shows `?id=...`. */
  readonly id = input<string | null>(null);

  readonly operators  = CONDITION_OPERATORS;
  readonly accessLevels = ACCESS_LEVELS;

  /** C-29 (M01 §7) — a live method call (not a value baked into a
   * `computed()`), so it re-resolves correctly if the user switches
   * language after this page has already rendered. A verb outside the
   * well-known set (a future custom privilege key) keeps the same
   * capitalize-the-raw-string fallback the old hardcoded map had. */
  verbLabel(verb: string): string {
    return KNOWN_VERBS.includes(verb)
      ? this.lang.translate(`roleForm.verb.${verb}`)
      : verb.charAt(0).toUpperCase() + verb.slice(1);
  }

  readonly tabs = [
    { id: 'general',     label: 'General',          icon: 'las la-info-circle' },
    { id: 'grants',      label: 'Privilege Grants',  icon: 'las la-key' },
    { id: 'access',      label: 'Record Access',     icon: 'las la-shield-alt' },
    { id: 'assignments', label: 'Assignments',       icon: 'las la-user-friends' },
    { id: 'signin',      label: 'Sign-in',           icon: 'las la-user-shield' },
    { id: 'notes',       label: 'Notes',             icon: 'las la-edit' },
  ] as const;
  readonly activeTab = signal<(typeof this.tabs)[number]['id']>('general');

  readonly isEdit  = computed(() => this.id() !== null);
  readonly role    = signal<RoleItem | null>(null);
  readonly loadError = signal<string | null>(null);

  /** Reruns whenever `id()` changes — including null -> value right after
   * `saveGeneral()`'s create-then-navigate, which a plain `ngOnInit` guard
   * would only ever see once. */
  private readonly loadOnIdChange = effect(() => {
    const id = this.id();
    if (id) {
      this.loadRole(id);
      this.loadAccessGrants(id);
      this.loadAssignments(id);
      this.loadAuthPolicy(id);
    }
  });

  // Sign-in (Q5-T10)
  readonly mfaModes = MFA_MODES;
  readonly mfaFactors = MFA_FACTORS;
  readonly authPolicy = signal<RoleAuthPolicy | null>(null);
  readonly savingPolicy = signal(false);
  readonly policyError = signal<string | null>(null);
  readonly policySaved = signal(false);
  editMfaMode = 'inherit';
  editFactors = new Set<string>();
  editGraceDays = 7;
  editRememberDays = 30;
  editPhishingOnly = false;
  editSsoOnly = false;

  /** A weak factor cannot be chosen for a role that grants administration. */
  factorDisabled(factor: string): boolean {
    return this.authPolicy()?.is_admin_role === true && WEAK_MFA_FACTORS.includes(factor);
  }

  isWeak(factor: string): boolean {
    return WEAK_MFA_FACTORS.includes(factor);
  }

  toggleFactor(factor: string): void {
    const next = new Set(this.editFactors);
    if (next.has(factor)) next.delete(factor); else next.add(factor);
    this.editFactors = next;
  }

  private applyPolicy(policy: RoleAuthPolicy): void {
    this.authPolicy.set(policy);
    this.editMfaMode = policy.mfa_mode;
    this.editFactors = new Set(policy.mfa_factors.filter(f => !this.factorDisabled(f)));
    this.editGraceDays = policy.mfa_grace_days;
    this.editRememberDays = policy.remember_device_days;
    this.editPhishingOnly = policy.phishing_resistant_only;
    this.editSsoOnly = policy.sso_only;
  }

  private loadAuthPolicy(roleId: string): void {
    this.svc.getRoleAuthPolicy(roleId).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: policy => this.applyPolicy(policy),
      error: (e: ApiError) => this.policyError.set(this.lang.errorText(e)),
    });
  }

  saveAuthPolicy(): void {
    const id = this.id();
    if (!id) return;
    const factors = MFA_FACTORS.filter(f => this.editFactors.has(f) && !this.factorDisabled(f));
    if (factors.length === 0) {
      this.policyError.set(this.lang.translate('roleForm.mfa.noFactor'));
      return;
    }
    this.savingPolicy.set(true);
    this.policyError.set(null);
    this.policySaved.set(false);
    this.svc.updateRoleAuthPolicy(id, {
      sso_only: this.editSsoOnly,
      mfa_mode: this.editMfaMode,
      mfa_factors: [...factors],
      mfa_grace_days: Math.trunc(Number(this.editGraceDays)),
      remember_device_days: Math.trunc(Number(this.editRememberDays)),
      phishing_resistant_only: this.editPhishingOnly,
    }).subscribe({
      next: policy => { this.applyPolicy(policy); this.savingPolicy.set(false); this.policySaved.set(true); },
      error: (e: ApiError) => { this.savingPolicy.set(false); this.policyError.set(this.lang.errorText(e)); },
    });
  }

  // General
  editName = '';
  editDescription = '';
  editPositionHierarchy = false;
  readonly savingGeneral = signal(false);
  readonly generalError  = signal<string | null>(null);

  // Privilege Grants
  readonly entities       = signal<EntityMeta[]>([]);
  readonly privileges     = signal<PrivilegeItem[]>([]);
  readonly roleGrants     = signal<RoleGrantItem[]>([]);
  readonly grantsLoading  = signal(true);
  /** Staged checkbox toggles, keyed by privilege key, not yet sent to the
   * server — nothing here calls the API until `saveGrantChanges()` runs, per
   * the product requirement that Privilege Grants (and the inline Scope
   * selects below) only take effect on an explicit Save, unlike the
   * Record Access tab's own create-panel Save (already explicit) or the
   * Conditions editor's Add/Delete buttons (already explicit). Value is the
   * desired granted state; an entry is only present when it differs from
   * `roleGrants()`'s current server truth. */
  readonly pendingGrantChanges = signal<Map<string, boolean>>(new Map());
  /** Staged inline Scope-column edits, keyed by entity logicalname, holding
   * the full desired grant body (same shape `createAccess` sends) so a save
   * only needs one upsert call per touched entity regardless of how many of
   * its three columns changed. */
  readonly pendingScopeChanges = signal<Map<string, UpsertEntityAccessGrantBody>>(new Map());
  readonly savingGrants    = signal(false);
  readonly grantsSaveError = signal<string | null>(null);
  /** Tracks COLLAPSED entities, not expanded ones — so a freshly-loaded
   * entity (not yet in this set) defaults to expanded, matching the
   * reference design, without needing to know the entity list up front to
   * pre-seed an "expanded" set at declaration time (entities load async). */
  readonly collapsedEntities = signal<Set<string>>(new Set());
  entitySearch = '';
  entityFilter = '';
  verbFilter = '';

  /** Every distinct verb across the real privilege catalog — not a fixed
   * list, so a future custom key (e.g. `account.export`) shows up in the
   * filter automatically. */
  readonly allVerbs = computed(() => {
    const entityNames = new Set(this.entities().map(e => e.logicalname));
    const verbs = new Set<string>();
    for (const p of this.privileges()) {
      const [prefix, ...rest] = p.key.split('.');
      if (entityNames.has(prefix) && rest.length) verbs.add(rest.join('.'));
    }
    return [...verbs].sort(
      (a, b) => (VERB_ORDER.indexOf(a) + 1 || 99) - (VERB_ORDER.indexOf(b) + 1 || 99) || a.localeCompare(b),
    );
  });

  /** Privileges whose key doesn't belong to any registered entity —
   * `system.admin`, `sidebar.manage`, etc. (D-369's flat `{namespace}.{verb}`
   * convention). No Scope/Conditions column: these are flat booleans, not
   * record-level grants. */
  readonly systemPrivileges = computed<PrivilegeRow[]>(() => {
    const entityNames = new Set(this.entities().map(e => e.logicalname));
    const grantsByKey = new Map(this.roleGrants().map(g => [g.privilege_key, g]));
    return this.privileges()
      .filter(p => !entityNames.has(p.key.split('.')[0]))
      .map(p => ({
        privilege: p, verb: p.key, label: p.name,
        grant: grantsByKey.get(p.key),
        scopeColumn: null, ownerVisibleColumn: null,
      }));
  });

  readonly systemGrantedCount = computed(() =>
    this.systemPrivileges().filter(r => this.isGranted(r)).length,
  );

  readonly hasPendingGrantChanges = computed(() =>
    this.pendingGrantChanges().size > 0 || this.pendingScopeChanges().size > 0,
  );
  readonly pendingGrantChangeCount = computed(() =>
    this.pendingGrantChanges().size + this.pendingScopeChanges().size,
  );

  /** Whether `row` should render as checked/granted right now — the staged
   * value if the user has touched this checkbox since the last save,
   * otherwise the server's current grant. */
  isGranted(row: PrivilegeRow): boolean {
    const pending = this.pendingGrantChanges().get(row.privilege.key);
    return pending !== undefined ? pending : !!row.grant;
  }

  readonly filteredGroups = computed<EntityPrivilegeGroup[]>(() => {
    const search = this.entitySearch.trim().toLowerCase();
    const grantsByKey = new Map(this.roleGrants().map(g => [g.privilege_key, g]));
    const accessByEntity = new Map(this.accessGrants().map(g => [g.entity, g]));
    const privilegesByEntity = new Map<string, PrivilegeItem[]>();
    for (const p of this.privileges()) {
      const prefix = p.key.split('.')[0];
      if (!privilegesByEntity.has(prefix)) privilegesByEntity.set(prefix, []);
      privilegesByEntity.get(prefix)!.push(p);
    }

    const groups: EntityPrivilegeGroup[] = [];
    for (const entity of this.entities()) {
      if (this.entityFilter && entity.logicalname !== this.entityFilter) continue;
      if (search && !entity.name.toLowerCase().includes(search)
          && !entity.logicalname.toLowerCase().includes(search)) continue;

      const entityPrivileges = privilegesByEntity.get(entity.logicalname) ?? [];
      let rows: PrivilegeRow[] = entityPrivileges.map(p => {
        const verb = p.key.slice(entity.logicalname.length + 1);
        const scope = SCOPE_COLUMNS[verb];
        return {
          privilege: p, verb,
          grant: grantsByKey.get(p.key),
          scopeColumn: scope?.[0] ?? null,
          ownerVisibleColumn: scope?.[1] ?? null,
        };
      });
      if (this.verbFilter) rows = rows.filter(r => r.verb === this.verbFilter);
      if (rows.length === 0) continue;

      rows.sort((a, b) => (VERB_ORDER.indexOf(a.verb) + 1 || 99) - (VERB_ORDER.indexOf(b.verb) + 1 || 99));
      groups.push({
        entity,
        rows,
        grantedCount: rows.filter(r => this.isGranted(r)).length,
        accessGrant: accessByEntity.get(entity.logicalname) ?? null,
      });
    }

    return groups.sort((a, b) => a.entity.name.localeCompare(b.entity.name));
  });

  isExpanded(entityId: string): boolean {
    return !this.collapsedEntities().has(entityId);
  }

  toggleExpanded(entityId: string): void {
    this.collapsedEntities.update(set => {
      const next = new Set(set);
      if (next.has(entityId)) next.delete(entityId); else next.add(entityId);
      return next;
    });
  }

  expandAll(): void {
    this.collapsedEntities.set(new Set());
  }

  collapseAll(): void {
    this.collapsedEntities.set(
      new Set(['__system__', ...this.filteredGroups().map(g => g.entity.id)]),
    );
  }

  /** The persisted grant body for `group`'s entity, defaulted the same way
   * `createAccess`/`updateScope` always have — used both to render the Scope
   * selects and as the base a staged column edit merges onto. */
  private scopeBody(group: EntityPrivilegeGroup): UpsertEntityAccessGrantBody {
    const cur = group.accessGrant;
    return {
      role_id: this.id()!,
      entity: group.entity.logicalname,
      read_access_level:   cur?.read_access_level   ?? 3,
      write_access_level:  cur?.write_access_level  ?? 3,
      delete_access_level: cur?.delete_access_level ?? 3,
      read_owner_visible:   cur?.read_owner_visible   ?? false,
      write_owner_visible:  cur?.write_owner_visible  ?? false,
      delete_owner_visible: cur?.delete_owner_visible ?? false,
      // Q10-T12: this tab edits only read, write and delete; keep the rest.
      ...operationLevelsOf(cur),
    };
  }

  scopeLabel(group: EntityPrivilegeGroup, column: ScopeColumn): number {
    const pending = this.pendingScopeChanges().get(group.entity.logicalname);
    if (pending) return pending[column] ?? 3;
    return group.accessGrant?.[column] ?? 3;
  }

  updateScope(group: EntityPrivilegeGroup, column: ScopeColumn, value: number): void {
    const key = group.entity.logicalname;
    const persisted = this.scopeBody(group);
    const base = this.pendingScopeChanges().get(key) ?? persisted;
    const next: UpsertEntityAccessGrantBody = { ...base, [column]: value };

    this.pendingScopeChanges.update(m => {
      const copy = new Map(m);
      const unchanged = ACCESS_SCOPE_COLUMNS.every(c => next[c] === persisted[c]);
      if (unchanged) copy.delete(key); else copy.set(key, next);
      return copy;
    });
  }

  selectAllInEntity(group: EntityPrivilegeGroup): void {
    for (const row of group.rows) {
      if (!this.isGranted(row)) this.toggleGrant(row);
    }
  }

  grantStatus(row: PrivilegeRow): 'granted' | 'conditional' | 'none' {
    if (!this.isGranted(row)) return 'none';
    const isPending = this.pendingGrantChanges().has(row.privilege.key);
    if (!isPending && row.grant && row.grant.condition_count > 0) return 'conditional';
    return 'granted';
  }

  // Conditions (lazy per-grant)
  private readonly conditionStates = signal<Map<string, ConditionEditorState>>(new Map());
  readonly expandedGrantId = signal<string | null>(null);
  conditionState(grantId: string): ConditionEditorState | undefined {
    return this.conditionStates().get(grantId);
  }

  // Record Access
  readonly accessGrants   = signal<RoleEntityAccessItem[]>([]);
  readonly showAccessCreate = signal(false);
  readonly savingAccess   = signal(false);
  readonly accessError    = signal<string | null>(null);
  newAccessEntity = '';
  newAccessRead   = 3;
  newAccessWrite  = 3;
  newAccessDelete = 3;
  newAccessReadOwnerVisible   = false;
  newAccessWriteOwnerVisible  = false;
  newAccessDeleteOwnerVisible = false;

  // Assignments
  readonly roleUsers = signal<RoleUserItem[]>([]);
  readonly assignmentsLoading = signal(false);
  readonly assigning  = signal(false);
  readonly assignError = signal<string | null>(null);
  assignEmail = '';

  ngOnInit(): void {
    this.adminSvc.listEntities().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: es => this.entities.set(es) });
    this.svc.listPrivileges().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: ps => this.privileges.set(ps) });
    this.svc.listRoleGrants().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next:  gs => { this.roleGrants.set(gs); this.grantsLoading.set(false); },
      error: (e: ApiError) => { this.loadError.set(e.message); this.grantsLoading.set(false); },
    });
  }

  private loadRole(id: string): void {
    this.svc.listRoles().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: roles => {
        const r = roles.find(x => x.id === id);
        if (!r) { this.loadError.set('Role not found.'); return; }
        this.role.set(r);
        this.editName = r.name;
        this.editDescription = r.description ?? '';
        this.editPositionHierarchy = r.position_hierarchy_enabled;
      },
      error: (e: ApiError) => this.loadError.set(e.message),
    });
  }

  // ── Tabs ────────────────────────────────────────────────────────────────

  selectTab(tab: (typeof this.tabs)[number]['id']): void {
    if (!this.isEdit() && tab !== 'general') return;
    this.activeTab.set(tab);
  }

  onTabKeydown(event: KeyboardEvent): void {
    const current = this.tabs.findIndex(tab => tab.id === this.activeTab());
    let next: number;
    if (event.key === 'ArrowRight') next = (current + 1) % this.tabs.length;
    else if (event.key === 'ArrowLeft') next = (current - 1 + this.tabs.length) % this.tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = this.tabs.length - 1;
    else return;

    event.preventDefault();
    this.selectTab(this.tabs[next].id);
    // The listener is bound on the tab button itself, so its *parent* (the
    // `.xf-tabs` wrapper) is where the sibling `[role="tab"]` buttons live —
    // querying the button's own subtree here would always find nothing.
    const tabButton = event.currentTarget as HTMLElement;
    tabButton.parentElement?.querySelectorAll<HTMLElement>('[role="tab"]')[next]?.focus();
  }

  back(): void {
    void this.router.navigate(['/xrm/core/role/list']);
  }

  // ── General ─────────────────────────────────────────────────────────────

  saveGeneral(): void {
    const name = this.editName.trim();
    if (!name) { this.generalError.set('Name is required.'); return; }

    this.savingGeneral.set(true);
    this.generalError.set(null);

    if (this.isEdit()) {
      this.svc.updateRole(this.id()!, {
        name, description: this.editDescription,
      }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: r => { this.role.set(r); this.savingGeneral.set(false); },
        error: (e: ApiError) => { this.generalError.set(e.message); this.savingGeneral.set(false); },
      });
    } else {
      this.svc.createRole({
        name, description: this.editDescription || undefined,
      }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: r => {
          this.savingGeneral.set(false);
          void this.router.navigate(['/xrm/core/role/form'], { queryParams: { id: r.id } });
        },
        error: (e: ApiError) => { this.generalError.set(e.message); this.savingGeneral.set(false); },
      });
    }
  }

  /** F138's flag has its own dedicated endpoint (`updateRolePositionHierarchy`)
   * because toggling it invalidates every current holder's cached
   * `SecurityContext` — see `security-admin.service.ts`'s `UpdateRoleBody`
   * doc comment for why it's excluded from the plain General-tab PATCH. */
  savePositionHierarchy(): void {
    if (!this.isEdit()) return;
    this.svc.updateRolePositionHierarchy(this.id()!, this.editPositionHierarchy).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      error: (e: ApiError) => {
        void this.dialogSvc.error(e.message);
        this.editPositionHierarchy = !this.editPositionHierarchy;
      },
    });
  }

  // ── Privilege Grants ───────────────────────────────────────────────────

  operatorLabel(value: number): string {
    const key = this.operators.find(o => o.value === value)?.label;
    return key ? this.lang.translate(key) : String(value);
  }
  formatValue(value: unknown): string {
    return Array.isArray(value) ? value.join(', ') : String(value);
  }

  /** Stages the flip, it does not call the API — `saveGrantChanges()` does
   * that for every staged row/scope edit at once, on an explicit Save. */
  toggleGrant(row: PrivilegeRow): void {
    const key = row.privilege.key;
    const desired = !this.isGranted(row);
    const original = !!row.grant;
    this.pendingGrantChanges.update(m => {
      const next = new Map(m);
      if (desired === original) next.delete(key); else next.set(key, desired);
      return next;
    });
  }

  /** Commits every staged checkbox toggle and Scope-column edit in one batch
   * — one create/delete per touched privilege, one upsert per touched
   * entity's scope, run concurrently via `forkJoin`. Reloads grants and
   * access grants from the server afterwards rather than hand-patching local
   * state, since a batch can touch dozens of rows at once. */
  saveGrantChanges(): void {
    if (this.savingGrants() || !this.hasPendingGrantChanges()) return;

    const ops: Observable<unknown>[] = [];
    for (const [key, desired] of this.pendingGrantChanges()) {
      const existing = this.roleGrants().find(g => g.privilege_key === key);
      if (desired && !existing) {
        ops.push(this.svc.createRoleGrant({ role_id: this.id()!, privilege_key: key }));
      } else if (!desired && existing) {
        ops.push(this.svc.deleteRoleGrant(existing.id));
      }
    }
    for (const body of this.pendingScopeChanges().values()) {
      ops.push(this.svc.upsertEntityAccessGrant(body));
    }
    if (ops.length === 0) { this.discardGrantChanges(); return; }

    this.savingGrants.set(true);
    this.grantsSaveError.set(null);
    forkJoin(ops).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.pendingGrantChanges.set(new Map());
        this.pendingScopeChanges.set(new Map());
        this.svc.listRoleGrants().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: gs => this.roleGrants.set(gs) });
        this.loadAccessGrants(this.id()!);
        this.savingGrants.set(false);
      },
      error: (e: ApiError) => { this.grantsSaveError.set(e.message); this.savingGrants.set(false); },
    });
  }

  discardGrantChanges(): void {
    this.pendingGrantChanges.set(new Map());
    this.pendingScopeChanges.set(new Map());
    this.grantsSaveError.set(null);
  }

  toggleConditions(grant: RoleGrantItem): void {
    if (this.expandedGrantId() === grant.id) {
      this.expandedGrantId.set(null);
      return;
    }
    this.expandedGrantId.set(grant.id);
    if (this.conditionStates().has(grant.id)) return;

    const state: ConditionEditorState = {
      loading: true, error: null, items: [], newField: '', newOperator: 0, newValue: '',
    };
    this.conditionStates.update(m => new Map(m).set(grant.id, state));
    this.svc.listGrantConditions(grant.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: items => this.patchConditionState(grant.id, { loading: false, items }),
      error: (e: ApiError) => this.patchConditionState(grant.id, { loading: false, error: e.message }),
    });
  }

  private patchConditionState(grantId: string, patch: Partial<ConditionEditorState>): void {
    this.conditionStates.update(m => {
      const next = new Map(m);
      const cur = next.get(grantId);
      if (cur) next.set(grantId, { ...cur, ...patch });
      return next;
    });
  }

  addCondition(grant: RoleGrantItem, state: ConditionEditorState): void {
    const field = state.newField.trim();
    if (!field) { this.patchConditionState(grant.id, { error: 'Field is required.' }); return; }

    let value: unknown;
    if (state.newOperator === 6) {
      value = state.newValue.split(',').map(v => coerceScalar(v.trim())).filter(v => v !== '');
    } else {
      value = coerceScalar(state.newValue.trim());
    }

    const body: CreateConditionBody = { field_logicalname: field, operator: state.newOperator, value };
    this.patchConditionState(grant.id, { error: null });
    this.svc.createGrantCondition(grant.id, body).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: item => this.patchConditionState(grant.id, {
        items: [...(this.conditionState(grant.id)?.items ?? []), item],
        newField: '', newValue: '',
      }),
      error: (e: ApiError) => this.patchConditionState(grant.id, { error: e.message }),
    });
  }

  deleteCondition(grant: RoleGrantItem, condition: RoleGrantConditionItem): void {
    this.svc.deleteGrantCondition(grant.id, condition.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => this.patchConditionState(grant.id, {
        items: (this.conditionState(grant.id)?.items ?? []).filter(c => c.id !== condition.id),
      }),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }

  // ── Record Access ───────────────────────────────────────────────────────

  private loadAccessGrants(roleId: string): void {
    this.svc.listEntityAccessGrants().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: gs => this.accessGrants.set(gs.filter(g => g.role_id === roleId)),
      error: (e: ApiError) => this.loadError.set(e.message),
    });
  }

  levelLabel(value: number): string {
    const key = this.accessLevels.find(l => l.value === value)?.label;
    return key ? this.lang.translate(key) : String(value);
  }

  toggleAccessCreate(): void {
    this.showAccessCreate.update(v => !v);
    this.newAccessEntity = ''; this.newAccessRead = 3; this.newAccessWrite = 3; this.newAccessDelete = 3;
    this.newAccessReadOwnerVisible = false;
    this.newAccessWriteOwnerVisible = false;
    this.newAccessDeleteOwnerVisible = false;
    this.accessError.set(null);
  }

  createAccess(): void {
    if (!this.newAccessEntity) { this.accessError.set('Entity is required.'); return; }
    const body: UpsertEntityAccessGrantBody = {
      role_id: this.id()!, entity: this.newAccessEntity,
      read_access_level: this.newAccessRead, write_access_level: this.newAccessWrite,
      delete_access_level: this.newAccessDelete,
      read_owner_visible: this.newAccessReadOwnerVisible,
      write_owner_visible: this.newAccessWriteOwnerVisible,
      delete_owner_visible: this.newAccessDeleteOwnerVisible,
      ...operationLevelsOf(this.accessGrants().find(x => x.entity === this.newAccessEntity)),
    };
    this.savingAccess.set(true);
    this.accessError.set(null);
    this.svc.upsertEntityAccessGrant(body).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: g => {
        this.accessGrants.update(list => [g, ...list.filter(x => x.entity !== g.entity)]);
        this.savingAccess.set(false);
        this.showAccessCreate.set(false);
      },
      error: (e: ApiError) => { this.accessError.set(e.message); this.savingAccess.set(false); },
    });
  }

  async removeAccess(g: RoleEntityAccessItem): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({
      message: `Reset back to Global on "${g.entity}"? This widens access.`,
      variant: 'warning',
      confirmText: 'Reset',
    });
    if (!confirmed) return;
    this.svc.deleteEntityAccessGrant(g.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => this.accessGrants.update(list => list.filter(x => x.id !== g.id)),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }

  // ── Assignments ─────────────────────────────────────────────────────────

  private loadAssignments(roleId: string): void {
    this.assignmentsLoading.set(true);
    this.svc.listRoleUsers(roleId).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: us => { this.roleUsers.set(us); this.assignmentsLoading.set(false); },
      error: (e: ApiError) => { this.loadError.set(e.message); this.assignmentsLoading.set(false); },
    });
  }

  assignUser(): void {
    const email = this.assignEmail.trim();
    if (!email) { this.assignError.set('Email is required.'); return; }
    this.assigning.set(true);
    this.assignError.set(null);
    this.svc.findUserByEmail(email).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: matches => {
        const user = matches[0];
        if (!user) { this.assignError.set('No user found with that email.'); this.assigning.set(false); return; }
        this.svc.assignUserRole(user.id, { role_id: this.id()! }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
          next: () => { this.assignEmail = ''; this.assigning.set(false); this.loadAssignments(this.id()!); },
          error: (e: ApiError) => { this.assignError.set(e.message); this.assigning.set(false); },
        });
      },
      error: (e: ApiError) => { this.assignError.set(e.message); this.assigning.set(false); },
    });
  }

  async removeAssignment(u: RoleUserItem): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({
      message: `Remove "${u.user_name || u.email}" from this role?`,
      variant: 'danger',
      confirmText: 'Remove',
    });
    if (!confirmed) return;
    this.svc.removeUserRole(u.user_id, this.id()!).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => this.roleUsers.update(list => list.filter(x => x.id !== u.id)),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }
}

/** Best-effort JSON-scalar coercion for a plain-text condition-value input —
 * `"true"`/`"false"` -> boolean, a valid number literal -> number, anything
 * else stays a string. */
function coerceScalar(raw: string): unknown {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  if (raw !== '' && !Number.isNaN(Number(raw))) return Number(raw);
  return raw;
}
