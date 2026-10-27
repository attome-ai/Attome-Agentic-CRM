import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

import { AdminService, EntityMeta, FeatureFlagsService } from '@attome/xrm/core/admin/data';
import {
  ACCESS_LEVELS,
  PermissionSetAssignment,
  PermissionSetDetail,
  PermissionSetItem,
  PrivilegeItem,
  SECURITY_FLAGS,
  SecurityAdminService,
  SetEntityAccessItem,
  TeamItem,
  UserListItem,
  endOfDay,
} from './security-admin.service';

/** The levels a new entity row in a set starts with: the table defaults. */
export function defaultSetAccess(entity: string): SetEntityAccessItem {
  return {
    entity,
    read_access_level: 3,
    write_access_level: 3,
    delete_access_level: 3,
    create_access_level: null,
    assign_access_level: null,
    share_access_level: null,
    export_access_level: 0,
    bulk_access_level: 0,
    read_bu_children: true,
    write_bu_children: true,
    delete_bu_children: true,
    assign_bu_children: true,
    share_bu_children: true,
  };
}

/**
 * Q10-T12 — permission sets (Q10-T5): additive bundles of privileges and
 * entity levels, assigned to a user or a team, optionally until an end date
 * and with a reason. A set never takes access away and never carries
 * `system.admin` (the server refuses it). The screen sits behind
 * `security.permission_sets`; end dates and reasons behind
 * `security.grant_end_dates`.
 */
@Component({
  selector: 'xrm-permission-sets',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css'],
  template: `
    <div class="page-header">
      <div>
        <h2>{{ 'permissionSets.title' | translate }}</h2>
        <p class="subtitle">{{ 'permissionSets.subtitle' | translate }}</p>
      </div>
      @if (enabled()) {
        <button class="btn-primary" (click)="toggleCreate()">
          <i class="las la-plus"></i> {{ 'permissionSets.new' | translate }}
        </button>
      }
    </div>

    @if (!enabled()) {
      <p class="state-msg">{{ 'permissionSets.off' | translate }}</p>
    } @else {
      @if (showCreate()) {
        <div class="create-panel">
          <div class="form-row-3">
            <div class="field">
              <label for="ps-name">{{ 'permissionSets.name' | translate }}</label>
              <input id="ps-name" [(ngModel)]="newName">
            </div>
            <div class="field">
              <label for="ps-name-ar">{{ 'permissionSets.nameAr' | translate }}</label>
              <input id="ps-name-ar" dir="rtl" [(ngModel)]="newNameAr">
            </div>
            <div class="field">
              <label for="ps-desc">{{ 'permissionSets.description' | translate }}</label>
              <input id="ps-desc" [(ngModel)]="newDescription">
            </div>
          </div>
          <div class="btn-row">
            <button class="btn-primary" (click)="create()" [disabled]="busy()">{{ 'permissionSets.save' | translate }}</button>
            <button class="btn-ghost" (click)="toggleCreate()">{{ 'permissionSets.cancel' | translate }}</button>
          </div>
        </div>
      }

      @if (error()) { <p class="error-msg" role="alert">{{ error() }}</p> }

      @if (loading()) {
        <p class="state-msg">{{ 'permissionSets.loading' | translate }}</p>
      } @else if (sets().length === 0) {
        <div class="empty-state"><p>{{ 'permissionSets.empty' | translate }}</p></div>
      } @else {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{{ 'permissionSets.name' | translate }}</th>
                <th>{{ 'permissionSets.description' | translate }}</th>
                <th>{{ 'permissionSets.layer' | translate }}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              @for (s of sets(); track s.id) {
                <tr [class.selected]="selected()?.id === s.id">
                  <td><button class="cell-link" (click)="open(s)">{{ setName(s) }}</button></td>
                  <td class="cell-muted">{{ s.description ?? '' }}</td>
                  <td class="cell-mono">{{ s.owner_layer }}</td>
                  <td class="actions">
                    <button class="btn-sm btn-sm-danger" (click)="remove(s)">{{ 'permissionSets.delete' | translate }}</button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

      @if (selected(); as d) {
        <div class="card">
          <h3>{{ setName(d) }}</h3>

          <h4>{{ 'permissionSets.privileges' | translate }} <span class="count">{{ d.privileges.length }}</span></h4>
          @if (d.privileges.length === 0) {
            <p class="state-msg">{{ 'permissionSets.noPrivileges' | translate }}</p>
          } @else {
            <table class="nested-table">
              <tbody>
                @for (key of d.privileges; track key) {
                  <tr>
                    <td class="cell-mono">{{ key }}</td>
                    <td class="actions">
                      <button class="btn-sm btn-sm-danger" (click)="removePrivilege(key)">{{ 'permissionSets.remove' | translate }}</button>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          }
          <div class="form-row-2 inline-form-panel">
            <div class="field">
              <label for="ps-priv">{{ 'permissionSets.addPrivilege' | translate }}</label>
              <select id="ps-priv" [(ngModel)]="newPrivilege">
                <option value="" disabled>{{ 'permissionSets.choose' | translate }}</option>
                @for (p of grantablePrivileges(); track p.id) {
                  <option [value]="p.key">{{ p.name }} ({{ p.key }})</option>
                }
              </select>
            </div>
            <div class="btn-row">
              <button class="btn-sm btn-primary" (click)="addPrivilege()" [disabled]="busy()">{{ 'permissionSets.add' | translate }}</button>
            </div>
          </div>

          <h4>{{ 'permissionSets.entityAccess' | translate }} <span class="count">{{ d.entity_access.length }}</span></h4>
          @if (d.entity_access.length > 0) {
            <table class="nested-table">
              <thead>
                <tr>
                  <th>{{ 'permissionSets.entity' | translate }}</th>
                  <th>{{ 'roleEntityAccess.read' | translate }}</th>
                  <th>{{ 'roleEntityAccess.write' | translate }}</th>
                  <th>{{ 'roleEntityAccess.delete' | translate }}</th>
                  <th>{{ 'roleEntityAccess.export' | translate }}</th>
                  <th>{{ 'roleEntityAccess.bulk' | translate }}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                @for (a of d.entity_access; track a.entity) {
                  <tr>
                    <td class="cell-mono">{{ a.entity }}</td>
                    <td>{{ levelLabel(a.read_access_level) }}</td>
                    <td>{{ levelLabel(a.write_access_level) }}</td>
                    <td>{{ levelLabel(a.delete_access_level) }}</td>
                    <td>{{ levelLabel(a.export_access_level) }}</td>
                    <td>{{ levelLabel(a.bulk_access_level) }}</td>
                    <td class="actions">
                      <button class="btn-sm" (click)="editAccess(a)">{{ 'permissionSets.edit' | translate }}</button>
                      <button class="btn-sm btn-sm-danger" (click)="clearAccess(a.entity)">{{ 'permissionSets.remove' | translate }}</button>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          }
          <div class="inline-form-panel">
            <div class="form-row-3">
              <div class="field">
                <label for="ps-entity">{{ 'permissionSets.entity' | translate }}</label>
                <select id="ps-entity" [ngModel]="access().entity" (ngModelChange)="setAccess('entity', $event)">
                  <option value="" disabled>{{ 'permissionSets.choose' | translate }}</option>
                  @for (e of entities(); track e.logicalname) {
                    <option [value]="e.logicalname">{{ e.name }} ({{ e.logicalname }})</option>
                  }
                </select>
              </div>
              @for (f of levelFields; track f.key) {
                <div class="field">
                  <label [for]="'ps-' + f.key">{{ f.label | translate }}</label>
                  <select [id]="'ps-' + f.key" [ngModel]="access()[f.key]" (ngModelChange)="setAccess(f.key, $event)">
                    @if (f.optional) { <option [ngValue]="null">{{ 'roleEntityAccess.sameAsWrite' | translate }}</option> }
                    @for (l of accessLevels; track l.value) { <option [ngValue]="l.value">{{ l.label | translate }}</option> }
                  </select>
                </div>
              }
            </div>
            @if (showChildUnits()) {
              <fieldset class="form-row-3">
                <legend>{{ 'roleEntityAccess.childUnits' | translate }}</legend>
                @for (c of childFields; track c.key) {
                  <label class="checkbox-row">
                    <input type="checkbox" [ngModel]="access()[c.key]" (ngModelChange)="setAccess(c.key, $event)">
                    {{ c.label | translate }}
                  </label>
                }
              </fieldset>
            }
            <div class="btn-row">
              <button class="btn-sm btn-primary" (click)="saveAccess()" [disabled]="busy()">{{ 'permissionSets.saveLevels' | translate }}</button>
            </div>
          </div>

          <h4>{{ 'permissionSets.assignments' | translate }} <span class="count">{{ assignments().length }}</span></h4>
          @if (assignments().length === 0) {
            <p class="state-msg">{{ 'permissionSets.noAssignments' | translate }}</p>
          } @else {
            <table class="nested-table">
              <thead>
                <tr>
                  <th>{{ 'permissionSets.assignee' | translate }}</th>
                  @if (showEndDates()) {
                    <th>{{ 'permissionSets.endsAt' | translate }}</th>
                    <th>{{ 'permissionSets.reason' | translate }}</th>
                  }
                  <th></th>
                </tr>
              </thead>
              <tbody>
                @for (a of assignments(); track a.id) {
                  <tr>
                    <td>{{ assigneeLabel(a) }}</td>
                    @if (showEndDates()) {
                      <td>{{ a.ends_at ? (a.ends_at | localDate) : ('permissionSets.noEnd' | translate) }}</td>
                      <td class="cell-muted">{{ a.reason ?? '' }}</td>
                    }
                    <td class="actions">
                      <button class="btn-sm btn-sm-danger" (click)="removeAssignment(a)">{{ 'permissionSets.remove' | translate }}</button>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          }
          <div class="inline-form-panel">
            <div class="form-row-3">
              <div class="field">
                <label for="ps-kind">{{ 'permissionSets.assignTo' | translate }}</label>
                <select id="ps-kind" [(ngModel)]="assignKind">
                  <option value="user">{{ 'permissionSets.user' | translate }}</option>
                  <option value="team">{{ 'permissionSets.team' | translate }}</option>
                </select>
              </div>
              <div class="field">
                <label for="ps-assignee">{{ 'permissionSets.assignee' | translate }}</label>
                <select id="ps-assignee" [(ngModel)]="assigneeId">
                  <option value="" disabled>{{ 'permissionSets.choose' | translate }}</option>
                  @if (assignKind === 'user') {
                    @for (u of users(); track u.id) { <option [value]="u.id">{{ u.user_name ?? u.email ?? u.id }}</option> }
                  } @else {
                    @for (t of teams(); track t.id) { <option [value]="t.id">{{ t.name }}</option> }
                  }
                </select>
              </div>
              @if (showEndDates()) {
                <div class="field">
                  <label for="ps-ends">{{ 'permissionSets.endsAt' | translate }}</label>
                  <input id="ps-ends" type="date" [(ngModel)]="assignEndsOn">
                </div>
              }
            </div>
            @if (showEndDates()) {
              <div class="form-row-1">
                <div class="field">
                  <label for="ps-reason">{{ 'permissionSets.reason' | translate }}</label>
                  <input id="ps-reason" [(ngModel)]="assignReason">
                </div>
              </div>
            }
            <div class="btn-row">
              <button class="btn-sm btn-primary" (click)="assign()" [disabled]="busy()">{{ 'permissionSets.assign' | translate }}</button>
            </div>
          </div>
        </div>
      }
    }
  `,
})
export class PermissionSetsComponent implements OnInit {
  private readonly svc       = inject(SecurityAdminService);
  private readonly adminSvc  = inject(AdminService);
  private readonly dialogSvc = inject(DialogService);
  private readonly lang      = inject(LangService);
  private readonly flags     = inject(FeatureFlagsService);

  readonly accessLevels = ACCESS_LEVELS;
  readonly levelFields: { key: LevelKey; label: string; optional: boolean }[] = [
    { key: 'read_access_level',   label: 'roleEntityAccess.read',   optional: false },
    { key: 'write_access_level',  label: 'roleEntityAccess.write',  optional: false },
    { key: 'delete_access_level', label: 'roleEntityAccess.delete', optional: false },
    { key: 'create_access_level', label: 'roleEntityAccess.create', optional: true },
    { key: 'assign_access_level', label: 'roleEntityAccess.assign', optional: true },
    { key: 'share_access_level',  label: 'roleEntityAccess.share',  optional: true },
    { key: 'export_access_level', label: 'roleEntityAccess.export', optional: false },
    { key: 'bulk_access_level',   label: 'roleEntityAccess.bulk',   optional: false },
  ];
  readonly childFields: { key: ChildKey; label: string }[] = [
    { key: 'read_bu_children',   label: 'roleEntityAccess.childRead' },
    { key: 'write_bu_children',  label: 'roleEntityAccess.childWrite' },
    { key: 'delete_bu_children', label: 'roleEntityAccess.childDelete' },
    { key: 'assign_bu_children', label: 'roleEntityAccess.childAssign' },
    { key: 'share_bu_children',  label: 'roleEntityAccess.childShare' },
  ];

  readonly enabled        = computed(() => this.flags.flags()[SECURITY_FLAGS.permissionSets] === true);
  readonly showEndDates   = computed(() => this.flags.flags()[SECURITY_FLAGS.grantEndDates] === true);
  readonly showChildUnits = computed(() => this.flags.flags()[SECURITY_FLAGS.childUnits] === true);

  readonly sets        = signal<PermissionSetItem[]>([]);
  readonly selected    = signal<PermissionSetDetail | null>(null);
  readonly assignments = signal<PermissionSetAssignment[]>([]);
  readonly privileges  = signal<PrivilegeItem[]>([]);
  readonly entities    = signal<EntityMeta[]>([]);
  readonly users       = signal<UserListItem[]>([]);
  readonly teams       = signal<TeamItem[]>([]);
  readonly access      = signal<SetEntityAccessItem>(defaultSetAccess(''));
  readonly loading     = signal(true);
  readonly busy        = signal(false);
  readonly error       = signal<string | null>(null);
  readonly showCreate  = signal(false);

  /** A set never grants system administration; it is not offered. */
  readonly grantablePrivileges = computed(() => {
    const held = new Set(this.selected()?.privileges ?? []);
    return this.privileges().filter(p => p.key !== 'system.admin' && !held.has(p.key));
  });

  newName = '';
  newNameAr = '';
  newDescription = '';
  newPrivilege = '';
  assignKind: 'user' | 'team' = 'user';
  assigneeId = '';
  assignEndsOn = '';
  assignReason = '';

  ngOnInit(): void {
    this.flags.ensureLoaded();
    this.load();
    this.svc.listPrivileges().subscribe({ next: ps => this.privileges.set(ps) });
    this.adminSvc.listEntities().subscribe({ next: es => this.entities.set(es) });
    this.svc.listUsers().subscribe({ next: page => this.users.set(page.items) });
    this.svc.listTeams().subscribe({ next: ts => this.teams.set(ts) });
  }

  private load(): void {
    this.loading.set(true);
    this.svc.listPermissionSets().subscribe({
      next:  sets => { this.sets.set(sets); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    this.error.set(e.message);
  }

  setName(s: { name: string; name_ar?: string | null }): string {
    return this.lang.current() === 'ar' && s.name_ar ? s.name_ar : s.name;
  }

  levelLabel(value: number | null | undefined): string {
    if (value == null) return this.lang.translate('roleEntityAccess.sameAsWrite');
    const key = this.accessLevels.find(l => l.value === value)?.label;
    return key ? this.lang.translate(key) : String(value);
  }

  assigneeLabel(a: PermissionSetAssignment): string {
    if (a.team_id) {
      const team = this.teams().find(t => t.id === a.team_id);
      return `${this.lang.translate('permissionSets.team')}: ${team?.name ?? a.team_id}`;
    }
    const user = this.users().find(u => u.id === a.user_id);
    return user?.user_name ?? user?.email ?? a.user_id ?? '';
  }

  toggleCreate(): void {
    this.showCreate.update(v => !v);
    this.newName = ''; this.newNameAr = ''; this.newDescription = '';
  }

  create(): void {
    const name = this.newName.trim();
    if (!name) {
      this.error.set(this.lang.translate('permissionSets.nameRequired'));
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.svc.createPermissionSet({
      name,
      name_ar: this.newNameAr.trim() || null,
      description: this.newDescription.trim() || null,
    }).subscribe({
      next: s => {
        this.busy.set(false);
        this.showCreate.set(false);
        this.sets.update(list => [...list, s]);
        this.open(s);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  open(s: PermissionSetItem): void {
    this.error.set(null);
    this.access.set(defaultSetAccess(''));
    this.svc.getPermissionSet(s.id).subscribe({
      next:  d => this.selected.set(d),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.svc.listPermissionSetAssignments(s.id).subscribe({
      next:  as => this.assignments.set(as),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  private reload(): void {
    const d = this.selected();
    if (d) this.open(d);
  }

  async remove(s: PermissionSetItem): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({
      message: this.lang.translate('permissionSets.confirmDelete', { name: this.setName(s) }),
      variant: 'danger',
      confirmText: this.lang.translate('permissionSets.delete'),
    });
    if (!confirmed) return;
    this.svc.deletePermissionSet(s.id).subscribe({
      next: () => {
        this.sets.update(list => list.filter(x => x.id !== s.id));
        if (this.selected()?.id === s.id) this.selected.set(null);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  addPrivilege(): void {
    const d = this.selected();
    if (!d || !this.newPrivilege) return;
    this.busy.set(true);
    this.svc.addPermissionSetPrivilege(d.id, this.newPrivilege).subscribe({
      next:  () => { this.busy.set(false); this.newPrivilege = ''; this.reload(); },
      error: (e: ApiError) => this.fail(e),
    });
  }

  removePrivilege(key: string): void {
    const d = this.selected();
    if (!d) return;
    this.svc.removePermissionSetPrivilege(d.id, key).subscribe({
      next:  () => this.reload(),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  setAccess<K extends keyof SetEntityAccessItem>(key: K, value: SetEntityAccessItem[K]): void {
    this.access.update(a => ({ ...a, [key]: value }));
  }

  editAccess(a: SetEntityAccessItem): void {
    this.access.set({ ...defaultSetAccess(a.entity), ...a });
  }

  saveAccess(): void {
    const d = this.selected();
    const levels = this.access();
    if (!d || !levels.entity) {
      this.error.set(this.lang.translate('permissionSets.entityRequired'));
      return;
    }
    // Without the switch the toggles are hidden and child units stay included.
    const body = this.showChildUnits()
      ? levels
      : { ...levels, ...childUnitsIncluded() };
    this.busy.set(true);
    this.error.set(null);
    this.svc.setPermissionSetEntityAccess(d.id, body).subscribe({
      next:  () => { this.busy.set(false); this.access.set(defaultSetAccess('')); this.reload(); },
      error: (e: ApiError) => this.fail(e),
    });
  }

  clearAccess(entity: string): void {
    const d = this.selected();
    if (!d) return;
    this.svc.clearPermissionSetEntityAccess(d.id, entity).subscribe({
      next:  () => this.reload(),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  assign(): void {
    const d = this.selected();
    if (!d || !this.assigneeId) {
      this.error.set(this.lang.translate('permissionSets.assigneeRequired'));
      return;
    }
    const withDates = this.showEndDates();
    this.busy.set(true);
    this.error.set(null);
    this.svc.assignPermissionSet(d.id, {
      user_id: this.assignKind === 'user' ? this.assigneeId : null,
      team_id: this.assignKind === 'team' ? this.assigneeId : null,
      ends_at: withDates ? endOfDay(this.assignEndsOn) : null,
      reason: withDates ? this.assignReason.trim() || null : null,
    }).subscribe({
      next: a => {
        this.busy.set(false);
        this.assignments.update(list => [...list, a]);
        this.assigneeId = ''; this.assignEndsOn = ''; this.assignReason = '';
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  removeAssignment(a: PermissionSetAssignment): void {
    const d = this.selected();
    if (!d) return;
    this.svc.removePermissionSetAssignment(d.id, a.id).subscribe({
      next:  () => this.assignments.update(list => list.filter(x => x.id !== a.id)),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}

type LevelKey =
  | 'read_access_level' | 'write_access_level' | 'delete_access_level'
  | 'create_access_level' | 'assign_access_level' | 'share_access_level'
  | 'export_access_level' | 'bulk_access_level';
type ChildKey =
  | 'read_bu_children' | 'write_bu_children' | 'delete_bu_children'
  | 'assign_bu_children' | 'share_bu_children';

function childUnitsIncluded(): Record<ChildKey, boolean> {
  return {
    read_bu_children: true, write_bu_children: true, delete_bu_children: true,
    assign_bu_children: true, share_bu_children: true,
  };
}

