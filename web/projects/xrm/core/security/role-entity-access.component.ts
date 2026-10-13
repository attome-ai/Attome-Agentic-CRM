import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

import { AdminService, EntityMeta } from '@attome/xrm/core/admin/data';
import {
  ACCESS_LEVELS,
  RoleEntityAccessItem,
  RoleItem,
  SecurityAdminService,
  UpsertEntityAccessGrantBody,
} from './security-admin.service';

/// D-133/D-134/D-136: per-(role, entity) record-level depth on the
/// read/write/delete ladder (None < Team < BusinessUnit < Global). This is
/// the piece D-136 replaced the single-scalar `core_role.access_level` with
/// — a role's depth for one entity must never leak into another entity's
/// resolution, so this page configures depth per (role, entity), not once
/// per role. A role holding an entity's privilege but no row here defaults
/// to Global (zero-behavior-change guarantee) — this page is entirely
/// opt-in narrowing, never a prerequisite for a role to work at all.
@Component({
  selector:   'xrm-role-entity-access',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, TranslatePipe],
  styleUrls:  ['../../styles/admin-page.css'],
  template: `

    <div class="page-header">
      <div>
        <h2>{{ 'roleEntityAccess.title' | translate }}</h2>
        <p class="subtitle">
          {{ 'roleEntityAccess.subtitle' | translate }}
        </p>
      </div>
      <button class="btn-primary" (click)="toggleCreate()">
        <i class="las la-plus"></i> Set Access Level
      </button>
    </div>

    @if (showCreate()) {
      <div class="create-panel">
        <h3>Set Access Level</h3>
        <div class="form-row-2">
          <div class="field">
            <label for="rea-role">Role</label>
            <select id="rea-role" [(ngModel)]="newRoleId">
              <option value="" disabled>Select a role…</option>
              @for (r of roles(); track r.id) {
                <option [value]="r.id">{{ r.name }}</option>
              }
            </select>
          </div>
          <div class="field">
            <label for="rea-entity">Entity</label>
            <select id="rea-entity" [(ngModel)]="newEntity">
              <option value="" disabled>Select an entity…</option>
              @for (e of entities(); track e.logicalname) {
                <option [value]="e.logicalname">{{ e.name }} ({{ e.logicalname }})</option>
              }
            </select>
          </div>
        </div>
        <div class="form-row-3">
          <div class="field">
            <label for="rea-read">Read depth</label>
            <select id="rea-read" [(ngModel)]="newRead">
              @for (l of accessLevels; track l.value) { <option [ngValue]="l.value">{{ l.label | translate }}</option> }
            </select>
          </div>
          <div class="field">
            <label for="rea-write">Write depth</label>
            <select id="rea-write" [(ngModel)]="newWrite">
              @for (l of accessLevels; track l.value) { <option [ngValue]="l.value">{{ l.label | translate }}</option> }
            </select>
          </div>
          <div class="field">
            <label for="rea-delete">Delete depth</label>
            <select id="rea-delete" [(ngModel)]="newDelete">
              @for (l of accessLevels; track l.value) { <option [ngValue]="l.value">{{ l.label | translate }}</option> }
            </select>
          </div>
        </div>
        <div class="form-row-3">
          <label class="checkbox-row">
            <input type="checkbox" [(ngModel)]="newReadOwnerVisible"> Owner-visible (read)
          </label>
          <label class="checkbox-row">
            <input type="checkbox" [(ngModel)]="newWriteOwnerVisible"> Owner-visible (write)
          </label>
          <label class="checkbox-row">
            <input type="checkbox" [(ngModel)]="newDeleteOwnerVisible"> Owner-visible (delete)
          </label>
        </div>
        <p class="state-msg">
          {{ 'roleEntityAccess.ownerVisibleHelp' | translate }}
        </p>
        @if (createError()) { <p class="error-msg">{{ createError() }}</p> }
        <div class="btn-row">
          <button class="btn-primary" (click)="create()" [disabled]="creating()">
            {{ creating() ? 'Saving…' : 'Save' }}
          </button>
          <button class="btn-ghost" (click)="toggleCreate()">Cancel</button>
        </div>
      </div>
    }

    @if (loading()) {
      <p class="state-msg">Loading access levels…</p>
    } @else if (error()) {
      <p class="error-msg">{{ error() }}</p>
    } @else if (grants().length === 0) {
      <div class="empty-state">
        <p>Every role is Global on every entity — nothing has been narrowed yet.</p>
      </div>
    } @else {
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Role</th>
              <th>Entity</th>
              <th>Read</th>
              <th>Write</th>
              <th>Delete</th>
              <th>Owner-visible</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            @for (g of grants(); track g.id) {
              <tr>
                <td>{{ g.role_name ?? g.role_id }}</td>
                <td class="cell-mono">{{ g.entity }}</td>
                <td>{{ levelLabel(g.read_access_level) }}</td>
                <td>{{ levelLabel(g.write_access_level) }}</td>
                <td>{{ levelLabel(g.delete_access_level) }}</td>
                <td class="cell-mono">
                  {{ g.read_owner_visible ? 'R' : '' }}{{ g.write_owner_visible ? 'W' : '' }}{{ g.delete_owner_visible ? 'D' : '' }}
                  @if (!g.read_owner_visible && !g.write_owner_visible && !g.delete_owner_visible) {
                    <span class="cell-muted">—</span>
                  }
                </td>
                <td class="actions">
                  <button class="btn-sm btn-sm-danger" (click)="remove(g)">
                    <i class="las la-times"></i> Reset to Global
                  </button>
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    }
  `,
})
export class RoleEntityAccessComponent implements OnInit {
  private readonly svc       = inject(SecurityAdminService);
  private readonly adminSvc  = inject(AdminService);
  private readonly dialogSvc = inject(DialogService);
  private readonly lang      = inject(LangService);

  readonly accessLevels = ACCESS_LEVELS;

  readonly grants      = signal<RoleEntityAccessItem[]>([]);
  readonly roles       = signal<RoleItem[]>([]);
  readonly entities    = signal<EntityMeta[]>([]);
  readonly loading     = signal(true);
  readonly error       = signal<string | null>(null);
  readonly showCreate  = signal(false);
  readonly creating    = signal(false);
  readonly createError = signal<string | null>(null);

  newRoleId = '';
  newEntity = '';
  newRead   = 3;
  newWrite  = 3;
  newDelete = 3;
  newReadOwnerVisible   = false;
  newWriteOwnerVisible  = false;
  newDeleteOwnerVisible = false;

  ngOnInit(): void {
    this.load();
    this.svc.listRoles().subscribe({ next: rs => this.roles.set(rs) });
    this.adminSvc.listEntities().subscribe({ next: es => this.entities.set(es) });
  }

  private load(): void {
    this.loading.set(true);
    this.svc.listEntityAccessGrants().subscribe({
      next:  gs => { this.grants.set(gs); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  levelLabel(value: number): string {
    const key = this.accessLevels.find(l => l.value === value)?.label;
    return key ? this.lang.translate(key) : String(value);
  }

  toggleCreate(): void {
    this.showCreate.update(v => !v);
    this.newRoleId = ''; this.newEntity = '';
    this.newRead = 3; this.newWrite = 3; this.newDelete = 3;
    this.newReadOwnerVisible = false; this.newWriteOwnerVisible = false; this.newDeleteOwnerVisible = false;
    this.createError.set(null);
  }

  create(): void {
    if (!this.newRoleId || !this.newEntity) {
      this.createError.set('Both role and entity are required.');
      return;
    }
    const body: UpsertEntityAccessGrantBody = {
      role_id: this.newRoleId,
      entity: this.newEntity,
      read_access_level: this.newRead,
      write_access_level: this.newWrite,
      delete_access_level: this.newDelete,
      read_owner_visible: this.newReadOwnerVisible,
      write_owner_visible: this.newWriteOwnerVisible,
      delete_owner_visible: this.newDeleteOwnerVisible,
    };
    this.creating.set(true);
    this.createError.set(null);
    this.svc.upsertEntityAccessGrant(body).subscribe({
      next: g => {
        this.grants.update(list => [
          g,
          ...list.filter(x => !(x.role_id === g.role_id && x.entity === g.entity)),
        ]);
        this.creating.set(false);
        this.showCreate.set(false);
      },
      error: (e: ApiError) => { this.creating.set(false); this.createError.set(e.message); },
    });
  }

  async remove(g: RoleEntityAccessItem): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({
      message: `Reset "${g.role_name ?? g.role_id}" back to Global on "${g.entity}"? This widens access.`,
      variant: 'warning',
      confirmText: 'Reset',
    });
    if (!confirmed) return;
    this.svc.deleteEntityAccessGrant(g.id).subscribe({
      next:  () => this.grants.update(list => list.filter(x => x.id !== g.id)),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }
}
