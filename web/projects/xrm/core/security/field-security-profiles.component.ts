import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

import {
  CreateFieldSecurityProfileBody,
  FieldSecurityProfileFieldItem,
  FieldSecurityProfileItem,
  RoleItem,
  SecurityAdminService,
} from './security-admin.service';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

/// F013/F135 (D-111): a field-security profile is a named bundle of
/// per-(entity, field) read grants, assigned to roles the same way
/// privileges are. This admin page lets an operator create a profile, toggle
/// which (entity, field) pairs it grants `can_read` for, and assign/unassign
/// it to roles — all against the `core_field_security_profile*` tables via
/// `SecurityAdminService`.
///
/// P-field-write-security (D-141): each field row also carries an
/// independent `can_update` grant — a caller can be allowed to see a
/// sensitive field without being allowed to change it, or vice versa.
@Component({
  selector:   'attome-field-security-profiles',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [OwnerLayerBadgeComponent, FormsModule, TranslatePipe],
  styleUrls:  ['../../styles/admin-page.css'],
  template: `

    <div class="page-header">
      <div>
        <h2>{{ 'fieldSecurityProfiles.title' | translate }}</h2>
        <p class="subtitle">
          {{ 'fieldSecurityProfiles.subtitle' | translate }}
        </p>
      </div>
      <button class="btn-primary" (click)="toggleCreate()">
        <i class="las la-plus"></i> New Profile
      </button>
    </div>

    @if (showCreate()) {
      <div class="create-panel">
        <h3>New Profile</h3>
        <div class="form-row-2">
          <div class="field">
            <label for="fsp-new-name">Name</label>
            <input id="fsp-new-name" [(ngModel)]="newName" [placeholder]="'fieldSecurityProfiles.namePlaceholder' | translate" autocomplete="off">
          </div>
          <div class="field">
            <label for="fsp-new-description">Description <span class="hint">(optional)</span></label>
            <input id="fsp-new-description" [(ngModel)]="newDescription" autocomplete="off">
          </div>
        </div>
        @if (createError()) { <p class="error-msg">{{ createError() }}</p> }
        <div class="btn-row">
          <button class="btn-primary" (click)="create()" [disabled]="creating()">
            {{ creating() ? 'Creating…' : 'Create' }}
          </button>
          <button class="btn-ghost" (click)="toggleCreate()">Cancel</button>
        </div>
      </div>
    }

    @if (loading()) {
      <p class="state-msg">Loading profiles…</p>
    } @else if (error()) {
      <p class="error-msg">{{ error() }}</p>
    } @else if (profiles().length === 0) {
      <div class="empty-state">
        <p>No field security profiles yet.</p>
      </div>
    } @else {
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            @for (p of profiles(); track p.id) {
              <tr>
                <td>{{ p.name }} <xrm-owner-layer-badge [layer]="p.owner_layer" /></td>
                <td class="cell-muted">{{ p.description ?? '—' }}</td>
                <td class="actions">
                  <button class="btn-sm" (click)="toggleDetail(p)">
                    {{ selectedProfile()?.id === p.id ? 'Hide' : 'Manage' }}
                  </button>
                </td>
              </tr>
              @if (selectedProfile()?.id === p.id) {
                <tr>
                  <td colspan="3">
                    <div class="detail-panel">

                      <h4>Fields</h4>
                      <div class="form-row-2">
                        <div class="field">
                          <label for="fsp-new-field-entity">Entity logicalname</label>
                          <input id="fsp-new-field-entity" [(ngModel)]="newFieldEntity" [placeholder]="'fieldSecurityProfiles.entityPlaceholder' | translate" autocomplete="off">
                        </div>
                        <div class="field">
                          <label for="fsp-new-field-name">Field logicalname</label>
                          <input id="fsp-new-field-name" [(ngModel)]="newFieldName" [placeholder]="'fieldSecurityProfiles.fieldPlaceholder' | translate" autocomplete="off">
                        </div>
                      </div>
                      <div class="form-row-2">
                        <div class="field field-cb">
                          <label class="checkbox-row">
                            <input type="checkbox" [(ngModel)]="newFieldCanRead">
                            {{ 'fieldSecurityProfiles.canRead' | translate }}
                          </label>
                        </div>
                        <div class="field field-cb">
                          <label class="checkbox-row">
                            <input type="checkbox" [(ngModel)]="newFieldCanUpdate">
                            {{ 'fieldSecurityProfiles.canUpdate' | translate }}
                          </label>
                        </div>
                      </div>
                      <div class="btn-row">
                        <button class="btn-sm btn-primary" (click)="addField(p)" [disabled]="savingField()">
                          {{ savingField() ? 'Saving…' : 'Grant Access' }}
                        </button>
                      </div>
                      @if (fieldError()) { <p class="error-msg">{{ fieldError() }}</p> }

                      @if (profileFields().length > 0) {
                        <table class="nested-table">
                          <thead>
                            <tr><th>Entity</th><th>Field</th><th>Can Read</th><th>Can Update</th><th></th></tr>
                          </thead>
                          <tbody>
                            @for (f of profileFields(); track f.id) {
                              <tr>
                                <td class="cell-mono">{{ f.entity_logicalname }}</td>
                                <td class="cell-mono">{{ f.field_logicalname }}</td>
                                <td>{{ f.can_read ? 'Yes' : 'No' }}</td>
                                <td>{{ f.can_update ? 'Yes' : 'No' }}</td>
                                <td class="actions">
                                  <button class="btn-sm btn-sm-danger" (click)="revokeField(p, f)">
                                    {{ 'fieldSecurityProfiles.revokeAll' | translate }}
                                  </button>
                                </td>
                              </tr>
                            }
                          </tbody>
                        </table>
                      }

                      <h4>Assign to Role</h4>
                      <div class="form-row-2">
                        <div class="field">
                          <label for="fsp-assign-role">Role</label>
                          <select id="fsp-assign-role" [(ngModel)]="assignRoleId">
                            <option value="" disabled>Select a role…</option>
                            @for (r of roles(); track r.id) {
                              <option [value]="r.id">{{ r.name }}</option>
                            }
                          </select>
                        </div>
                      </div>
                      <div class="btn-row">
                        <button class="btn-sm btn-primary" (click)="assign(p)" [disabled]="assigning()">
                          {{ assigning() ? 'Assigning…' : 'Assign' }}
                        </button>
                      </div>
                      @if (assignError()) { <p class="error-msg">{{ assignError() }}</p> }

                    </div>
                  </td>
                </tr>
              }
            }
          </tbody>
        </table>
      </div>
    }
  `,
})
export class FieldSecurityProfilesComponent implements OnInit {
  private readonly svc = inject(SecurityAdminService);
  private readonly dialogSvc = inject(DialogService);

  readonly profiles      = signal<FieldSecurityProfileItem[]>([]);
  readonly roles         = signal<RoleItem[]>([]);
  readonly loading       = signal(true);
  readonly error         = signal<string | null>(null);
  readonly showCreate    = signal(false);
  readonly creating      = signal(false);
  readonly createError   = signal<string | null>(null);

  readonly selectedProfile = signal<FieldSecurityProfileItem | null>(null);
  readonly profileFields   = signal<FieldSecurityProfileFieldItem[]>([]);
  readonly savingField      = signal(false);
  readonly fieldError       = signal<string | null>(null);
  readonly assigning        = signal(false);
  readonly assignError      = signal<string | null>(null);

  newName = '';
  newDescription = '';
  newFieldEntity = '';
  newFieldName = '';
  newFieldCanRead = true;
  newFieldCanUpdate = false;
  assignRoleId = '';

  ngOnInit(): void {
    this.load();
    this.svc.listRoles().subscribe({ next: rs => this.roles.set(rs) });
  }

  private load(): void {
    this.loading.set(true);
    this.svc.listFieldProfiles().subscribe({
      next:  ps => { this.profiles.set(ps); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  toggleCreate(): void {
    this.showCreate.update(v => !v);
    this.newName = ''; this.newDescription = '';
    this.createError.set(null);
  }

  create(): void {
    const name = this.newName.trim();
    if (!name) {
      this.createError.set('Name is required.');
      return;
    }
    const body: CreateFieldSecurityProfileBody = {
      name,
      description: this.newDescription.trim() || undefined,
    };
    this.creating.set(true);
    this.createError.set(null);
    this.svc.createFieldProfile(body).subscribe({
      next:  p => { this.profiles.update(list => [p, ...list]); this.creating.set(false); this.showCreate.set(false); },
      error: (e: ApiError) => { this.creating.set(false); this.createError.set(e.message); },
    });
  }

  toggleDetail(p: FieldSecurityProfileItem): void {
    if (this.selectedProfile()?.id === p.id) {
      this.selectedProfile.set(null);
      return;
    }
    this.selectedProfile.set(p);
    this.newFieldEntity = ''; this.newFieldName = ''; this.assignRoleId = '';
    this.newFieldCanRead = true; this.newFieldCanUpdate = false;
    this.fieldError.set(null); this.assignError.set(null);
    this.svc.listFieldProfileFields(p.id).subscribe({
      next: fs => this.profileFields.set(fs),
    });
  }

  addField(p: FieldSecurityProfileItem): void {
    const entity_logicalname = this.newFieldEntity.trim();
    const field_logicalname  = this.newFieldName.trim();
    if (!entity_logicalname || !field_logicalname) {
      this.fieldError.set('Both entity and field logicalname are required.');
      return;
    }
    if (!this.newFieldCanRead && !this.newFieldCanUpdate) {
      this.fieldError.set('Grant at least one of read or update access.');
      return;
    }
    this.savingField.set(true);
    this.fieldError.set(null);
    this.svc.setFieldProfileField(p.id, {
      entity_logicalname,
      field_logicalname,
      can_read: this.newFieldCanRead,
      can_update: this.newFieldCanUpdate,
    }).subscribe({
      next: f => {
        this.profileFields.update(list => [
          ...list.filter(x => !(x.entity_logicalname === f.entity_logicalname && x.field_logicalname === f.field_logicalname)),
          f,
        ]);
        this.savingField.set(false);
        this.newFieldEntity = ''; this.newFieldName = '';
        this.newFieldCanRead = true; this.newFieldCanUpdate = false;
      },
      error: (e: ApiError) => { this.savingField.set(false); this.fieldError.set(e.message); },
    });
  }

  /// Revokes both grant dimensions — the row's steady state is
  /// `can_read = false, can_update = false`, matching the backend comment on
  /// `set_field_profile_field` (there's no separate "delete the row" call).
  revokeField(p: FieldSecurityProfileItem, f: FieldSecurityProfileFieldItem): void {
    this.svc.setFieldProfileField(p.id, {
      entity_logicalname: f.entity_logicalname,
      field_logicalname:  f.field_logicalname,
      can_read: false,
      can_update: false,
    }).subscribe({
      next: updated => this.profileFields.update(list => list.map(x => x.id === updated.id ? updated : x)),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }

  assign(p: FieldSecurityProfileItem): void {
    if (!this.assignRoleId) {
      this.assignError.set('Select a role.');
      return;
    }
    this.assigning.set(true);
    this.assignError.set(null);
    this.svc.assignFieldProfile(p.id, this.assignRoleId).subscribe({
      next:  () => { this.assigning.set(false); this.assignRoleId = ''; },
      error: (e: ApiError) => { this.assigning.set(false); this.assignError.set(e.message); },
    });
  }
}
