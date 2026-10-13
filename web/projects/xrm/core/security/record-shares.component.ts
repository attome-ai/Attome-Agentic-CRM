import { ChangeDetectionStrategy, Component, Input, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

import { AdminService, EntityMeta } from '@attome/xrm/core/admin/data';
import {
  EntityDefaultShareItem,
  OwnerItem,
  RecordShareItem,
  SecurityAdminService,
  ShareCapability,
} from './security-admin.service';

/// D-133 (4): explicit F137 record sharing, entity-wide default shares, and
/// admin-exempt deny — one table shape (core_record_share/
/// core_entity_default_share), two scopes. Both sections here support all
/// three capabilities (view/action/deny), so "Explicit denies" is not a
/// separate screen — it's the same create form with `capability = deny`.
/// This page is also where "record-specific exceptions" (the third leg of
/// the required configured/effective/record-specific view, alongside
/// User Access's configured-vs-effective pair) are visible: the Record
/// Shares section is scoped to exactly one (entity, record).
@Component({
  selector:   'xrm-record-shares',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, DatePipe, TranslatePipe],
  styleUrls:  ['../../styles/admin-page.css'],
  template: `

    <div class="page-header">
      <div>
        <h2>{{ 'recordShares.title' | translate }}</h2>
        <p class="subtitle">
          {{ 'recordShares.subtitle' | translate }}
        </p>
      </div>
    </div>

    <div class="card">
      <div class="section-header"><h3>Record Shares <span class="hint">— one specific record</span></h3></div>

      @if (!isLocked) {
        <div class="filter-bar">
          <select [(ngModel)]="recordEntity">
            <option value="" disabled>Entity…</option>
            @for (e of entities(); track e.logicalname) {
              <option [value]="e.logicalname">{{ e.name }} ({{ e.logicalname }})</option>
            }
          </select>
          <input class="search" [(ngModel)]="recordId" [placeholder]="'recordShares.recordIdPlaceholder' | translate" autocomplete="off">
          <button class="btn-primary" (click)="loadRecordShares()" [disabled]="loadingRecordShares()">
            {{ loadingRecordShares() ? 'Loading…' : 'Load Shares' }}
          </button>
        </div>
      }
      @if (recordSharesError()) { <p class="error-msg">{{ recordSharesError() }}</p> }

      @if (recordSharesLoaded()) {
        @if (recordShares().length === 0) {
          <p class="state-msg">No explicit shares or denies on this record.</p>
        } @else {
          <table class="nested-table">
            <thead>
              <tr><th>Principal</th><th>Capability</th><th>Granted</th><th></th></tr>
            </thead>
            <tbody>
              @for (s of recordShares(); track s.id) {
                <tr>
                  <td>{{ s.principal_type }}: <span class="cell-mono">{{ s.principal_id }}</span></td>
                  <td><span class="badge" [class.badge-boolean]="s.capability !== 'deny'"
                            [class.badge-choice]="s.capability === 'deny'">{{ s.capability }}</span></td>
                  <td class="cell-muted">{{ s.granted_at ? (s.granted_at | date:'medium') : '—' }}</td>
                  <td class="actions">
                    <button class="btn-sm btn-sm-danger" (click)="deleteRecordShare(s)">Revoke</button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        }

        <div class="inline-form-panel">
          <h4>Grant or Deny</h4>
          <div class="form-row-3">
            <div class="field">
              <label for="record-share-principal-type">Principal type</label>
              <select id="record-share-principal-type" [(ngModel)]="newSharePrincipalType">
                <option value="user">User</option>
                <option value="team">Team</option>
              </select>
            </div>
            @if (newSharePrincipalType === 'user') {
              <div class="field">
                <label for="record-share-user-email">User email</label>
                <input id="record-share-user-email" [(ngModel)]="newShareUserEmail" [placeholder]="'recordShares.userEmailPlaceholder' | translate" autocomplete="off">
              </div>
            } @else {
              <div class="field">
                <label for="record-share-team-name">Team name</label>
                <input id="record-share-team-name" [(ngModel)]="newShareTeamName" [placeholder]="'recordShares.teamNamePlaceholder' | translate" autocomplete="off">
              </div>
            }
            <div class="field">
              <label for="record-share-capability">Capability</label>
              <select id="record-share-capability" [(ngModel)]="newShareCapability">
                <option value="view">View</option>
                <option value="action">Action (view + mutate)</option>
                <option value="deny">Deny (overrides any grant)</option>
              </select>
            </div>
          </div>
          <div class="btn-row">
            <button class="btn-sm btn-primary" (click)="createRecordShare()" [disabled]="savingRecordShare()">
              {{ savingRecordShare() ? 'Saving…' : (newShareCapability === 'deny' ? 'Deny' : 'Grant') }}
            </button>
          </div>
          @if (recordShareCreateError()) { <p class="error-msg">{{ recordShareCreateError() }}</p> }

          <h4>Reassign Owner</h4>
          <p class="hint">Grants the new owner an action-capability share; the previous owner's share is left as-is.</p>
          <div class="form-row-3">
            <div class="field">
              <label for="reassign-principal-type">Principal type</label>
              <select id="reassign-principal-type" [(ngModel)]="reassignPrincipalType">
                <option value="user">User</option>
                <option value="team">Team</option>
              </select>
            </div>
            @if (reassignPrincipalType === 'user') {
              <div class="field">
                <label for="reassign-user-email">New owner email</label>
                <input id="reassign-user-email" [(ngModel)]="reassignUserEmail" [placeholder]="'recordShares.userEmailPlaceholder' | translate" autocomplete="off">
              </div>
            } @else {
              <div class="field">
                <label for="reassign-team-name">New owner team</label>
                <input id="reassign-team-name" [(ngModel)]="reassignTeamName" [placeholder]="'recordShares.teamNamePlaceholder' | translate" autocomplete="off">
              </div>
            }
          </div>
          <div class="btn-row">
            <button class="btn-sm btn-primary" (click)="reassignOwner()" [disabled]="reassigning()">
              {{ reassigning() ? 'Reassigning…' : 'Reassign Owner' }}
            </button>
          </div>
          @if (reassignResult()) { <p class="hint">Now owned by {{ reassignResult()!.owner_type }}: {{ reassignResult()!.owner_id }}</p> }
          @if (reassignError()) { <p class="error-msg">{{ reassignError() }}</p> }
        </div>
      }
    </div>

    @if (!isLocked) {
    <div class="card">
      <div class="section-header"><h3>Entity Default Shares <span class="hint">— every record of one entity</span></h3></div>

      <div class="filter-bar">
        <select [(ngModel)]="defaultEntity">
          <option value="" disabled>Entity…</option>
          @for (e of entities(); track e.logicalname) {
            <option [value]="e.logicalname">{{ e.name }} ({{ e.logicalname }})</option>
          }
        </select>
        <button class="btn-primary" (click)="loadDefaultShares()" [disabled]="loadingDefaultShares()">
          {{ loadingDefaultShares() ? 'Loading…' : 'Load Defaults' }}
        </button>
      </div>
      @if (defaultSharesError()) { <p class="error-msg">{{ defaultSharesError() }}</p> }

      @if (defaultSharesLoaded()) {
        @if (defaultShares().length === 0) {
          <p class="state-msg">No entity-wide default shares configured for this entity.</p>
        } @else {
          <table class="nested-table">
            <thead>
              <tr><th>Principal</th><th>Capability</th><th>Granted</th><th></th></tr>
            </thead>
            <tbody>
              @for (s of defaultShares(); track s.id) {
                <tr>
                  <td>{{ s.principal_type }}: <span class="cell-mono">{{ s.principal_id }}</span></td>
                  <td><span class="badge" [class.badge-boolean]="s.capability !== 'deny'"
                            [class.badge-choice]="s.capability === 'deny'">{{ s.capability }}</span></td>
                  <td class="cell-muted">{{ s.granted_at ? (s.granted_at | date:'medium') : '—' }}</td>
                  <td class="actions">
                    <button class="btn-sm btn-sm-danger" (click)="deleteDefaultShare(s)">Revoke</button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        }

        <div class="inline-form-panel">
          <h4>Grant or Deny (applies to every record of this entity)</h4>
          <div class="form-row-3">
            <div class="field">
              <label for="default-share-principal-type">Principal type</label>
              <select id="default-share-principal-type" [(ngModel)]="newDefaultPrincipalType">
                <option value="user">User</option>
                <option value="team">Team</option>
              </select>
            </div>
            @if (newDefaultPrincipalType === 'user') {
              <div class="field">
                <label for="default-share-user-email">User email</label>
                <input id="default-share-user-email" [(ngModel)]="newDefaultUserEmail" [placeholder]="'recordShares.userEmailPlaceholder' | translate" autocomplete="off">
              </div>
            } @else {
              <div class="field">
                <label for="default-share-team-name">Team name</label>
                <input id="default-share-team-name" [(ngModel)]="newDefaultTeamName" [placeholder]="'recordShares.teamNamePlaceholder' | translate" autocomplete="off">
              </div>
            }
            <div class="field">
              <label for="default-share-capability">Capability</label>
              <select id="default-share-capability" [(ngModel)]="newDefaultCapability">
                <option value="view">View</option>
                <option value="action">Action (view + mutate)</option>
                <option value="deny">Deny (overrides any grant)</option>
              </select>
            </div>
          </div>
          <div class="btn-row">
            <button class="btn-sm btn-primary" (click)="createDefaultShare()" [disabled]="savingDefaultShare()">
              {{ savingDefaultShare() ? 'Saving…' : (newDefaultCapability === 'deny' ? 'Deny' : 'Grant') }}
            </button>
          </div>
          @if (defaultShareCreateError()) { <p class="error-msg">{{ defaultShareCreateError() }}</p> }
        </div>
      }
    </div>
    }
  `,
})
export class RecordSharesComponent implements OnInit {
  private readonly svc      = inject(SecurityAdminService);
  private readonly adminSvc = inject(AdminService);
  private readonly dialogSvc = inject(DialogService);

  /**
   * Pre-fills and hides the Record Shares entity/record-id picker, and hides
   * the Entity Default Shares section entirely — a caller embedding this as
   * one dashboard's Permissions tab (`@attome/xrm/dashboard`'s
   * `dashboard-editor`) wants exactly one record's shares, not a way to
   * grant access to every record of the entity. Both inputs must be set
   * together; either alone leaves the picker visible (nothing to lock onto
   * with just one half).
   */
  @Input() lockedEntity?: string;
  @Input() lockedRecordId?: string;

  get isLocked(): boolean {
    return !!this.lockedEntity && !!this.lockedRecordId;
  }

  readonly entities = signal<EntityMeta[]>([]);

  // ── Record shares (one specific record) ──────────────────────────────
  recordEntity = '';
  recordId = '';
  readonly loadingRecordShares = signal(false);
  readonly recordSharesLoaded  = signal(false);
  readonly recordSharesError   = signal<string | null>(null);
  readonly recordShares        = signal<RecordShareItem[]>([]);

  newSharePrincipalType: 'user' | 'team' = 'user';
  newShareUserEmail = '';
  newShareTeamName  = '';
  newShareCapability: ShareCapability = 'view';
  readonly savingRecordShare       = signal(false);
  readonly recordShareCreateError  = signal<string | null>(null);

  reassignPrincipalType: 'user' | 'team' = 'user';
  reassignUserEmail = '';
  reassignTeamName  = '';
  readonly reassigning     = signal(false);
  readonly reassignError   = signal<string | null>(null);
  readonly reassignResult  = signal<OwnerItem | null>(null);

  // ── Entity default shares (every record of one entity) ───────────────
  defaultEntity = '';
  readonly loadingDefaultShares = signal(false);
  readonly defaultSharesLoaded  = signal(false);
  readonly defaultSharesError   = signal<string | null>(null);
  readonly defaultShares        = signal<EntityDefaultShareItem[]>([]);

  newDefaultPrincipalType: 'user' | 'team' = 'user';
  newDefaultUserEmail = '';
  newDefaultTeamName  = '';
  newDefaultCapability: ShareCapability = 'view';
  readonly savingDefaultShare      = signal(false);
  readonly defaultShareCreateError = signal<string | null>(null);

  constructor() {
    this.adminSvc.listEntities().subscribe({ next: es => this.entities.set(es) });
  }

  ngOnInit(): void {
    // Inputs aren't populated until after construction — this is the first
    // hook that can safely read `lockedEntity`/`lockedRecordId`.
    if (this.isLocked) {
      this.recordEntity = this.lockedEntity!;
      this.recordId = this.lockedRecordId!;
      this.loadRecordShares();
    }
  }

  // ── Record shares ─────────────────────────────────────────────────────

  loadRecordShares(): void {
    const entity = this.recordEntity;
    const recordId = this.recordId.trim();
    if (!entity || !recordId) {
      this.recordSharesError.set('Select an entity and enter a record ID.');
      return;
    }
    this.loadingRecordShares.set(true);
    this.recordSharesError.set(null);
    this.reassignResult.set(null);
    this.svc.listRecordShares(entity, recordId).subscribe({
      next: ss => {
        this.recordShares.set(ss);
        this.recordSharesLoaded.set(true);
        this.loadingRecordShares.set(false);
      },
      error: (e: ApiError) => { this.loadingRecordShares.set(false); this.recordSharesError.set(e.message); },
    });
  }

  async createRecordShare(): Promise<void> {
    const entity = this.recordEntity;
    const record_id = this.recordId.trim();
    const user_email = this.newSharePrincipalType === 'user' ? this.newShareUserEmail.trim() : undefined;
    const team_name  = this.newSharePrincipalType === 'team' ? this.newShareTeamName.trim() : undefined;
    if (!entity || !record_id || (!user_email && !team_name)) {
      this.recordShareCreateError.set('Entity, record ID, and a principal are required.');
      return;
    }
    if (this.newShareCapability === 'deny') {
      const confirmed = await this.dialogSvc.confirm({
        message: 'This will DENY access even if another grant would otherwise allow it. Continue?',
        variant: 'danger',
        confirmText: 'Continue',
      });
      if (!confirmed) return;
    }
    this.savingRecordShare.set(true);
    this.recordShareCreateError.set(null);
    this.svc.createRecordShare({ entity, record_id, capability: this.newShareCapability, user_email, team_name }).subscribe({
      next: s => {
        this.recordShares.update(list => [s, ...list.filter(x => x.id !== s.id)]);
        this.savingRecordShare.set(false);
        this.newShareUserEmail = ''; this.newShareTeamName = '';
      },
      error: (e: ApiError) => { this.savingRecordShare.set(false); this.recordShareCreateError.set(e.message); },
    });
  }

  async deleteRecordShare(s: RecordShareItem): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({
      message: `Revoke this ${s.capability} share for ${s.principal_type} ${s.principal_id}?`,
      variant: 'danger',
      confirmText: 'Revoke',
    });
    if (!confirmed) return;
    this.svc.deleteRecordShare(s.id).subscribe({
      next:  () => this.recordShares.update(list => list.filter(x => x.id !== s.id)),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }

  async reassignOwner(): Promise<void> {
    const entity = this.recordEntity;
    const record_id = this.recordId.trim();
    const user_email = this.reassignPrincipalType === 'user' ? this.reassignUserEmail.trim() : undefined;
    const team_name  = this.reassignPrincipalType === 'team' ? this.reassignTeamName.trim() : undefined;
    if (!entity || !record_id || (!user_email && !team_name)) {
      this.reassignError.set('Entity, record ID, and a new owner are required.');
      return;
    }
    const confirmed = await this.dialogSvc.confirm({
      message: `Reassign ownership of this ${entity} record to ${user_email ?? team_name}?`,
      variant: 'primary',
      confirmText: 'Reassign',
    });
    if (!confirmed) return;
    this.reassigning.set(true);
    this.reassignError.set(null);
    this.svc.reassignOwner({ entity, record_id, user_email, team_name }).subscribe({
      next: owner => {
        this.reassignResult.set(owner);
        this.reassigning.set(false);
        this.loadRecordShares();
      },
      error: (e: ApiError) => { this.reassigning.set(false); this.reassignError.set(e.message); },
    });
  }

  // ── Entity default shares ─────────────────────────────────────────────

  loadDefaultShares(): void {
    const entity = this.defaultEntity;
    if (!entity) {
      this.defaultSharesError.set('Select an entity.');
      return;
    }
    this.loadingDefaultShares.set(true);
    this.defaultSharesError.set(null);
    this.svc.listEntityDefaultShares(entity).subscribe({
      next: ss => {
        this.defaultShares.set(ss);
        this.defaultSharesLoaded.set(true);
        this.loadingDefaultShares.set(false);
      },
      error: (e: ApiError) => { this.loadingDefaultShares.set(false); this.defaultSharesError.set(e.message); },
    });
  }

  async createDefaultShare(): Promise<void> {
    const entity = this.defaultEntity;
    const user_email = this.newDefaultPrincipalType === 'user' ? this.newDefaultUserEmail.trim() : undefined;
    const team_name  = this.newDefaultPrincipalType === 'team' ? this.newDefaultTeamName.trim() : undefined;
    if (!entity || (!user_email && !team_name)) {
      this.defaultShareCreateError.set('Entity and a principal are required.');
      return;
    }
    const confirmed = this.newDefaultCapability === 'deny'
      ? await this.dialogSvc.confirm({
          message: `This will DENY access to EVERY record of "${entity}" for this principal, even if another grant would otherwise allow it. Continue?`,
          variant: 'danger',
          confirmText: 'Continue',
        })
      : await this.dialogSvc.confirm({
          message: `This will grant "${this.newDefaultCapability}" access to EVERY record of "${entity}" for this principal. Continue?`,
          variant: 'primary',
          confirmText: 'Continue',
        });
    if (!confirmed) return;
    this.savingDefaultShare.set(true);
    this.defaultShareCreateError.set(null);
    this.svc.createEntityDefaultShare({ entity, capability: this.newDefaultCapability, user_email, team_name }).subscribe({
      next: s => {
        this.defaultShares.update(list => [s, ...list.filter(x => x.id !== s.id)]);
        this.savingDefaultShare.set(false);
        this.newDefaultUserEmail = ''; this.newDefaultTeamName = '';
      },
      error: (e: ApiError) => { this.savingDefaultShare.set(false); this.defaultShareCreateError.set(e.message); },
    });
  }

  async deleteDefaultShare(s: EntityDefaultShareItem): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({
      message: `Revoke this entity-wide ${s.capability} default for ${s.principal_type} ${s.principal_id}?`,
      variant: 'danger',
      confirmText: 'Revoke',
    });
    if (!confirmed) return;
    this.svc.deleteEntityDefaultShare(s.id).subscribe({
      next:  () => this.defaultShares.update(list => list.filter(x => x.id !== s.id)),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }
}
