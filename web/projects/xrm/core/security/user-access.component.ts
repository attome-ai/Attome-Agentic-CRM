import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ImpersonationService, LangService, TranslatePipe } from '@attome/base';
import { Router } from '@angular/router';
import { DialogService } from '@attome/base/dialog';
import { FeatureFlagsService } from '@attome/xrm/core/admin/data';

import {
  EffectiveAccessPreview,
  OrganizationItem,
  RoleItem,
  SECURITY_FLAGS,
  SecurityAdminService,
  endOfDay,
} from './security-admin.service';

interface UserLookupResult {
  id:     string;
  email?: string | null;
}

/// The RLS admin UI's user-centric page: look a user up, then edit their
/// "Configured" access (direct role assignments, business-unit/organization
/// membership — team membership itself is edited on the Teams page, shown
/// here read-only since it also feeds this user's resolution) side by side
/// with their live "Effective" access (privileges/org reach/subordinates as
/// `attome_security::resolve_uncached` actually resolves them, right now,
/// bypassing every cache layer). Record-specific exceptions (per-record
/// shares/denies) are deliberately NOT here — those live on the Record
/// Shares page, scoped to one (entity, record), not one user.
@Component({
  selector:   'xrm-user-access',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, TranslatePipe],
  styleUrls:  ['../../styles/admin-page.css'],
  template: `

    <div class="page-header">
      <div>
        <h2>{{ 'userAccess.title' | translate }}</h2>
        <p class="subtitle">
          {{ 'userAccess.subtitle' | translate }}
        </p>
      </div>
    </div>

    <div class="card">
      <h3>Find a User</h3>
      <div class="filter-bar">
        <input class="search" [(ngModel)]="searchEmail" (keyup.enter)="search()"
               [placeholder]="'userAccess.searchPlaceholder' | translate" autocomplete="off">
        <button class="btn-primary" (click)="search()" [disabled]="searching()">
          {{ searching() ? 'Searching…' : 'Search' }}
        </button>
      </div>
      @if (searchError()) { <p class="error-msg">{{ searchError() }}</p> }
      @if (results().length > 0) {
        <div class="table-wrap">
          <table>
            <thead><tr><th>Email</th><th></th></tr></thead>
            <tbody>
              @for (u of results(); track u.id) {
                <tr>
                  <td>{{ u.email ?? u.id }}</td>
                  <td class="actions">
                    <button class="btn-sm btn-sm-accent" (click)="select(u)">View Access</button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </div>

    @if (loadingPreview()) {
      <p class="state-msg">Resolving access…</p>
    } @else if (previewError()) {
      <p class="error-msg">{{ previewError() }}</p>
    } @else if (preview(); as p) {

      <div class="card">
        <h3>
          {{ p.user_email ?? p.user_id }}
          @if (p.is_active === false) {
            <span class="badge badge-choice">Disabled</span>
          }
        </h3>
        <p class="cell-mono cell-muted">{{ p.user_id }}</p>
        <!-- Q13-T2: see or act as this person, with a reason. -->
        <div class="form-row-2 inline-form-panel">
          <div class="field">
            <label for="ua-imp-reason">{{ 'impersonation.reason' | translate }}</label>
            <input id="ua-imp-reason" [(ngModel)]="impersonationReason">
          </div>
          <div class="btn-row">
            <button class="btn-sm" (click)="impersonate(p, 'view')" [disabled]="impersonating()">
              {{ 'impersonation.viewAs' | translate }}
            </button>
            <button class="btn-sm" (click)="impersonate(p, 'act')" [disabled]="impersonating()">
              {{ 'impersonation.actAs' | translate }}
            </button>
          </div>
        </div>
        <p class="hint">{{ 'impersonation.hint' | translate }}</p>
        @if (impersonationError()) { <p class="error-msg" role="alert">{{ impersonationError() }}</p> }
      </div>

      <div class="card">
        <div class="section-header">
          <h3>Configured Access</h3>
        </div>

        <h4>Direct Roles <span class="count">{{ p.configured.direct_roles.length }}</span></h4>
        @if (p.configured.direct_roles.length === 0) {
          <p class="state-msg">No roles assigned directly (team-mediated roles are listed below).</p>
        } @else {
          <table class="nested-table">
            <thead><tr><th>Role</th><th></th></tr></thead>
            <tbody>
              @for (r of p.configured.direct_roles; track r.id) {
                <tr>
                  <td>{{ r.name }}</td>
                  <td class="actions">
                    <button class="btn-sm btn-sm-danger" (click)="removeRole(r)">Remove</button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        }
        <div class="form-row-2 inline-form-panel">
          <div class="field">
            <label for="ua-assign-role">Assign a role directly</label>
            <select id="ua-assign-role" [(ngModel)]="assignRoleId">
              <option value="" disabled>Select a role…</option>
              @for (r of roles(); track r.id) {
                <option [value]="r.id">{{ r.name }}</option>
              }
            </select>
          </div>
          @if (showEndDates()) {
            <div class="field">
              <label for="ua-assign-until">{{ 'userAccess.validUntil' | translate }}</label>
              <input id="ua-assign-until" type="date" [(ngModel)]="assignUntil">
            </div>
          }
        </div>
        @if (showEndDates()) {
          <div class="form-row-1">
            <div class="field">
              <label for="ua-assign-reason">{{ 'userAccess.reason' | translate }}</label>
              <input id="ua-assign-reason" [(ngModel)]="assignReason">
            </div>
          </div>
        }
        <div class="btn-row">
          <button class="btn-sm btn-primary" (click)="addRole()" [disabled]="savingRole()">
            {{ savingRole() ? 'Assigning…' : 'Assign' }}
          </button>
        </div>
        @if (roleError()) { <p class="error-msg">{{ roleError() }}</p> }

        <h4>Business Units <span class="count">{{ p.configured.organizations.length }}</span></h4>
        <p class="hint">
          {{ 'userAccess.businessUnitsHint' | translate }}
        </p>
        @if (p.configured.organizations.length === 0) {
          <p class="state-msg">Not a member of any organization.</p>
        } @else {
          <table class="nested-table">
            <thead><tr><th>Organization</th><th></th></tr></thead>
            <tbody>
              @for (o of p.configured.organizations; track o.id) {
                <tr>
                  <td>{{ o.name ?? o.id }}</td>
                  <td class="actions">
                    <button class="btn-sm btn-sm-danger" (click)="removeOrg(o)">Remove</button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        }
        <div class="form-row-2 inline-form-panel">
          <div class="field">
            <label for="ua-assign-org">Add to business unit</label>
            <select id="ua-assign-org" [(ngModel)]="assignOrgId">
              <option value="" disabled>Select an organization…</option>
              @for (o of organizations(); track o.id) {
                <option [value]="o.id">{{ o.name ?? o.id }}</option>
              }
            </select>
          </div>
        </div>
        <div class="btn-row">
          <button class="btn-sm btn-primary" (click)="addOrg()" [disabled]="savingOrg()">
            {{ savingOrg() ? 'Adding…' : 'Add' }}
          </button>
        </div>
        @if (orgError()) { <p class="error-msg">{{ orgError() }}</p> }
        <p class="hint">
          {{ 'userAccess.expiryHint' | translate }}
        </p>

        <h4>Team Memberships <span class="count">{{ p.configured.teams.length }}</span></h4>
        <p class="hint">Read-only here — edit team membership and team-role assignment on the Teams page.</p>
        @if (p.configured.teams.length === 0) {
          <p class="state-msg">Not a member of any team.</p>
        } @else {
          <table class="nested-table">
            <thead><tr><th>Team</th><th>Roles granted via this team</th></tr></thead>
            <tbody>
              @for (t of p.configured.teams; track t.id) {
                <tr>
                  <td>{{ t.name }}</td>
                  <td>{{ t.roles.length > 0 ? t.roles.map(r => r.name).join(', ') : '—' }}</td>
                </tr>
              }
            </tbody>
          </table>
        }

        @if (p.configured.position) {
          <h4>Position</h4>
          <p>{{ p.configured.position.name }} <span class="hint">(F138 position hierarchy)</span></p>
        }
      </div>

      <div class="card">
        <div class="section-header">
          <h3>Effective Access <span class="hint">— resolved live, uncached</span></h3>
          <button class="btn-sm" (click)="refresh()">Refresh</button>
        </div>
        <p>
          {{ 'userAccess.admin' | translate }}
          @if (p.effective.is_admin) {
            <span class="badge badge-boolean">Yes — system.admin</span>
          } @else {
            <span class="badge">No</span>
          }
        </p>
        <p>
          {{ 'userAccess.positionHierarchy' | translate }}
          @if (p.effective.position_hierarchy_enabled) {
            <span class="badge badge-boolean">Enabled — reaches {{ p.effective.subordinate_user_ids.length }} subordinate(s)</span>
          } @else {
            <span class="badge">Disabled</span>
          }
        </p>
        <p>Effective team reach: <strong>{{ p.effective.team_ids.length }}</strong> team(s)</p>
        <p>Effective business-unit reach: <strong>{{ p.effective.accessible_org_ids.length }}</strong> organization(s) (including sub-orgs)</p>

        <h4>Resolved Privileges <span class="count">{{ p.effective.privileges.length }}</span></h4>
        @if (p.effective.privileges.length === 0) {
          <p class="state-msg">No privileges held (and not an admin).</p>
        } @else {
          <table class="nested-table">
            <thead><tr><th>Key</th></tr></thead>
            <tbody>
              @for (k of p.effective.privileges; track k) { <tr><td class="cell-mono">{{ k }}</td></tr> }
            </tbody>
          </table>
        }
      </div>
    }
  `,
})
export class UserAccessComponent {
  private readonly svc = inject(SecurityAdminService);
  private readonly dialogSvc = inject(DialogService);
  private readonly flags = inject(FeatureFlagsService);
  private readonly impersonation = inject(ImpersonationService);
  private readonly router = inject(Router);
  private readonly lang = inject(LangService);

  /** Q13-T2: why, kept with the session. */
  impersonationReason = '';
  readonly impersonating = signal(false);
  readonly impersonationError = signal<string | null>(null);

  searchEmail = '';

  readonly searching    = signal(false);
  readonly searchError  = signal<string | null>(null);
  readonly results      = signal<UserLookupResult[]>([]);

  readonly loadingPreview = signal(false);
  readonly previewError   = signal<string | null>(null);
  readonly preview        = signal<EffectiveAccessPreview | null>(null);

  readonly roles         = signal<RoleItem[]>([]);
  readonly organizations = signal<OrganizationItem[]>([]);

  readonly savingRole = signal(false);
  readonly roleError  = signal<string | null>(null);
  readonly savingOrg  = signal(false);
  readonly orgError   = signal<string | null>(null);

  assignRoleId = '';
  assignOrgId  = '';
  /** Q10-T12: the grant's end date (`yyyy-mm-dd`) and reason, behind `security.grant_end_dates`. */
  assignUntil  = '';
  assignReason = '';
  readonly showEndDates = computed(() => this.flags.flags()[SECURITY_FLAGS.grantEndDates] === true);

  constructor() {
    this.flags.ensureLoaded();
    this.svc.listRoles().subscribe({ next: rs => this.roles.set(rs) });
    this.svc.listOrganizations().subscribe({ next: os => this.organizations.set(os) });
  }

  search(): void {
    const email = this.searchEmail.trim();
    if (!email) {
      this.searchError.set('Enter an email (or part of one) to search.');
      return;
    }
    this.searching.set(true);
    this.searchError.set(null);
    this.svc.findUserByEmail(email).subscribe({
      next:  rs => { this.results.set(rs); this.searching.set(false); },
      error: (e: ApiError) => { this.searching.set(false); this.searchError.set(e.message); },
    });
  }

  select(u: UserLookupResult): void {
    this.results.set([]);
    this.loadPreview(u.id);
  }

  refresh(): void {
    const id = this.preview()?.user_id;
    if (id) this.loadPreview(id);
  }

  private loadPreview(userId: string): void {
    this.loadingPreview.set(true);
    this.previewError.set(null);
    this.svc.effectiveAccessPreview(userId).subscribe({
      next:  p => { this.preview.set(p); this.loadingPreview.set(false); },
      error: (e: ApiError) => { this.loadingPreview.set(false); this.previewError.set(e.message); },
    });
  }

  addRole(): void {
    const p = this.preview();
    if (!p || !this.assignRoleId) {
      this.roleError.set('Select a role.');
      return;
    }
    this.savingRole.set(true);
    this.roleError.set(null);
    const withDates = this.showEndDates();
    this.svc.assignUserRole(p.user_id, {
      role_id: this.assignRoleId,
      valid_until: withDates ? endOfDay(this.assignUntil) : null,
      reason: withDates ? this.assignReason.trim() || null : null,
    }).subscribe({
      next:  () => {
        this.savingRole.set(false);
        this.assignRoleId = ''; this.assignUntil = ''; this.assignReason = '';
        this.loadPreview(p.user_id);
      },
      error: (e: ApiError) => { this.savingRole.set(false); this.roleError.set(e.message); },
    });
  }

  async removeRole(r: { id: string; name: string }): Promise<void> {
    const p = this.preview();
    if (!p) return;
    const confirmed = await this.dialogSvc.confirm({
      message: `Remove role "${r.name}" from ${p.user_email ?? p.user_id}?`,
      variant: 'danger',
      confirmText: 'Remove',
    });
    if (!confirmed) return;
    this.svc.removeUserRole(p.user_id, r.id).subscribe({
      next:  () => this.loadPreview(p.user_id),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }

  addOrg(): void {
    const p = this.preview();
    if (!p || !this.assignOrgId) {
      this.orgError.set('Select an organization.');
      return;
    }
    if (!p.user_email) {
      this.orgError.set('This user has no email on file — cannot resolve the membership request.');
      return;
    }
    this.savingOrg.set(true);
    this.orgError.set(null);
    this.svc.addOrganizationMember(this.assignOrgId, { user_email: p.user_email }).subscribe({
      next:  () => { this.savingOrg.set(false); this.assignOrgId = ''; this.loadPreview(p.user_id); },
      error: (e: ApiError) => { this.savingOrg.set(false); this.orgError.set(e.message); },
    });
  }

  async removeOrg(o: { id: string; name?: string | null }): Promise<void> {
    const p = this.preview();
    if (!p) return;
    const confirmed = await this.dialogSvc.confirm({
      message: `Remove ${p.user_email ?? p.user_id} from business unit "${o.name ?? o.id}"?`,
      variant: 'danger',
      confirmText: 'Remove',
    });
    if (!confirmed) return;
    this.svc.removeOrganizationMember(o.id, p.user_id).subscribe({
      next:  () => this.loadPreview(p.user_id),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }

  /** Q13-T2: starts a session as the person and opens the app as them. */
  impersonate(p: EffectiveAccessPreview, mode: 'view' | 'act'): void {
    const reason = this.impersonationReason.trim();
    if (!reason) {
      this.impersonationError.set(this.lang.translate('impersonation.reasonRequired'));
      return;
    }
    this.impersonating.set(true);
    this.impersonationError.set(null);
    this.impersonation.start(p.user_id, mode, reason, p.user_email ?? undefined).subscribe({
      next: () => {
        this.impersonating.set(false);
        this.impersonationReason = '';
        void this.router.navigate(['/xrm']);
      },
      error: (e: ApiError) => {
        this.impersonating.set(false);
        this.impersonationError.set(this.lang.errorText(e));
      },
    });
  }
}
