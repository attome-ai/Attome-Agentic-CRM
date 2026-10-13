import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, output, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { forkJoin } from 'rxjs';
import {
  ApiService, AuthService, LangService, LocalDatePipe, TranslatePipe,
  type ApiComponents, type ApiError,
} from '@attome/base';
import { DialogService } from '@attome/base/dialog';

type RoleItem               = ApiComponents['schemas']['RoleItem'];
type UserRoleItem           = ApiComponents['schemas']['UserRoleItem'];
type AssignUserRoleResponse = ApiComponents['schemas']['AssignUserRoleResponse'];
type EffectiveAccessPreview = ApiComponents['schemas']['EffectiveAccessPreview'];

const USERS = '/api/v1/admin/security/users';

/**
 * The user form's "Account & security" tab: the account-level operations the
 * generic record save cannot perform.
 *
 * `is_active` is a system-managed column (`attome_core::ALL_SYSTEM_COLS`),
 * so the generic PATCH drops it from the body — a switch bound to it saved
 * nothing. Suspending an account is `…/users/{id}/disable`, which also bumps
 * the auth epoch, revokes refresh tokens and deactivates the user's API keys
 * in one transaction (D-121); `…/enable` is its inverse. Neither touches
 * `row_version`, so the surrounding form's next save does not conflict.
 *
 * Direct role assignment goes through `…/users/{id}/roles`, never the
 * `user_account_mm_role` table generically, because that route carries
 * the four-eyes gate (`security.role_grant`): a 2xx may mean "submitted for
 * approval", not "assigned", and is reported as such.
 *
 * Calls `ApiService` directly rather than `SecurityAdminService` for the same
 * chunk reason `user-account-state.actions.ts` records: importing
 * `@attome/xrm/core/security` from this registration entry would pull that
 * entry's eight admin pages into this lazy chunk.
 */
@Component({
  selector: 'xrm-user-security-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, LocalDatePipe],
  styleUrls: ['../../../../../../styles/xrm-form.css', './user-security-panel.component.css'],
  templateUrl: './user-security-panel.component.html',
})
export class UserSecurityPanelComponent implements OnInit {
  readonly userId    = input.required<string>();
  /** `status`: the activate/deactivate section only (the form's Settings
   * tab). `access`: everything else (the Access tab). `all`: both. */
  readonly part      = input<'all' | 'status' | 'access'>('all');
  /** `user_account.last_login`, from the form's already-loaded record. */
  readonly lastLogin = input<string | null>(null);
  /** Emits the account's new state after a successful activate/deactivate, so the form header can follow. */
  readonly activeChange = output<boolean>();

  private readonly api    = inject(ApiService);
  private readonly auth   = inject(AuthService);
  private readonly lang   = inject(LangService);
  private readonly dialog = inject(DialogService);
  private readonly destroyRef = inject(DestroyRef);

  readonly loading   = signal(true);
  readonly loadError = signal<string | null>(null);
  /** Result of the last action, announced politely. */
  readonly notice    = signal<string | null>(null);
  /** Failure of the last action, announced as an alert. */
  readonly actionError = signal<string | null>(null);
  /** Key of the action in flight, so only its button shows progress. */
  readonly busy      = signal<string | null>(null);
  readonly refreshing = signal(false);

  readonly preview   = signal<EffectiveAccessPreview | null>(null);
  readonly userRoles = signal<UserRoleItem[]>([]);
  readonly allRoles  = signal<RoleItem[]>([]);
  selectedRoleId = '';

  /**
   * NULL is live on this table (every server predicate reads
   * `is_active IS NULL OR is_active = TRUE`), so only an explicit `false` is
   * inactive — the same reading `user-account-state.actions.ts` uses.
   */
  readonly isActive = computed(() => this.preview()?.is_active !== false);
  readonly isSelf   = computed(() => this.auth.userId() === this.userId());

  readonly assignableRoles = computed(() => {
    const held = new Set(this.userRoles().map(r => r.role_id));
    return this.allRoles()
      .filter(r => !held.has(r.id))
      .sort((a, b) => a.name.localeCompare(b.name));
  });

  ngOnInit(): void {
    this.load();
  }

  names(refs: { name: string }[]): string {
    return refs.map(r => r.name).join(', ');
  }

  load(): void {
    const id = this.userId();
    this.loading.set(true);
    this.loadError.set(null);
    forkJoin({
      preview:   this.api.get<EffectiveAccessPreview>(`${USERS}/${id}/effective-access`),
      userRoles: this.api.getAllPages<UserRoleItem>(`${USERS}/${id}/roles`),
      allRoles:  this.api.getAllPages<RoleItem>('/api/v1/admin/security/roles'),
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => {
        this.preview.set(r.preview);
        this.userRoles.set(r.userRoles);
        this.allRoles.set(r.allRoles);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.loadError.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  /**
   * Re-reads what the resolver now says, after a change that affects it.
   * Public for the Refresh control: team and direct-privilege changes happen
   * in the related grids beside this panel, which emit nothing.
   */
  refreshAccess(): void {
    const id = this.userId();
    this.refreshing.set(true);
    forkJoin({
      preview:   this.api.get<EffectiveAccessPreview>(`${USERS}/${id}/effective-access`),
      userRoles: this.api.getAllPages<UserRoleItem>(`${USERS}/${id}/roles`),
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => { this.preview.set(r.preview); this.userRoles.set(r.userRoles); this.refreshing.set(false); },
      error: (e: ApiError) => { this.actionError.set(this.lang.errorText(e)); this.refreshing.set(false); },
    });
  }

  private begin(key: string): void {
    this.busy.set(key);
    this.notice.set(null);
    this.actionError.set(null);
  }

  private fail(e: ApiError): void {
    this.busy.set(null);
    this.actionError.set(this.lang.errorText(e));
  }

  async toggleActive(): Promise<void> {
    if (this.busy() || (this.isActive() && this.isSelf())) return;
    const deactivate = this.isActive();
    const ok = await this.dialog.confirm({
      title:       this.lang.translate(deactivate ? 'userForm.security.deactivateTitle' : 'userForm.security.activateTitle'),
      message:     this.lang.translate(deactivate ? 'userForm.security.deactivateConfirm' : 'userForm.security.activateConfirm'),
      confirmText: this.lang.translate(deactivate ? 'userForm.security.deactivate' : 'userForm.security.activate'),
      variant:     deactivate ? 'danger' : 'primary',
    });
    if (!ok) return;
    this.begin('active');
    this.api.post<void>(`${USERS}/${this.userId()}/${deactivate ? 'disable' : 'enable'}`, {})
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: () => {
          this.busy.set(null);
          const p = this.preview();
          if (p) this.preview.set({ ...p, is_active: !deactivate });
          this.activeChange.emit(!deactivate);
          this.notice.set(this.lang.translate(deactivate ? 'userForm.security.deactivated' : 'userForm.security.activated'));
        },
        error: (e: ApiError) => this.fail(e),
      });
  }

  async resetMfa(): Promise<void> {
    if (this.busy()) return;
    const ok = await this.dialog.confirm({
      title:       this.lang.translate('userForm.security.resetMfaTitle'),
      message:     this.lang.translate('userForm.security.resetMfaConfirm'),
      confirmText: this.lang.translate('userForm.security.resetMfa'),
      variant:     'warning',
    });
    if (!ok) return;
    this.begin('mfa');
    this.api.post<void>(`${USERS}/${this.userId()}/mfa/reset`, {})
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: () => {
          this.busy.set(null);
          this.notice.set(this.lang.translate('userForm.security.mfaReset'));
        },
        // 404 is the handler's "no active enrollment" answer, not a missing user.
        error: (e: ApiError) => {
          if (e.kind === 'not_found') {
            this.busy.set(null);
            this.notice.set(this.lang.translate('userForm.security.noMfa'));
          } else {
            this.fail(e);
          }
        },
      });
  }

  assignRole(): void {
    const roleId = this.selectedRoleId;
    if (!roleId || this.busy()) return;
    this.begin('assign');
    this.api.post<AssignUserRoleResponse>(`${USERS}/${this.userId()}/roles`, { role_id: roleId })
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: r => {
          this.busy.set(null);
          this.selectedRoleId = '';
          const name = r.role_name ?? this.allRoles().find(x => x.id === roleId)?.name ?? '';
          this.notice.set(this.lang.translate(
            r.approval_pending ? 'userForm.security.roleApprovalPending' : 'userForm.security.roleAssigned',
            { name },
          ));
          if (!r.approval_pending) this.refreshAccess();
        },
        error: (e: ApiError) => this.fail(e),
      });
  }

  async removeRole(role: UserRoleItem): Promise<void> {
    if (this.busy()) return;
    const ok = await this.dialog.confirm({
      title:       this.lang.translate('userForm.security.removeRoleTitle'),
      message:     this.lang.translate('userForm.security.removeRoleConfirm', { name: role.role_name }),
      confirmText: this.lang.translate('userForm.security.removeRole'),
      variant:     'danger',
    });
    if (!ok) return;
    this.begin(`remove:${role.role_id}`);
    this.api.delete(`${USERS}/${this.userId()}/roles/${role.role_id}`)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: () => {
          this.busy.set(null);
          this.notice.set(this.lang.translate('userForm.security.roleRemoved', { name: role.role_name }));
          this.refreshAccess();
        },
        error: (e: ApiError) => this.fail(e),
      });
  }
}
