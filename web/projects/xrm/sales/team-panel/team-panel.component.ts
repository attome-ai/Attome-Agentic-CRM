import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { forkJoin, Observable } from 'rxjs';
import { SalesApiService } from '../sales-api.service';
import { PickOption, SalesTeamApiService, TeamAccess, TeamMember } from '../team-api';

/** The feature that turns deal teams on. */
export const TEAM_FLAG = 'sales.deal_teams';

/**
 * D7-T7: an opportunity's team, as its Team tab. Lists each member with role
 * and access; adds a person with a role and access, removes one, and copies
 * the account team's members with the given account roles. The server checks
 * that a member's own roles allow the access and keeps the owner on the team.
 */
@Component({
  selector: 'xrm-sales-team-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './team-panel.component.html',
  styleUrl: './team-panel.component.css',
})
export class TeamPanelComponent {
  private readonly sales = inject(SalesApiService);
  private readonly team = inject(SalesTeamApiService);
  private readonly lang = inject(LangService);

  readonly entityName = input('opportunity');
  readonly recordId = input<string | null>(null);

  readonly on = signal<boolean | null>(null);
  readonly members = signal<TeamMember[]>([]);
  readonly roles = signal<PickOption[]>([]);
  readonly users = signal<PickOption[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  readonly notice = signal<string | null>(null);

  readonly newUser = signal('');
  readonly newRole = signal('');
  readonly newAccess = signal<TeamAccess>('read');
  readonly copyRoles = signal('account_manager');

  readonly accessLevels: readonly TeamAccess[] = ['read', 'edit'];

  private readonly userNames = computed(() => new Map(this.users().map(u => [u.id, u.label])));
  private readonly roleNames = computed(() => new Map(this.roles().map(r => [r.id, r.label])));

  constructor() {
    effect(() => {
      const id = this.recordId();
      if (id) this.load(id);
    });
  }

  private load(id: string): void {
    this.sales.featureOn(TEAM_FLAG).subscribe({
      next: on => {
        this.on.set(on);
        if (on) this.reload(id);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e) || null),
    });
  }

  private reload(id: string): void {
    forkJoin({ members: this.team.members(id), roles: this.team.roles(), users: this.team.users() }).subscribe({
      next: r => {
        this.members.set(r.members);
        this.roles.set(r.roles);
        this.users.set(r.users);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e) || null),
    });
  }

  userLabel(m: TeamMember): string {
    return (m.user_ref && this.userNames().get(m.user_ref)) ?? m.user_ref ?? m.partner_contact_ref ?? '';
  }

  roleLabel(m: TeamMember): string {
    return (m.team_role_ref && this.roleNames().get(m.team_role_ref)) ?? '';
  }

  accessKey(level: string | null): string {
    return level === 'edit' ? 'xrm.sales.team.accessEdit' : 'xrm.sales.team.accessRead';
  }

  add(): void {
    const id = this.recordId();
    const user = this.newUser();
    const role = this.newRole();
    if (!id || !user || !role) {
      this.error.set(this.lang.translate('xrm.sales.team.pickBoth'));
      return;
    }
    this.run(this.team.addMember(id, { user_ref: user, team_role_ref: role, access_level: this.newAccess() }), id);
  }

  remove(member: TeamMember): void {
    const id = this.recordId();
    if (id) this.run(this.team.removeMember(id, member.id), id);
  }

  copy(): void {
    const id = this.recordId();
    const roles = this.copyRoles().split(',').map(r => r.trim()).filter(r => r.length > 0);
    if (!id || roles.length === 0) return;
    this.busy.set(true);
    this.error.set(null);
    this.team.copyAccountTeam(id, roles).subscribe({
      next: r => {
        this.busy.set(false);
        this.notice.set(this.lang.translate('xrm.sales.team.copied', { added: r.added, skipped: r.skipped }));
        this.reload(id);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e) || null);
      },
    });
  }

  private run(call: Observable<unknown>, id: string): void {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
    call.subscribe({
      next: () => {
        this.busy.set(false);
        this.newUser.set('');
        this.reload(id);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e) || null);
      },
    });
  }
}
