import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '@attome/base';

interface SecurityAdminLink {
  path:  string[];
  title: string;
  desc:  string;
  group: string;
}

/// Landing page for the RLS/team/share administration UI (item 19). Ties
/// together every security admin screen — the pre-existing ones
/// (privilege grants, role privileges, field-security profiles, MFA, my
/// access) and this pass's additions (role access levels, user access,
/// teams, record shares) — and explains the three views the backend
/// (D-133/D-134) draws a hard line between: Configured, Effective, and
/// Record-specific. The backend remains the sole authority on all three;
/// nothing here reimplements `attome_security::rls_predicate` or the resolver.
@Component({
  selector:   'attome-security-admin-overview',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [RouterLink, TranslatePipe],
  styleUrls:  ['../../styles/admin-page.css'],
  template: `

    <div class="page-header">
      <div>
        <h2>{{ 'securityOverview.title' | translate }}</h2>
        <p class="subtitle">
          {{ 'securityOverview.subtitle' | translate }}
        </p>
      </div>
    </div>

    <div class="card">
      <h3>{{ 'securityOverview.threeViews' | translate }}</h3>
      <p>
        <strong>{{ 'securityOverview.configured' | translate }}</strong>
        {{ 'securityOverview.configuredDesc' | translate }}
        <strong>{{ 'securityOverview.effective' | translate }}</strong>
        {{ 'securityOverview.effectiveDesc' | translate }}
        <strong>{{ 'securityOverview.recordSpecific' | translate }}</strong>
        {{ 'securityOverview.recordSpecificDesc' | translate }}
      </p>
    </div>

    <div class="card">
      <h3>{{ 'securityOverview.knownLimitation' | translate }}</h3>
      <p class="warn-msg">
        {{ 'securityOverview.expiryNote' | translate }}
      </p>
    </div>

    @for (group of groups; track group) {
      <div class="card">
        <h3>{{ group }}</h3>
        <div class="table-wrap">
          <table>
            <tbody>
              @for (l of linksIn(group); track l.title) {
                <tr>
                  <td style="width: 220px">
                    <a class="cell-link" [routerLink]="l.path">{{ l.title }}</a>
                  </td>
                  <td class="cell-muted">{{ l.desc }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </div>
    }
  `,
})
export class SecurityAdminOverviewComponent {
  private readonly links: SecurityAdminLink[] = [
    { group: 'Roles', title: 'Roles', desc: 'The unified Role form — privilege grants, record access, assignments, and notes for one role.', path: ['/xrm/core/role/list'] },
    { group: 'Roles', title: 'Role Access Levels', desc: 'How far a role\'s read/write/delete reach extends, per entity (None/Team/Business Unit/Global).', path: ['/xrm/admin/security/role-entity-access'] },
    { group: 'Roles', title: 'Field Security Profiles', desc: 'Per-field read grants for sensitive attributes, assigned to roles.', path: ['/xrm/admin/security/field-profiles'] },
    { group: 'Users', title: 'User Access', desc: 'Direct role assignment, business-unit membership, and effective access preview for one user.', path: ['/xrm/admin/security/users'] },
    { group: 'Users', title: 'Privileges', desc: 'The full privilege catalog — every key a role or user grant can assign.', path: ['/xrm/core/privilege/list'] },
    { group: 'Users', title: 'My Access', desc: 'What the current session is authorized to do.', path: ['/xrm/admin/security/whoami'] },
    { group: 'Users', title: 'MFA', desc: 'Manage your own two-factor enrollment.', path: ['/xrm/admin/security/mfa'] },
    { group: 'Teams', title: 'Teams', desc: 'Browse and edit team records.', path: ['/xrm/core/team/list'] },
    { group: 'Sharing', title: 'Record Shares', desc: 'Per-record shares/denies, entity-wide default shares, and owner reassignment.', path: ['/xrm/admin/security/record-shares'] },
  ];

  readonly groups = ['Roles', 'Users', 'Teams', 'Sharing'];

  linksIn(group: string): SecurityAdminLink[] {
    return this.links.filter(l => l.group === group);
  }
}
