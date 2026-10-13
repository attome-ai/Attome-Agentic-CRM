import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError } from '@attome/base';

import { OrganizationItem, OrganizationMemberItem, SecurityAdminService } from './security-admin.service';

@Component({
  selector: 'xrm-organizations-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../styles/admin-page.css'],
  template: `
    <div class="page-header">
      <div><h2>Organizations</h2><p class="subtitle">Business units and their current members.</p></div>
      <button class="btn-ghost" (click)="load()"><i class="las la-sync"></i> Refresh</button>
    </div>
    @if (loading()) { <p class="state-msg">Loading organizations…</p> }
    @else if (error()) { <p class="error-msg">{{ error() }}</p> }
    @else if (organizations().length === 0) { <div class="empty-state"><p>No organizations found.</p></div> }
    @else {
      <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>ID</th><th></th></tr></thead>
        <tbody>@for (organization of organizations(); track organization.id) {
          <tr><td>{{ organization.name ?? 'Unnamed organization' }}</td><td class="cell-mono">{{ organization.id }}</td>
            <td class="actions"><button class="btn-sm" (click)="toggleMembers(organization)">
              {{ selectedOrganization()?.id === organization.id ? 'Hide members' : 'View members' }}
            </button></td></tr>
          @if (selectedOrganization()?.id === organization.id) {
            <tr><td colspan="3"><div class="detail-panel">
              <h4>Members <span class="count">{{ members().length }}</span></h4>
              @if (membersLoading()) { <p class="state-msg">Loading members…</p> }
              @else if (members().length === 0) { <p class="state-msg">No members.</p> }
              @else { <table class="nested-table"><thead><tr><th>Email</th><th>User ID</th></tr></thead>
                <tbody>@for (member of members(); track member.id) {
                  <tr><td>{{ member.user_email ?? '—' }}</td><td class="cell-mono">{{ member.user_id }}</td></tr>
                }</tbody></table> }
            </div></td></tr>
          }
        }</tbody>
      </table></div>
    }
  `,
})
export class OrganizationsListComponent implements OnInit {
  private readonly svc = inject(SecurityAdminService);
  readonly organizations = signal<OrganizationItem[]>([]);
  readonly selectedOrganization = signal<OrganizationItem | null>(null);
  readonly members = signal<OrganizationMemberItem[]>([]);
  readonly loading = signal(true);
  readonly membersLoading = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listOrganizations().subscribe({
      next: organizations => { this.organizations.set(organizations); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  toggleMembers(organization: OrganizationItem): void {
    if (this.selectedOrganization()?.id === organization.id) {
      this.selectedOrganization.set(null);
      this.members.set([]);
      return;
    }
    this.selectedOrganization.set(organization);
    this.members.set([]);
    this.membersLoading.set(true);
    this.svc.listOrganizationMembers(organization.id).subscribe({
      next: members => { this.members.set(members); this.membersLoading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.membersLoading.set(false); },
    });
  }
}
