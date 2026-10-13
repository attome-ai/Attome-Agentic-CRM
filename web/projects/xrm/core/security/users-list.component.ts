import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';

import { SecurityAdminService, UserListItem } from './security-admin.service';

@Component({
  selector: 'xrm-users-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css'],
  template: `
    <div class="page-header">
      <div><h2>{{ 'usersList.title' | translate }}</h2><p class="subtitle">{{ 'usersList.subtitle' | translate }}</p></div>
      <button class="btn-ghost" (click)="load()"><i class="las la-sync"></i> {{ 'usersList.refresh' | translate }}</button>
    </div>
    <div class="create-panel">
      <div class="field"><label for="users-filter">{{ 'usersList.searchUsers' | translate }}</label>
        <input id="users-filter" [(ngModel)]="filter" [placeholder]="'usersList.filterPlaceholder' | translate" autocomplete="off">
      </div>
    </div>
    @if (loading()) { <p class="state-msg">{{ 'usersList.loading' | translate }}</p> }
    @else if (error()) { <p class="error-msg">{{ error() }}</p> }
    @else if (filteredUsers().length === 0) { <div class="empty-state"><p>{{ 'usersList.empty' | translate }}</p></div> }
    @else {
      <div class="table-wrap"><table>
        <thead><tr><th>{{ 'usersList.colName' | translate }}</th><th>{{ 'usersList.colEmail' | translate }}</th><th>{{ 'usersList.colStatus' | translate }}</th><th>{{ 'usersList.colId' | translate }}</th></tr></thead>
        <tbody>@for (user of filteredUsers(); track user.id) {
          <tr><td>{{ user.user_name ?? '—' }}</td><td>{{ user.email ?? '—' }}</td>
            <td>{{ (user.is_active ? 'usersList.active' : 'usersList.inactive') | translate }}</td><td class="cell-mono">{{ user.id }}</td></tr>
        }</tbody>
      </table></div>
    }
  `,
})
export class UsersListComponent implements OnInit {
  private readonly svc = inject(SecurityAdminService);
  readonly users = signal<UserListItem[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  filter = '';

  filteredUsers(): UserListItem[] {
    const needle = this.filter.trim().toLowerCase();
    if (!needle) return this.users();
    return this.users().filter(user =>
      (user.user_name ?? '').toLowerCase().includes(needle) ||
      (user.email ?? '').toLowerCase().includes(needle));
  }

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.users.set([]);
    this.loadPage(1);
  }

  // Backend now paginates (was a flat `LIMIT 500` with no way to see past
  // row 500 — admins past that row were simply invisible with no signal
  // truncation had happened). This screen still shows "all users" with
  // client-side search, so it walks every page and accumulates rather than
  // exposing pager controls.
  private loadPage(page: number): void {
    this.svc.listUsers(page).subscribe({
      next: res => {
        this.users.update(existing => [...existing, ...res.items]);
        if (res.page_size > 0 && page * res.page_size < res.total) {
          this.loadPage(page + 1);
        } else {
          this.loading.set(false);
        }
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }
}
