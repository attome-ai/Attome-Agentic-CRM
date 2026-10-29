import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import type { Page } from '@attome/base';
import type { Observable } from 'rxjs';

import { AdminSessionItem, RoleItem, SecurityAdminService, SessionsEnded } from './security-admin.service';

const PAGE_SIZE = 50;

/**
 * Q8-T9: live sessions (`admin/security/sessions`) over the Q8-T5 routes:
 * deployment-wide, narrowed to a role's holders or to one person, with
 * ending one session, every session of a person, or every session of a
 * role's holders (a large role is ended by a job).
 */
@Component({
  selector: 'xrm-sessions-admin',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css'],
  template: `
    <div class="page-header">
      <div><h2>{{ 'sessionsAdmin.title' | translate }}</h2><p class="subtitle">{{ 'sessionsAdmin.subtitle' | translate }}</p></div>
      <button type="button" class="btn-ghost" (click)="load()"><i class="las la-sync" aria-hidden="true"></i> {{ 'sessionsAdmin.refresh' | translate }}</button>
    </div>
    @if (error(); as message) { <p class="error-msg" role="alert">{{ message }}</p> }
    @if (notice(); as message) { <p class="state-msg" role="status" data-notice>{{ message }}</p> }

    <div class="filter-bar" role="search">
      <div class="field">
        <label for="sessions-role">{{ 'sessionsAdmin.role' | translate }}</label>
        <select id="sessions-role" (change)="onRole($event)" [value]="roleId()" data-testid="sessions-role">
          <option value="">{{ 'sessionsAdmin.allRoles' | translate }}</option>
          @for (r of roles(); track r.id) { <option [value]="r.id">{{ r.name }}</option> }
        </select>
      </div>
      <div class="field">
        <label for="sessions-user">{{ 'sessionsAdmin.user' | translate }}</label>
        <input id="sessions-user" dir="ltr" [value]="userId()" (change)="onUser($event)"
               [attr.placeholder]="'sessionsAdmin.userPlaceholder' | translate" data-testid="sessions-user">
      </div>
      @if (userId()) {
        <button type="button" class="btn-ghost" [disabled]="busy()" (click)="endAllOfUser()" data-testid="end-user">
          {{ 'sessionsAdmin.endAllOfUser' | translate }}
        </button>
      } @else if (roleId()) {
        <button type="button" class="btn-ghost" [disabled]="busy()" (click)="endAllOfRole()" data-testid="end-role">
          {{ 'sessionsAdmin.endAllOfRole' | translate }}
        </button>
      }
    </div>

    @if (loading()) { <p class="state-msg">{{ 'sessionsAdmin.loading' | translate }}</p> }
    @else if (rows().length === 0) { <div class="empty-state"><p>{{ 'sessionsAdmin.empty' | translate }}</p></div> }
    @else {
      <div class="table-wrap"><table>
        <thead><tr>
          <th scope="col">{{ 'sessionsAdmin.colUser' | translate }}</th>
          <th scope="col">{{ 'sessionsAdmin.colDevice' | translate }}</th>
          <th scope="col">{{ 'sessionsAdmin.colMethod' | translate }}</th>
          <th scope="col">{{ 'sessionsAdmin.colStarted' | translate }}</th>
          <th scope="col">{{ 'sessionsAdmin.colLastActive' | translate }}</th>
          <th scope="col">{{ 'sessionsAdmin.colActions' | translate }}</th>
        </tr></thead>
        <tbody>@for (s of rows(); track s.id) {
          <tr [attr.data-session]="s.id">
            <td dir="ltr">{{ s.user_email ?? s.user_id }}</td>
            <td [attr.title]="s.user_agent">{{ s.device_label ?? ('sessionsAdmin.unknownDevice' | translate) }}</td>
            <td class="cell-mono">{{ s.sign_in_method ?? '—' }}</td>
            <td class="cell-muted">{{ s.created_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}</td>
            <td class="cell-muted">
              @if (s.last_activity_at) { {{ s.last_activity_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }} } @else { — }
            </td>
            <td><button type="button" class="btn-text" [disabled]="busy()" (click)="end(s)">{{ 'sessionsAdmin.end' | translate }}</button></td>
          </tr>
        }</tbody>
      </table></div>
      <div class="pager">
        <button type="button" class="btn-text" [disabled]="page() <= 1 || loading()" (click)="go(page() - 1)">{{ 'sessionsAdmin.prev' | translate }}</button>
        <button type="button" class="btn-text" [disabled]="page() * pageSize >= total() || loading()" (click)="go(page() + 1)">{{ 'sessionsAdmin.next' | translate }}</button>
      </div>
    }
  `,
})
export class SessionsAdminComponent implements OnInit {
  private readonly svc = inject(SecurityAdminService);
  private readonly lang = inject(LangService);
  private readonly confirm = inject(ConfirmService);

  readonly pageSize = PAGE_SIZE;
  readonly rows = signal<AdminSessionItem[]>([]);
  readonly roles = signal<RoleItem[]>([]);
  readonly roleId = signal('');
  readonly userId = signal('');
  readonly page = signal(1);
  readonly total = signal(0);
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  ngOnInit(): void {
    this.svc.listRoles().subscribe({ next: r => this.roles.set(r), error: () => this.roles.set([]) });
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    const user = this.userId().trim();
    const page$: Observable<Page<AdminSessionItem>> = user
      ? this.svc.listUserSessions(user, this.page(), PAGE_SIZE)
      : this.svc.listSessions(this.roleId() || undefined, this.page(), PAGE_SIZE);
    page$.subscribe({
      next: p => { this.rows.set(p.items); this.total.set(p.total); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
  }

  go(page: number): void {
    this.page.set(page);
    this.load();
  }

  onRole(event: Event): void {
    this.roleId.set((event.target as HTMLSelectElement).value);
    this.page.set(1);
    this.load();
  }

  onUser(event: Event): void {
    this.userId.set((event.target as HTMLInputElement).value.trim());
    this.page.set(1);
    this.load();
  }

  end(session: AdminSessionItem): void {
    this.run(this.svc.endSession(session.id), () => null);
  }

  endAllOfUser(): void {
    this.run(this.svc.revokeUserSessions(this.userId()), r => this.endedText(r));
  }

  async endAllOfRole(): Promise<void> {
    const ok = await this.confirm.confirm({
      title: this.lang.translate('sessionsAdmin.endAllOfRole'),
      message: this.lang.translate('sessionsAdmin.confirmRole'),
      confirmText: this.lang.translate('sessionsAdmin.end'),
      cancelText: this.lang.translate('sessionsAdmin.cancel'),
      variant: 'warning',
    });
    if (!ok) return;
    this.run(this.svc.revokeRoleSessions(this.roleId()), r => this.endedText(r));
  }

  private endedText(result: SessionsEnded): string {
    return result.queued
      ? this.lang.translate('sessionsAdmin.queued')
      : this.lang.translate('sessionsAdmin.ended', { count: result.ended_users });
  }

  private run<T>(call: Observable<T>, notice: (result: T) => string | null): void {
    this.busy.set(true);
    this.notice.set(null);
    call.subscribe({
      next: result => { this.busy.set(false); this.notice.set(notice(result)); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
