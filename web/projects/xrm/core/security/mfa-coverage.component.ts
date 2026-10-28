import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import { MfaCoverageRow, MfaCoverageSummary, RoleItem, SecurityAdminService } from './security-admin.service';

/**
 * Q5-T10: second-factor coverage (`admin/security/mfa-coverage`), over the
 * Q5-T9 report: per role, how many members have a second factor, and the
 * accounts with their factors, filtered by role or to those with none.
 * Administrators missing a phishing-resistant factor are marked.
 */
@Component({
  selector: 'xrm-mfa-coverage',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../../styles/admin-page.css'],
  template: `
    <div class="page-header">
      <div><h2>{{ 'mfaCoverage.title' | translate }}</h2><p class="subtitle">{{ 'mfaCoverage.subtitle' | translate }}</p></div>
      <button type="button" class="btn-ghost" (click)="load()"><i class="las la-sync"></i> {{ 'mfaCoverage.refresh' | translate }}</button>
    </div>
    @if (error(); as message) { <p class="error-msg" role="alert">{{ message }}</p> }

    <div class="table-wrap"><table>
      <thead><tr>
        <th>{{ 'mfaCoverage.colRole' | translate }}</th><th>{{ 'mfaCoverage.colUsers' | translate }}</th>
        <th>{{ 'mfaCoverage.colWithTotp' | translate }}</th><th>{{ 'mfaCoverage.colWithout' | translate }}</th>
      </tr></thead>
      <tbody>@for (s of summary(); track s.role_id ?? 'none') {
        <tr [attr.data-summary]="s.role_id ?? 'none'">
          <td>{{ s.role ?? ('mfaCoverage.noRole' | translate) }}</td><td>{{ s.users }}</td>
          <td>{{ s.with_totp }}</td><td [class.cell-muted]="s.without_mfa === 0">{{ s.without_mfa }}</td>
        </tr>
      }</tbody>
    </table></div>

    <div class="filter-bar" role="search">
      <div class="field">
        <label for="mfa-coverage-role">{{ 'mfaCoverage.role' | translate }}</label>
        <select id="mfa-coverage-role" (change)="onRole($event)" [value]="roleId()" data-testid="coverage-role">
          <option value="">{{ 'mfaCoverage.allRoles' | translate }}</option>
          @for (r of roles(); track r.id) { <option [value]="r.id">{{ r.name }}</option> }
        </select>
      </div>
      <label class="checkbox-row">
        <input type="checkbox" [checked]="missingOnly()" (change)="onMissingOnly($event)" data-testid="coverage-missing">
        {{ 'mfaCoverage.missingOnly' | translate }}
      </label>
    </div>

    @if (loading()) { <p class="state-msg">{{ 'mfaCoverage.loading' | translate }}</p> }
    @else if (rows().length === 0) { <div class="empty-state"><p>{{ 'mfaCoverage.empty' | translate }}</p></div> }
    @else {
      <div class="table-wrap"><table>
        <thead><tr>
          <th>{{ 'mfaCoverage.colEmail' | translate }}</th><th>{{ 'mfaCoverage.colRoles' | translate }}</th>
          <th>{{ 'mfaCoverage.colFactors' | translate }}</th>
        </tr></thead>
        <tbody>@for (r of rows(); track r.user_id) {
          <tr [attr.data-user]="r.user_id">
            <td dir="ltr">{{ r.email ?? r.user_id }}
              @if (r.is_admin) { <span class="badge badge-other">{{ 'mfaCoverage.admin' | translate }}</span> }
            </td>
            <td>{{ r.roles.join(', ') }}</td>
            <td>
              @if (r.factors.length === 0) { <span class="error-msg" data-none>{{ 'mfaCoverage.none' | translate }}</span> }
              @else { {{ factorNames(r) }} }
              @if (r.admin_missing_phishing_resistant) { <span class="warn-msg" data-phishing>{{ 'mfaCoverage.needsPasskey' | translate }}</span> }
            </td>
          </tr>
        }</tbody>
      </table></div>
    }
  `,
})
export class MfaCoverageComponent implements OnInit {
  private readonly svc = inject(SecurityAdminService);
  private readonly lang = inject(LangService);

  readonly summary = signal<MfaCoverageSummary[]>([]);
  readonly rows = signal<MfaCoverageRow[]>([]);
  readonly roles = signal<RoleItem[]>([]);
  readonly roleId = signal('');
  readonly missingOnly = signal(false);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.svc.listRoles().subscribe({ next: r => this.roles.set(r), error: () => this.roles.set([]) });
    this.load();
  }

  load(): void {
    this.error.set(null);
    this.svc.mfaCoverageSummary().subscribe({
      next: s => this.summary.set(s),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
    this.loadRows();
  }

  private loadRows(): void {
    this.loading.set(true);
    this.svc.mfaCoverage({ roleId: this.roleId() || undefined, missingOnly: this.missingOnly() }).subscribe({
      next: rows => { this.rows.set(rows); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
  }

  onRole(event: Event): void {
    this.roleId.set((event.target as HTMLSelectElement).value);
    this.loadRows();
  }

  onMissingOnly(event: Event): void {
    this.missingOnly.set((event.target as HTMLInputElement).checked);
    this.loadRows();
  }

  /** The account's factors in the reader's language. */
  factorNames(r: MfaCoverageRow): string {
    return r.factors.map(f => this.lang.translate(`roleForm.mfa.factor.${f}`)).join(', ');
  }
}
