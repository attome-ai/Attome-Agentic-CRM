import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';

import { OidcProviderItem, SecurityAdminService } from './security-admin.service';

/**
 * Q1-T14: the sign-in providers (`admin/security/oidc-providers`). Providers
 * added on screen open in the editor; a provider from `config.json` is shown
 * with a "config" badge and opens read-only.
 */
@Component({
  selector: 'xrm-oidc-providers',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css'],
  template: `
    <div class="page-header">
      <div><h2>{{ 'oidcAdmin.title' | translate }}</h2><p class="subtitle">{{ 'oidcAdmin.subtitle' | translate }}</p></div>
      <div class="btn-row-inline">
        <button type="button" class="btn-ghost" (click)="load()"><i class="las la-sync"></i> {{ 'oidcAdmin.refresh' | translate }}</button>
        <a class="btn-primary" routerLink="new" data-testid="oidc-new">{{ 'oidcAdmin.add' | translate }}</a>
      </div>
    </div>
    @if (loading()) { <p class="state-msg">{{ 'oidcAdmin.loading' | translate }}</p> }
    @else if (error()) { <p class="error-msg" role="alert">{{ error() }}</p> }
    @else if (providers().length === 0) { <div class="empty-state"><p>{{ 'oidcAdmin.empty' | translate }}</p></div> }
    @else {
      <div class="table-wrap"><table>
        <thead><tr>
          <th>{{ 'oidcAdmin.colName' | translate }}</th><th>{{ 'oidcAdmin.colKey' | translate }}</th>
          <th>{{ 'oidcAdmin.colIssuer' | translate }}</th><th>{{ 'oidcAdmin.colStatus' | translate }}</th>
        </tr></thead>
        <tbody>@for (p of providers(); track p.key) {
          <tr [attr.data-provider]="p.key">
            <td>
              @if (p.id) { <a class="cell-link" [routerLink]="p.id">{{ name(p) }}</a> } @else { {{ name(p) }} }
              @if (p.read_only) { <span class="badge badge-other" data-config>{{ 'oidcAdmin.config' | translate }}</span> }
            </td>
            <td class="cell-mono">{{ p.key }}</td>
            <td class="cell-mono" dir="ltr">{{ p.issuer }}</td>
            <td>{{ (p.enabled ? 'oidcAdmin.enabled' : 'oidcAdmin.disabled') | translate }}</td>
          </tr>
        }</tbody>
      </table></div>
    }
  `,
})
export class OidcProvidersComponent implements OnInit {
  private readonly svc = inject(SecurityAdminService);
  private readonly lang = inject(LangService);

  readonly providers = signal<OidcProviderItem[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listOidcProviders().subscribe({
      next: providers => { this.providers.set(providers); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
  }

  /** The provider's name in the reader's language. */
  name(p: OidcProviderItem): string {
    return this.lang.current() === 'ar' && p.display_name_ar ? p.display_name_ar : p.display_name;
  }
}
