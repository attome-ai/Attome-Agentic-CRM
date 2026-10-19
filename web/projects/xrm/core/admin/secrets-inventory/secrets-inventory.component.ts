import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { SecretInventoryRow, SecretsAdminService } from '../data/services/secrets-admin.service';

/**
 * Z1-T14 — the secret inventory: every secret this node's configuration
 * holds, the features that use it, its active key id and age, and a warning
 * when it is older than `security.secret_max_age_days`. The server sends no
 * value, and this screen has no column for one.
 */
@Component({
  selector: 'xrm-secrets-inventory',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../config-admin.css'],
  template: `
    <section class="config-admin" data-secrets-inventory>
      <h2>{{ 'secretsAdmin.title' | translate }}</h2>
      <p class="config-intro">{{ 'secretsAdmin.intro' | translate }}</p>
      @if (error(); as e) {
        <p class="config-error" role="alert">{{ e }}</p>
      } @else if (loading()) {
        <p class="config-state">{{ 'secretsAdmin.loading' | translate }}</p>
      } @else if (!rows().length) {
        <p class="config-state">{{ 'secretsAdmin.empty' | translate }}</p>
      } @else {
        <div class="table-wrap">
          <table class="config-table">
            <thead>
              <tr>
                <th scope="col">{{ 'secretsAdmin.name' | translate }}</th>
                <th scope="col">{{ 'secretsAdmin.usedBy' | translate }}</th>
                <th scope="col">{{ 'secretsAdmin.activeKey' | translate }}</th>
                <th scope="col">{{ 'secretsAdmin.age' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (row of rows(); track row.name) {
                <tr [attr.data-secret-row]="row.name">
                  <th scope="row" class="mono">{{ row.name }}</th>
                  <td>{{ row.used_by.join(', ') }}</td>
                  <td class="mono">{{ row.active_key_id ?? '—' }}</td>
                  <td>
                    @if (row.age_days !== null && row.age_days !== undefined) {
                      {{ 'secretsAdmin.days' | translate: { count: row.age_days } }}
                    } @else {
                      —
                    }
                    @if (!row.set) {
                      <span class="config-badge" data-secret-unset>{{ 'secretsAdmin.unset' | translate }}</span>
                    }
                    @if (row.over_age) {
                      <span class="config-badge config-badge-warn" data-secret-over-age>
                        {{ 'secretsAdmin.overAge' | translate }}
                      </span>
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }
    </section>
  `,
})
export class SecretsInventoryComponent implements OnInit {
  private readonly svc = inject(SecretsAdminService);
  private readonly lang = inject(LangService);

  readonly rows = signal<SecretInventoryRow[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.svc.secrets().subscribe({
      next: page => {
        this.rows.set(page.items);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }
}
