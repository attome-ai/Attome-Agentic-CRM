import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  CapabilityRow, DependenciesService, OutboundRow,
} from '../data/services/dependencies.service';

/**
 * AB6-T9 — the operator's dependency page: each gated capability's state,
 * and each outbound service with its breaker, error rate and retries over
 * the last hour. An open breaker reads red. The webhook row links to the
 * dead letters, where failed deliveries are inspected and replayed.
 */
@Component({
  selector: 'xrm-dependencies',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, RouterLink],
  styleUrls: ['../config-admin.css', './dependencies.component.css'],
  template: `
    <section class="config-admin" data-dependencies>
      <h2>{{ 'dependenciesAdmin.title' | translate }}</h2>
      <p class="config-intro">{{ 'dependenciesAdmin.intro' | translate }}</p>
      @if (error(); as e) {
        <p class="config-error" role="alert">{{ e }}</p>
      } @else if (loading()) {
        <p class="config-state">{{ 'dependenciesAdmin.loading' | translate }}</p>
      } @else {
        <h3>{{ 'dependenciesAdmin.capabilities' | translate }}</h3>
        <div class="table-wrap">
          <table class="config-table">
            <thead>
              <tr>
                <th scope="col">{{ 'dependenciesAdmin.capability' | translate }}</th>
                <th scope="col">{{ 'dependenciesAdmin.state' | translate }}</th>
                <th scope="col">{{ 'dependenciesAdmin.failures' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (row of capabilities(); track row.capability) {
                <tr [attr.data-capability-row]="row.capability">
                  <th scope="row" class="mono">{{ row.capability }}</th>
                  <td>
                    <span class="dep-state" [class.dep-bad]="row.state === 'unavailable'"
                          [class.dep-ok]="row.state === 'available'" data-capability-state>
                      {{ ('dependenciesAdmin.capabilityState.' + row.state) | translate }}
                    </span>
                  </td>
                  <td>{{ count(row.consecutive_failures) }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>

        <h3>{{ 'dependenciesAdmin.outbound' | translate }}</h3>
        @if (!outbound().length) {
          <p class="config-state">{{ 'dependenciesAdmin.noOutbound' | translate }}</p>
        } @else {
          <div class="table-wrap">
            <table class="config-table">
              <thead>
                <tr>
                  <th scope="col">{{ 'dependenciesAdmin.service' | translate }}</th>
                  <th scope="col">{{ 'dependenciesAdmin.breaker' | translate }}</th>
                  <th scope="col">{{ 'dependenciesAdmin.errorRate' | translate }}</th>
                  <th scope="col">{{ 'dependenciesAdmin.retries' | translate }}</th>
                  <th scope="col">{{ 'dependenciesAdmin.endpoints' | translate }}</th>
                </tr>
              </thead>
              <tbody>
                @for (row of outbound(); track row.service) {
                  <tr [attr.data-outbound-row]="row.service">
                    <th scope="row" class="mono">
                      @if (row.service === 'webhook') {
                        <a routerLink="/xrm/admin/jobs/failed" data-dead-letters>{{ row.service }}</a>
                      } @else {
                        {{ row.service }}
                      }
                    </th>
                    <td>
                      <span class="dep-state" [class.dep-bad]="row.state === 'open'"
                            [class.dep-warn]="row.state === 'half_open'"
                            [class.dep-ok]="row.state === 'closed'" data-breaker>
                        {{ ('dependenciesAdmin.breakerState.' + row.state) | translate }}
                      </span>
                    </td>
                    <td data-error-rate>{{ rate(row.error_rate) }}</td>
                    <td>{{ count(row.retries_1h) }}</td>
                    <td>{{ count(row.endpoints) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
        <p class="config-intro">{{ 'dependenciesAdmin.perNode' | translate }}</p>
      }
    </section>
  `,
})
export class DependenciesComponent implements OnInit {
  private readonly svc = inject(DependenciesService);
  private readonly lang = inject(LangService);

  readonly capabilities = signal<CapabilityRow[]>([]);
  readonly outbound = signal<OutboundRow[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.svc.report().subscribe({
      next: report => {
        this.capabilities.set(report.capabilities?.gated_routes ?? []);
        this.outbound.set(report.outbound ?? []);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  /** A share as a percentage, or a dash before the first call. */
  rate(value: number | null): string {
    if (value === null || value === undefined) return '—';
    return new Intl.NumberFormat(this.lang.intlLocale(), { style: 'percent', maximumFractionDigits: 1 })
      .format(value);
  }

  count(n: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale()).format(n);
  }
}
