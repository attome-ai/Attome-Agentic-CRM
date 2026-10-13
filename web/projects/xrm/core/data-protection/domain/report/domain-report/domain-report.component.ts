import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';

import { DataProtectionAdminService, DomainReport } from '../../../services/data-protection-admin.service';

/**
 * M15 (Data Governance, D-413) — the accountability report
 * (`GET /api/v1/admin/governance/domains/{id}/report`): every entity in this
 * domain, a classification breakdown reusing the existing
 * `data_classification` taxonomy (D-266/0087), legal holds and DSR requests
 * touching the domain's entities, and a best-effort "last reviewed" date.
 * `open_issues` is always empty today — M13 (duplicate queues) and M14
 * (quality issues), the plan's named sources, don't exist yet as engines.
 */
@Component({
  selector: 'xrm-domain-report',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, RouterLink],
  styleUrls: ['../../../../../styles/admin-page.css', './domain-report.component.css'],
  templateUrl: './domain-report.component.html',
})
export class DomainReportComponent {
  private readonly svc = inject(DataProtectionAdminService);

  /** Bound from the route's `:id` path segment (`withComponentInputBinding()`,
   *  app.config.ts) — reactive across an in-place navigation from one
   *  domain's report to another's, matching `role-form.component.ts`'s own
   *  `loadOnIdChange` convention. */
  readonly id = input<string | null>(null);

  readonly report = signal<DomainReport | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  private readonly loadOnIdChange = effect(() => {
    const id = this.id();
    if (id) this.loadReport(id);
  });

  private loadReport(id: string): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.getDomainReport(id).subscribe({
      next: r => {
        this.report.set(r);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loading.set(false);
      },
    });
  }
}
