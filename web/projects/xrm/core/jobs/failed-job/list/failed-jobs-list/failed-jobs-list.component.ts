import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe, NgTemplateOutlet } from '@angular/common';
import { ApiError } from '@attome/base';

import { DeadLetterJobItem, JobsAdminService } from '../../../services/jobs-admin.service';

/**
 * P-job-queue-hardening (D-165) / ENTERPRISE-AUDIT-2026-07-24 findings
 * #19/#39 — the admin-facing dead-letter surface. `apalis.jobs` already
 * retains a `Killed` (attempts-exhausted) row in place; this view only
 * lists/replays that existing data, split by queue (`EngineJob::is_batch`)
 * so an operator can see the batch lane (large BulkEntityOperation/
 * ApplyStagedImport runs) backing up independently of the fast lane
 * (SendEmail, notification fan-out).
 */
@Component({
  selector:   'xrm-failed-jobs-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [DatePipe, NgTemplateOutlet],
  styleUrls:  ['../../../../../styles/admin-page.css', './failed-jobs-list.component.css'],
  templateUrl: './failed-jobs-list.component.html',
})
export class FailedJobsListComponent implements OnInit {
  private readonly svc = inject(JobsAdminService);

  readonly fast         = signal<DeadLetterJobItem[]>([]);
  readonly batch        = signal<DeadLetterJobItem[]>([]);
  readonly loading      = signal(true);
  readonly error        = signal<string | null>(null);
  readonly replayingId  = signal<string | null>(null);

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    let pending = 2;
    const done = () => { if (--pending === 0) this.loading.set(false); };
    this.svc.listDeadLetter('fast').subscribe({
      next: res => { this.fast.set(res.items); done(); },
      error: (e: ApiError) => { this.error.set(e.message); done(); },
    });
    this.svc.listDeadLetter('batch').subscribe({
      next: res => { this.batch.set(res.items); done(); },
      error: (e: ApiError) => { this.error.set(e.message); done(); },
    });
  }

  replay(job: DeadLetterJobItem): void {
    this.replayingId.set(job.id);
    this.svc.replay(job.id).subscribe({
      next:  () => { this.replayingId.set(null); this.load(); },
      error: (e: ApiError) => { this.replayingId.set(null); this.error.set(e.message); },
    });
  }
}
