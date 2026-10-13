import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  RELEASE_REPORT_SOURCES, RELEASE_REPORT_STATUSES, ReleaseReportService, structureErrorText,
  type ReleaseReport, type ReleaseReportSource, type ReleaseReportStatus, type ReleaseReportSummary,
} from '@attome/xrm/core/admin/data';

/**
 * Solution 7 Phase 2 (design §10) — `/xrm/admin/release-reports`: every
 * release report, newest first, with the summary of open items. One-based
 * paging (D-731). Opening a report goes to `/xrm/admin/release-reports/{id}`
 * (the link the post-apply notification carries).
 */
@Component({
  selector: 'xrm-release-report-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../../../styles/admin-page.css', '../release-reports.css', './release-report-list.component.css'],
  templateUrl: './release-report-list.component.html',
})
export class ReleaseReportListComponent implements OnInit {
  private readonly svc = inject(ReleaseReportService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly statuses = RELEASE_REPORT_STATUSES;
  readonly sources = RELEASE_REPORT_SOURCES;
  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly pageSize = 20;

  readonly status = signal<ReleaseReportStatus | ''>('');
  readonly source = signal<ReleaseReportSource | ''>('');

  readonly summary = signal<ReleaseReportSummary | null>(null);
  readonly reports = signal<ReleaseReport[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));
  readonly hasPrevious = computed(() => this.page() > 1);
  readonly hasNext = computed(() => this.page() < this.pages());

  ngOnInit(): void {
    this.loadSummary();
    this.load();
  }

  apply(): void {
    this.page.set(1);
    this.load();
  }

  reset(): void {
    this.status.set('');
    this.source.set('');
    this.apply();
  }

  refresh(): void {
    this.loadSummary();
    this.load();
  }

  previous(): void {
    if (!this.hasPrevious() || this.loading()) return;
    this.page.update(p => p - 1);
    this.load();
  }

  next(): void {
    if (!this.hasNext() || this.loading()) return;
    this.page.update(p => p + 1);
    this.load();
  }

  statusKey(status: string): string { return `releaseReport.status.${status}`; }
  sourceKey(source: string): string { return `releaseReport.source.${source}`; }

  /** Open items by kind, for the summary line (kinds with none are left out). */
  readonly byKind = computed(() =>
    Object.entries(this.summary()?.by_kind ?? {})
      .filter(([, n]) => n > 0)
      .map(([kind, count]) => ({ kind, count })));

  private loadSummary(): void {
    this.svc.summary().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: s => this.summary.set(s),
      // The summary is a convenience: the list below still loads and says
      // what went wrong if the server is unreachable.
      error: () => this.summary.set(null),
    });
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    const filter = { status: this.status() || undefined, source: this.source() || undefined };
    this.svc.listReports(filter, this.page(), this.pageSize)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: res => {
          this.reports.set(res.items);
          this.total.set(res.total);
          this.loading.set(false);
        },
        error: (err: ApiError) => {
          this.error.set(structureErrorText(this.lang, err));
          this.loading.set(false);
        },
      });
  }
}
